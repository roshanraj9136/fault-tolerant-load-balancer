# Fault-Tolerant HTTP Load Balancer in Go

[![CI](https://github.com/roshanraj9136/fault-tolerant-load-balancer/actions/workflows/ci.yml/badge.svg)](https://github.com/roshanraj9136/fault-tolerant-load-balancer/actions/workflows/ci.yml)

A least-connections reverse-proxy load balancer, a replicated message service behind it, and a load generator. All of it is plain Go on the standard library, plus `lib/pq` for PostgreSQL.

I built it for the Distributed Systems Lab at IIT Bhilai. It runs on four Linux containers, each hard-capped at **1 CPU and 512 MiB of memory**. A graded harness drove the load, ramping up to 2,500 concurrent users.

```
                 clients / load generator
                           │
                           ▼
              ┌─────────────────────────┐
              │   loadbalancer  :3297   │  least-connections routing
              │                         │  active health checks, retry, metrics
              └────┬─────────┬──────────┘
                   │         │          │
                   ▼         ▼          ▼
            ┌──────────┐ ┌──────────┐ ┌──────────┐
            │ backend-1│ │ backend-2│ │ backend-3│   in-memory feed per node
            │  :3298   │ │  :3299   │ │  :3300   │   batched writes, peer sync
            └────┬─────┘ └────┬─────┘ └────┬─────┘
                 └────────────┼────────────┘
                              ▼
                        PostgreSQL
```

## Load balancer (`loadbalancer/`)

**Routing**
- Least-connections: each request goes to the backend with the fewest in-flight requests.
- The scan starts at a rotating index, so backends with equal load take turns.
- A backend that is marked down is heavily deprioritised, but is still used if no other backend is left.

**Health**
- An active `/health` probe runs every `-health-interval`.
- A backend is marked down after 3 consecutive failed probes, and back up on the next successful one.

**Retry**
- Request bodies are buffered, up to 1 MiB. Larger bodies are rejected with `413`.
- If a backend returns a connection error or a 5xx before any response bytes reach the client, the request is retried on a backend it has not tried yet.
- Once headers are committed, it is not retried.

**Connections**
- Each backend gets a keep-alive pool: up to 512 connections, 256 of them idle.
- The pool is warmed up at start.
- Every socket's send and receive buffers are capped. The container's cgroup charges kernel socket memory against the same 512 MiB limit.

**Memory**
- Request-body and copy buffers are reused through `sync.Pool`.

**Observability**
- `/lb/health` and `/lb/status`.
- `/lb/metrics`, which reports throughput, errors, and mean/p50/p95/p99 latency.
- An HTML status page at `/lb/`.

**Admin reset**
- `POST /lb/reset` only runs when the `X-Reset-Key` header matches the `LB_RESET_KEY` environment variable, compared in constant time.
- If `LB_RESET_KEY` is unset, the route is disabled.

**Optional sidecar**
- `-chat-cmd` makes the balancer supervise a co-hosted app.
- It stops the app when traffic spikes and restarts it after a quiet period.

## Backend (`backend/`)

**`POST /message`**
- An accepted message goes straight into the node's in-memory feed.
- A single writer goroutine then:
  - encrypts it with AES-GCM,
  - signs it with a per-client Ed25519 key,
  - inserts it into PostgreSQL in batches of up to 500 rows, flushed every 25 ms.

**`GET /feed`**
- Serves a pre-rendered JSON array, so a read never scans or decrypts the table.
- Bodies over 4 KB are gzip-compressed, and the compressed copy is cached across readers.

**Replication**
- Every 300 ms, each node pulls rows written by its peers, tracked by a monotonic sequence number.
- It also periodically reconciles against the durable row count to repair gaps left by out-of-order batch commits.
- Before serving an authoritative feed, it asks peers to flush their write queues through `/peer/flush`.

## Load generator (`client/`)

- A worker pool sends messages with randomized sizes and intervals.
- It reports throughput, dropout, and p50/p95/p99 latency.
- Results can be written as JSON (`-out`) or appended to a CSV (`-csv`).

## Debugging an out-of-memory failure

Under graded load the system returned **about 18% errors**, while latency for requests that did succeed stayed low. The errors clustered in the first seconds of each new load stage, and there were zero timeouts.

The cause was the load balancer's container repeatedly hitting its 512 MiB limit:
- `/sys/fs/cgroup/memory.events` recorded 121 `oom_kill` events.
- The supervisor restarted the process after a 1-second sleep.
- For that second nothing was listening, so every connecting client got an immediate refusal.
- Feed integrity still looked perfect, because each backend rebuilds its feed from PostgreSQL on restart. That hid the crashes.

The fixes were all about memory:

| Change | Why |
|---|---|
| Reuse request-body buffers via `sync.Pool` instead of a fresh `io.ReadAll` per request | Removed per-request heap churn |
| Smaller outbound connection buffers and a bounded latency sample reservoir | Cut permanently resident memory |
| `GOMEMLIMIT` plus a lower `GOGC` on every node | Kept the Go heap well under the container limit, which also has to hold kernel socket buffers |
| `snapshotFresh` on the backend | `/feed` stopped copying the entire feed on every request while holding the write lock that `/message` needs |
| Restart delay cut from 1 s to 50 ms | Any remaining crash now costs milliseconds of refusals, not a full second |

**Result:** two graded load runs back to back came out as follows.

| Metric | Result |
|---|---|
| Traffic | 60,000 requests, ramping up to 2,500 concurrent users |
| Errors | **0** |
| New OOM kills | None |
| Peak load balancer memory | 364 MB of 512 MB |
| Feed consistency | All three backends reported the same 57,490-message feed |

## Benchmarks

These come from the load generator in this repo, with all nodes on 1 CPU. The raw data is in `results/`.

| Run | Requests | Concurrency | Failed | Throughput | p50 | p99 |
|---|---:|---:|---:|---:|---:|---:|
| 1 backend | 5,000 | 40 | 0 | 504 req/s | 96.7 ms | 201.6 ms |
| 3 backends | 5,000 | 40 | 0 | 516 req/s | 95.9 ms | 201.7 ms |
| 1 backend | 10,000 | 100 | 0 | 497 req/s | 197.1 ms | 488.3 ms |
| 3 backends | 10,000 | 100 | 0 | 478 req/s | 198.1 ms | 500.0 ms |

Throughput stays roughly flat going from 1 to 3 backends. That suggests the single-CPU load balancer, not backend capacity, is the bottleneck at these loads.

## Build and run

Requires Go 1.22+ and PostgreSQL. It targets Linux, because the socket buffer caps use Linux socket options.

```bash
go build -o bin/loadbalancer ./loadbalancer
go build -o bin/backend ./backend
go build -o bin/client ./client

DB="postgres://postgres:postgres@127.0.0.1:5432/lb?sslmode=disable"   # the database must exist; tables are created on start

./bin/backend -name backend-1 -port 3298 -db "$DB" -peers http://127.0.0.1:3299,http://127.0.0.1:3300 &
./bin/backend -name backend-2 -port 3299 -db "$DB" -peers http://127.0.0.1:3298,http://127.0.0.1:3300 &
./bin/backend -name backend-3 -port 3300 -db "$DB" -peers http://127.0.0.1:3298,http://127.0.0.1:3299 &

./bin/loadbalancer -port 3297 -backends http://127.0.0.1:3298,http://127.0.0.1:3299,http://127.0.0.1:3300 &

./bin/client -url http://127.0.0.1:3297 -requests 5000 -concurrency 40
curl http://127.0.0.1:3297/lb/metrics
```

In the capped containers, each process ran with `ulimit -n 65535` and these settings:

| Process | `GOMAXPROCS` | `GOMEMLIMIT` | `GOGC` |
|---|---|---|---|
| Load balancer | 1 | 240MiB | 80 |
| Backends | 1 | 256MiB | 80 |
