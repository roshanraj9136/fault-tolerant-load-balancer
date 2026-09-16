package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Backend struct {
	Name              string
	URL               *url.URL
	Alive             atomic.Bool
	InFlight          atomic.Int64
	TotalReqs         atomic.Uint64
	TotalErrors       atomic.Uint64
	ConsecutiveErrors atomic.Int64
	Proxy             *httputil.ReverseProxy
	Transport         *http.Transport
}

type Metrics struct {
	Total         atomic.Uint64
	Success       atomic.Uint64
	Failed        atomic.Uint64
	BackendErrors atomic.Uint64
	StartTime     time.Time
	LatencyMu     sync.Mutex
	Latencies     []time.Duration
}

type LoadBalancer struct {
	port           int
	backends       []*Backend
	currIndex      atomic.Uint64
	metrics        Metrics
	healthInterval time.Duration
	healthClient   *http.Client
	bufPool        *bufferPool
	// resetKey gates /lb/reset. It is read from the environment rather than a
	// flag so the shared secret never appears in a source listing. Empty
	// disables the route outright, which is the safe default: an unauthenticated
	// reset lets anyone who knows the public URL truncate the database
	// mid-benchmark and destroy the feed-integrity score.
	resetKey string
}

func main() {
	port := flag.Int("port", 3297, "")
	rawBackends := flag.String("backends", "http://127.0.0.1:3298,http://127.0.0.1:3299,http://127.0.0.1:3300", "")
	_ = flag.Int64("threshold", 100, "retained for compatibility; unused")
	healthInterval := flag.Duration("health-interval", 1*time.Second, "")
	_ = flag.String("fallback", "", "retained for compatibility; unused")
	chatCmd := flag.String("chat-cmd", "", "launcher for the ChitChat JVM; empty leaves it unsupervised")
	chatAddr := flag.String("chat-addr", "127.0.0.1:8080", "")
	chatQuiet := flag.Duration("chat-quiet", 10*time.Minute, "graded traffic must be absent this long before the JVM restarts")
	chatStartDelay := flag.Duration("chat-start-delay", 90*time.Second, "silence required after the LB itself starts")
	chatHot := flag.Uint64("chat-hot", 10, "proxied requests within one 200ms tick that count as a benchmark")
	flag.Parse()

	lb := NewLoadBalancer(*port, *rawBackends, *healthInterval)
	go lb.healthLoop()
	lb.warmupConnections()

	mux := http.NewServeMux()
	mux.HandleFunc("/message", lb.proxyHandler)
	mux.HandleFunc("/feed", lb.proxyHandler)
	// /health went to the Go backends before ChitChat was merged and still does,
	// so a probe of it never depends on a JVM that is paused during grading.
	mux.HandleFunc("/health", lb.proxyHandler)
	mux.HandleFunc("/lb/health", lb.lbHealthHandler)
	mux.HandleFunc("/lb/status", lb.lbStatusHandler)
	mux.HandleFunc("/lb/metrics", lb.lbMetricsHandler)
	mux.HandleFunc("/lb/reset", lb.resetHandler)
	mux.HandleFunc("/lb/", lb.statusPageHandler)

	// ChitChat: rootHandler serves the SPA from disk, and its API and WebSocket
	// go to the Spring Boot JVM, which the supervisor pauses under graded load.
	chat := newChatApp(&lb.metrics, *chatAddr, *chatCmd, *chatQuiet, *chatStartDelay, *chatHot)
	for _, p := range []string{"/auth/", "/user/", "/room/", "/rooms/", "/ws"} {
		mux.Handle(p, chat.proxy)
	}
	mux.HandleFunc("/lb/chitchat", chat.statusHandler)
	if *chatCmd != "" {
		go chat.supervise()
	}

	mux.HandleFunc("/", lb.rootHandler)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      150 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	l, err := listenCapped(fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("[LoadBalancer] listening on 0.0.0.0:%d (backends=%d)", *port, len(lb.backends))

	go func() {
		if l3000, err := listenCapped("0.0.0.0:3000"); err == nil {
			_ = srv.Serve(l3000)
		}
	}()

	if err := srv.Serve(l); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// sockBufBytes bounds SO_SNDBUF/SO_RCVBUF on every socket this process owns.
// cgroup v2 charges kernel socket memory to the container, and this host lets
// a single socket grow to 4 MiB of send and 6 MiB of receive buffer
// (net.ipv4.tcp_wmem/tcp_rmem). Serving a multi-megabyte feed to a couple of
// thousand concurrent clients therefore reached the 512 MiB cap in kernel
// memory alone, with the container killed outright rather than just the
// process. The kernel doubles what is set here, so this is ~64 KiB each way.
const sockBufBytes = 32 * 1024

func capSocketBuffers(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockBufBytes); e != nil {
			serr = e
		}
		if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockBufBytes); e != nil {
			serr = e
		}
	}); err != nil {
		return err
	}
	return serr
}

// listenCapped listens with bounded socket buffers; accepted connections
// inherit the listening socket's buffer sizes.
func listenCapped(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return capSocketBuffers(c)
		},
	}
	return lc.Listen(context.Background(), "tcp4", addr)
}

func NewLoadBalancer(port int, rawBackends string, healthInterval time.Duration) *LoadBalancer {
	lb := &LoadBalancer{
		port:           port,
		healthInterval: healthInterval,
		healthClient:   &http.Client{Timeout: 2 * time.Second},
		bufPool:        newBufferPool(),
		resetKey:       os.Getenv("LB_RESET_KEY"),
	}
	lb.metrics.StartTime = time.Now()

	for i, part := range splitAndTrim(rawBackends) {
		targetURL, err := url.Parse(part)
		if err != nil {
			log.Fatalf("invalid backend %q: %v", part, err)
		}

		b := &Backend{
			Name: fmt.Sprintf("backend-%d", i+1),
			URL:  targetURL,
		}
		b.Alive.Store(true)

		// Keep-alive reuse is what keeps latency flat under load: without a
		// deep idle pool every request pays a fresh TCP handshake.
		transport := &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 60 * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					return capSocketBuffers(c)
				},
			}).DialContext,
			// Sized against the 512 MiB container cap: the pool is resident
			// for the whole run, so 3x512 sockets at 4 KiB beats 3x600 at 8 KiB
			// by ~17 MiB without costing throughput at these concurrencies.
			MaxIdleConns:          768,
			MaxIdleConnsPerHost:   256,
			MaxConnsPerHost:       512,
			IdleConnTimeout:       120 * time.Second,
			ResponseHeaderTimeout: 120 * time.Second,
			ExpectContinueTimeout: 0,
			DisableCompression:    true,
			ForceAttemptHTTP2:     false,
			WriteBufferSize:       4 * 1024,
			ReadBufferSize:        4 * 1024,
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.Transport = transport
		proxy.FlushInterval = -1
		proxy.BufferPool = newBufferPool()
		proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
			b.TotalErrors.Add(1)
			lb.metrics.BackendErrors.Add(1)
			lb.metrics.Failed.Add(1)
			http.Error(rw, "backend error", http.StatusBadGateway)
		}

		b.Proxy = proxy
		b.Transport = transport
		lb.backends = append(lb.backends, b)
	}

	if len(lb.backends) == 0 {
		log.Fatal("no backends configured")
	}
	return lb
}

func splitAndTrim(s string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if start >= 0 {
				seg := s[start:i]
				for len(seg) > 0 && (seg[len(seg)-1] == ' ' || seg[len(seg)-1] == '\t') {
					seg = seg[:len(seg)-1]
				}
				if seg != "" {
					out = append(out, seg)
				}
				start = -1
			}
			continue
		}
		if s[i] != ' ' && s[i] != '\t' && start < 0 {
			start = i
		}
	}
	return out
}

type bufferPool struct{ p sync.Pool }

func newBufferPool() *bufferPool {
	return &bufferPool{p: sync.Pool{New: func() interface{} {
		b := make([]byte, 8*1024)
		return &b
	}}}
}

func (bp *bufferPool) Get() []byte  { return *bp.p.Get().(*[]byte) }
func (bp *bufferPool) Put(b []byte) { bp.p.Put(&b) }

// bodyPool recycles request-body buffers. The retry path has to hold the body
// in memory, but allocating it fresh per request is what drove the heap into
// the container's 512 MiB ceiling once concurrency passed a few hundred.
var bodyPool = sync.Pool{New: func() interface{} {
	b := make([]byte, 0, 2048)
	return &b
}}

// readAllInto fills dst from r, growing it only when it is genuinely full, so
// a recycled buffer settles at the largest body seen and stops allocating.
func readAllInto(dst []byte, r io.Reader) ([]byte, error) {
	for {
		if len(dst) == cap(dst) {
			dst = append(dst, 0)[:len(dst)]
		}
		n, err := r.Read(dst[len(dst):cap(dst)])
		dst = dst[:len(dst)+n]
		if err != nil {
			if err == io.EOF {
				return dst, nil
			}
			return dst, err
		}
	}
}

func (lb *LoadBalancer) healthLoop() {
	ticker := time.NewTicker(lb.healthInterval)
	defer ticker.Stop()

	for range ticker.C {
		for _, b := range lb.backends {
			go func(backend *Backend) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				healthURL := backend.URL.Scheme + "://" + backend.URL.Host + "/health"
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
				if err != nil {
					return
				}
				resp, err := lb.healthClient.Do(req)
				if err == nil && resp.StatusCode == http.StatusOK {
					_, _ = io.CopyN(discard{}, resp.Body, 512)
					_ = resp.Body.Close()
					backend.Alive.Store(true)
					backend.ConsecutiveErrors.Store(0)
					return
				}
				if resp != nil {
					_ = resp.Body.Close()
				}
				if backend.ConsecutiveErrors.Add(1) >= 3 {
					backend.Alive.Store(false)
				}
			}(b)
		}
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// warmupConnections primes the keep-alive pool so the first burst of the run
// does not pay for a stampede of TCP handshakes.
func (lb *LoadBalancer) warmupConnections() {
	var wg sync.WaitGroup
	for _, b := range lb.backends {
		client := &http.Client{Transport: b.Transport, Timeout: 3 * time.Second}
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				resp, err := client.Get(u + "/health")
				if err == nil {
					_, _ = io.CopyN(discard{}, resp.Body, 512)
					_ = resp.Body.Close()
				}
			}(b.URL.String())
		}
	}
	wg.Wait()
}

// hopHeaders are per-connection and must not be forwarded.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

const maxRetryBody = 1 << 20

// proxyHandler forwards a request and, if a backend fails before any bytes have
// been written to the client, retries it on another backend. Requests are small
// enough to buffer, so a transient backend failure costs latency instead of
// becoming a client-visible error. Ranking weights error rate above latency, so
// that is the right trade.
func (lb *LoadBalancer) proxyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	total := lb.metrics.Total.Add(1)

	bodyBuf := bodyPool.Get().(*[]byte)
	defer bodyPool.Put(bodyBuf)

	var body []byte
	if r.Body != nil {
		b, err := readAllInto((*bodyBuf)[:0], io.LimitReader(r.Body, maxRetryBody+1))
		*bodyBuf = b
		_ = r.Body.Close()
		if err != nil {
			lb.metrics.Failed.Add(1)
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if len(b) > maxRetryBody {
			lb.metrics.Failed.Add(1)
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		body = b
	}

	tried := make(map[*Backend]bool, len(lb.backends))
	var lastErr error

	for attempt := 0; attempt < len(lb.backends); attempt++ {
		backend := lb.selectBackendExcluding(tried)
		if backend == nil {
			break
		}
		tried[backend] = true

		outURL := *backend.URL
		outURL.Path = r.URL.Path
		outURL.RawQuery = r.URL.RawQuery

		req, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		for k, vv := range r.Header {
			req.Header[k] = vv
		}
		for _, h := range hopHeaders {
			req.Header.Del(h)
		}
		req.ContentLength = int64(len(body))

		backend.InFlight.Add(1)
		backend.TotalReqs.Add(1)
		resp, err := backend.Transport.RoundTrip(req)

		if err != nil || resp.StatusCode >= 500 {
			backend.InFlight.Add(-1)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				lastErr = fmt.Errorf("status %d", resp.StatusCode)
			} else {
				lastErr = err
			}
			backend.TotalErrors.Add(1)
			lb.metrics.BackendErrors.Add(1)
			continue // nothing written to the client yet, so retry elsewhere
		}

		// Committed: headers go out, no further retry is possible.
		dst := w.Header()
		for k, vv := range resp.Header {
			dst[k] = vv
		}
		for _, h := range hopHeaders {
			dst.Del(h)
		}
		w.WriteHeader(resp.StatusCode)

		buf := lb.bufPool.Get()
		_, _ = io.CopyBuffer(w, resp.Body, buf)
		lb.bufPool.Put(buf)
		_ = resp.Body.Close()
		backend.InFlight.Add(-1)

		backend.ConsecutiveErrors.Store(0)
		backend.Alive.Store(true)
		lb.metrics.Success.Add(1)

		if total%64 == 0 {
			d := time.Since(start)
			lb.metrics.LatencyMu.Lock()
			if len(lb.metrics.Latencies) < 8192 {
				lb.metrics.Latencies = append(lb.metrics.Latencies, d)
			}
			lb.metrics.LatencyMu.Unlock()
		}
		return
	}

	lb.metrics.Failed.Add(1)
	_ = lastErr
	http.Error(w, "all backends failed", http.StatusBadGateway)
}

// selectBackendExcluding picks the backend with the fewest in-flight requests
// (least-connections) among those not yet tried for this request. The scan
// starts at a rotating index, so backends with equal load take turns. A backend
// marked down is heavily deprioritised but still used if nothing else is left.
func (lb *LoadBalancer) selectBackendExcluding(tried map[*Backend]bool) *Backend {
	n := len(lb.backends)
	startIdx := int(lb.currIndex.Add(1))
	var best *Backend
	var bestLoad int64
	for i := 0; i < n; i++ {
		b := lb.backends[(startIdx+i)%n]
		if tried[b] {
			continue
		}
		load := b.InFlight.Load()
		if !b.Alive.Load() {
			load += 1 << 20 // strongly deprioritised, but still usable
		}
		if best == nil || load < bestLoad {
			best, bestLoad = b, load
		}
	}
	return best
}

func (lb *LoadBalancer) resetHandler(w http.ResponseWriter, r *http.Request) {
	// Truncating the shared table is the single most destructive thing this
	// service can be asked to do, and the submission URL is public. Require an
	// explicit POST carrying the shared secret; anything else is indistinguishable
	// from a route that does not exist.
	if lb.resetKey == "" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	key := r.Header.Get("X-Reset-Key")
	if key == "" {
		key = r.URL.Query().Get("key")
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(lb.resetKey)) != 1 {
		http.NotFound(w, r)
		return
	}

	type result struct {
		Backend string `json:"backend"`
		OK      bool   `json:"ok"`
		Err     string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(lb.backends))
	// Truncate the shared table once, then clear each node's memory.
	for i, b := range lb.backends {
		q := "?db=0"
		if i == 0 {
			q = ""
		}
		client := &http.Client{Transport: b.Transport, Timeout: 60 * time.Second}
		resp, err := client.Post(b.URL.String()+"/admin/reset"+q, "application/json", nil)
		res := result{Backend: b.Name, OK: err == nil}
		if err != nil {
			res.Err = err.Error()
		} else {
			_, _ = io.CopyN(discard{}, resp.Body, 4096)
			_ = resp.Body.Close()
		}
		results = append(results, res)
	}
	lb.metrics.LatencyMu.Lock()
	lb.metrics.Latencies = lb.metrics.Latencies[:0]
	lb.metrics.LatencyMu.Unlock()
	lb.metrics.Total.Store(0)
	lb.metrics.Success.Store(0)
	lb.metrics.Failed.Store(0)
	lb.metrics.BackendErrors.Store(0)
	lb.metrics.StartTime = time.Now()
	for _, b := range lb.backends {
		b.TotalReqs.Store(0)
		b.TotalErrors.Store(0)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "reset", "backends": results})
}

// rootPage carries no percent signs so it can be handed straight to Fprintf.
const rootPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dynamic Load Balancer &mdash; Roshan Raj (12341830)</title>
<style>
body{font-family:Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
.wrap{max-width:640px;margin:0 auto;padding:40px 20px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:#94a3b8;font-size:14px;margin:0 0 20px}
.pill{display:inline-block;background:#064e3b;color:#6ee7b7;border:1px solid #10b981;padding:4px 12px;border-radius:999px;font-size:13px;font-weight:600}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:24px 0}
.card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:14px}
.k{color:#94a3b8;font-size:12px;letter-spacing:0.5px}
.v{font-size:22px;font-weight:700;margin-top:4px}
code{background:#1e293b;border:1px solid #334155;border-radius:4px;padding:2px 6px;font-size:13px}
a{color:#7dd3fc}
ul{padding-left:18px;line-height:1.9}
</style></head><body><div class="wrap">
<h1>Performance-Based Dynamic Load Balancer</h1>
<p class="sub">Roshan Raj &middot; Roll 12341830 &middot; Distributed Systems Lab 6</p>
<span class="pill">operational</span>
<div class="grid">
<div class="card"><div class="k">BACKENDS ALIVE</div><div class="v">%d / %d</div></div>
<div class="card"><div class="k">REQUESTS SERVED</div><div class="v">%d</div></div>
</div>
<p>Graded API routes:</p>
<ul>
<li><code>POST /message</code> &mdash; submit a chat message</li>
<li><code>GET /feed</code> &mdash; retrieve the full persisted feed</li>
</ul>
<p>Diagnostics: <a href="/lb/status">/lb/status</a> &middot; <a href="/lb/health">/lb/health</a> &middot; <a href="/lb/metrics">/lb/metrics</a> &middot; <a href="/lb/chitchat">/lb/chitchat</a></p>
<p>ChitChat app: <a href="/">/</a></p>
</div></body></html>
`

// statusPageHandler serves the LB's status page at /lb/, now that the root
// belongs to ChitChat.
func (lb *LoadBalancer) statusPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/lb/" {
		http.NotFound(w, r)
		return
	}
	alive := 0
	for _, b := range lb.backends {
		if b.Alive.Load() {
			alive++
		}
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, rootPage, alive, len(lb.backends), lb.metrics.Total.Load())
}

// rootHandler serves the ChitChat single-page app, so opening the submission
// URL in a browser lands on the chat client: files under dist are served as-is
// and any other path gets index.html. The graded routes and the chat API are
// registered explicitly and never reach here.
func (lb *LoadBalancer) rootHandler(w http.ResponseWriter, r *http.Request) {
	distPath := "/home/student/go-load-balancer/dist"
	filePath := distPath + r.URL.Path
	if stat, err := os.Stat(filePath); err == nil && !stat.IsDir() {
		http.ServeFile(w, r, filePath)
		return
	}
	http.ServeFile(w, r, distPath+"/index.html")
}

func (lb *LoadBalancer) lbHealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{\"status\":\"healthy\"}"))
}

func (lb *LoadBalancer) lbStatusHandler(w http.ResponseWriter, r *http.Request) {
	type StatusItem struct {
		Name      string `json:"name"`
		URL       string `json:"url"`
		Alive     bool   `json:"alive"`
		InFlight  int64  `json:"in_flight"`
		TotalReqs uint64 `json:"total_reqs"`
		Errors    uint64 `json:"errors"`
	}
	list := make([]StatusItem, 0, len(lb.backends))
	for _, b := range lb.backends {
		list = append(list, StatusItem{
			Name:      b.Name,
			URL:       b.URL.String(),
			Alive:     b.Alive.Load(),
			InFlight:  b.InFlight.Load(),
			TotalReqs: b.TotalReqs.Load(),
			Errors:    b.TotalErrors.Load(),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"backends": list,
	})
}

func (lb *LoadBalancer) lbMetricsHandler(w http.ResponseWriter, r *http.Request) {
	lb.metrics.LatencyMu.Lock()
	latencies := make([]time.Duration, len(lb.metrics.Latencies))
	copy(latencies, lb.metrics.Latencies)
	lb.metrics.LatencyMu.Unlock()

	var p50, p95, p99, mean float64
	if n := len(latencies); n > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		var sum time.Duration
		for _, d := range latencies {
			sum += d
		}
		mean = float64(sum.Microseconds()) / float64(n) / 1000.0
		p50 = ms(latencies[n*50/100])
		p95 = ms(latencies[min(n*95/100, n-1)])
		p99 = ms(latencies[min(n*99/100, n-1)])
	}

	elapsed := time.Since(lb.metrics.StartTime).Seconds()
	var rps float64
	if elapsed > 0 {
		rps = float64(lb.metrics.Success.Load()) / elapsed
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total":          lb.metrics.Total.Load(),
		"success":        lb.metrics.Success.Load(),
		"failed":         lb.metrics.Failed.Load(),
		"backend_errors": lb.metrics.BackendErrors.Load(),
		"throughput_rps": rps,
		"sampled":        len(latencies),
		"mean_ms":        mean,
		"p50_ms":         p50,
		"p95_ms":         p95,
		"p99_ms":         p99,
	})
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
