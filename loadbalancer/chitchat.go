package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// chatTick is how often the supervisor samples proxied traffic. It is also the
// longest the JVM can overlap with the start of a benchmark.
const chatTick = 200 * time.Millisecond

// chatApp puts the ChitChat backend (Spring Boot) behind the LB and keeps it
// out of the benchmark's way.
//
// The JVM lives in the LB's container, which is capped at 1 CPU and 512 MiB.
// It holds ~270 MiB resident and spends ~45 s of that one CPU booting, while a
// 2500-user run takes the LB alone past 360 MiB. The two cannot run together,
// and an OOM kill during grading is a wall of refused connections. The LB is
// the only component that sees graded traffic the moment it arrives, so it owns
// the JVM's lifecycle: SIGKILL within one tick of load, restart only once the
// benchmark has been quiet for a while. Grading always wins.
type chatApp struct {
	metrics *Metrics
	addr    string
	cmdPath string // launcher; it must exec the JVM so signals reach it directly
	match   string // substring of the JVM command line, for stray cleanup
	logPath string
	quiet   time.Duration
	hotReqs uint64
	proxy   *httputil.ReverseProxy

	mu        sync.Mutex
	proc      *os.Process
	planned   bool // the running JVM was killed on purpose
	startedAt time.Time
	exitedAt  time.Time
	lastHot   time.Time // last tick that saw benchmark-level traffic
	failures  int       // consecutive short-lived crashes, drives backoff
	starts    int
	kills     int
}

func newChatApp(m *Metrics, addr, cmdPath string, quiet, startDelay time.Duration, hotReqs uint64) *chatApp {
	c := &chatApp{
		metrics: m,
		addr:    addr,
		cmdPath: cmdPath,
		match:   "chitchat.jar",
		logPath: "/home/student/chitchat.log",
		quiet:   quiet,
		hotReqs: hotReqs,
	}
	// The LB starting counts as load: if it was restarted mid-benchmark, the JVM
	// must not boot into the run. startDelay of silence is enough here because a
	// submission's runs are back to back - a gap that long means grading is over.
	c.lastHot = time.Now().Add(startDelay - quiet)

	p := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: addr})
	p.Transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	p.ErrorHandler = c.unavailable
	c.proxy = p
	return c
}

// unavailable answers while the JVM is paused, booting or crashed. The frontend
// only looks at the status code; the body is for whoever curls it.
func (c *chatApp) unavailable(w http.ResponseWriter, r *http.Request, err error) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("Retry-After", "60")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "chat backend unavailable: paused while the load balancer is benchmarked, or still starting",
		"state": c.status().State,
	})
}

func (c *chatApp) supervise() {
	killStrayJVMs(c.match)
	ticker := time.NewTicker(chatTick)
	defer ticker.Stop()
	last := c.metrics.Total.Load()
	for now := range ticker.C {
		total := c.metrics.Total.Load()
		var delta uint64
		if total >= last { // /lb/reset zeroes the counter
			delta = total - last
		}
		last = total
		if delta >= c.hotReqs {
			c.pause(now, delta)
			continue
		}
		c.maybeStart(now)
	}
}

func (c *chatApp) pause(now time.Time, delta uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastHot = now
	if c.proc == nil || c.planned {
		return
	}
	c.planned = true
	c.kills++
	// The launcher runs in its own process group; take all of it down at once.
	_ = syscall.Kill(-c.proc.Pid, syscall.SIGKILL)
	log.Printf("[chitchat] %d proxied requests in %s: killed JVM pid %d", delta, chatTick, c.proc.Pid)
}

func (c *chatApp) maybeStart(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proc != nil || now.Sub(c.lastHot) < c.quiet || now.Sub(c.exitedAt) < c.backoff() {
		return
	}
	c.startLocked()
}

// backoff spaces out restarts after crashes. Every boot costs ~45 s of the
// container's only CPU, so a crash loop must not turn into a CPU hog.
func (c *chatApp) backoff() time.Duration {
	if c.failures == 0 {
		return 0
	}
	if c.failures > 5 {
		return 15 * time.Minute
	}
	return 30 * time.Second << (c.failures - 1)
}

func (c *chatApp) startLocked() {
	logf, err := openChatLog(c.logPath)
	if err != nil {
		log.Printf("[chitchat] log %s: %v", c.logPath, err)
	}
	type started struct {
		p   *os.Process
		err error
	}
	ch := make(chan started, 1)
	go func() {
		// Pdeathsig fires when the *thread* that forked the child exits, not the
		// process, so this goroutine stays locked to its thread for the JVM's
		// whole life. That is what takes the JVM down if the LB is killed.
		runtime.LockOSThread()
		cmd := exec.Command(c.cmdPath)
		cmd.Env = chatEnv()
		if logf != nil {
			cmd.Stdout, cmd.Stderr = logf, logf
			defer logf.Close()
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		if err := cmd.Start(); err != nil {
			ch <- started{err: err}
			return
		}
		ch <- started{p: cmd.Process}
		c.exited(cmd.Process, cmd.Wait())
	}()

	s := <-ch
	now := time.Now()
	if s.err != nil {
		c.exitedAt = now
		c.failures++
		log.Printf("[chitchat] start %s: %v", c.cmdPath, s.err)
		return
	}
	c.proc, c.planned, c.startedAt = s.p, false, now
	c.starts++
	// Should memory run out regardless, the kernel must pick the JVM, never the LB.
	_ = os.WriteFile("/proc/"+strconv.Itoa(s.p.Pid)+"/oom_score_adj", []byte("1000"), 0)
	log.Printf("[chitchat] started JVM pid %d", s.p.Pid)
}

func (c *chatApp) exited(p *os.Process, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proc != p {
		return
	}
	now := time.Now()
	ran := now.Sub(c.startedAt)
	c.proc, c.exitedAt = nil, now
	if c.planned {
		c.planned = false
		if ran >= 5*time.Minute {
			c.failures = 0
		}
		return
	}
	if ran < 5*time.Minute {
		c.failures++
	} else {
		c.failures = 1
	}
	log.Printf("[chitchat] JVM exited on its own after %s (%v); restart in >= %s", ran.Round(time.Second), err, c.backoff())
}

type chatStatus struct {
	State       string `json:"state"`
	Ready       bool   `json:"ready"`
	PID         int    `json:"pid,omitempty"`
	UptimeS     int64  `json:"uptime_s,omitempty"`
	ResumesInS  int64  `json:"resumes_in_s,omitempty"`
	QuietS      int64  `json:"quiet_period_s"`
	Starts      int    `json:"starts"`
	LoadKills   int    `json:"killed_for_load"`
	CrashStreak int    `json:"crash_streak"`
}

func (c *chatApp) status() chatStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	s := chatStatus{
		QuietS:      int64(c.quiet / time.Second),
		Starts:      c.starts,
		LoadKills:   c.kills,
		CrashStreak: c.failures,
	}
	switch {
	case c.cmdPath == "":
		s.State = "unsupervised"
	case c.proc != nil:
		s.State, s.PID, s.UptimeS = "running", c.proc.Pid, int64(now.Sub(c.startedAt)/time.Second)
	case now.Sub(c.lastHot) < c.quiet:
		s.State, s.ResumesInS = "paused", int64((c.quiet-now.Sub(c.lastHot))/time.Second)
	case now.Sub(c.exitedAt) < c.backoff():
		s.State, s.ResumesInS = "backoff", int64((c.backoff()-now.Sub(c.exitedAt))/time.Second)
	default:
		s.State = "starting"
	}
	return s
}

// statusHandler reports the supervisor's view; ready means the JVM is accepting
// connections, which lags "running" by the ~45 s boot.
func (c *chatApp) statusHandler(w http.ResponseWriter, r *http.Request) {
	s := c.status()
	if conn, err := net.DialTimeout("tcp", c.addr, 150*time.Millisecond); err == nil {
		_ = conn.Close()
		s.Ready = true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(s)
}

// chatEnv hands the LB's environment to the JVM minus the reset secret and the
// Go runtime tuning, none of which belongs to it.
func chatEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		switch k, _, _ := strings.Cut(kv, "="); k {
		case "LB_RESET_KEY", "GOMAXPROCS", "GOMEMLIMIT", "GOGC":
			continue
		}
		out = append(out, kv)
	}
	return out
}

// openChatLog appends to the JVM log, starting it afresh past 16 MiB so repeated
// restarts cannot slowly fill the disk.
func openChatLog(path string) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if st, err := os.Stat(path); err == nil && st.Size() > 16<<20 {
		flags |= os.O_TRUNC
	}
	return os.OpenFile(path, flags, 0o644)
}

// killStrayJVMs removes a JVM left behind by an earlier LB process or started by
// hand, which would hold the port and escape supervision. It matches java
// processes only: the tmux server's own command line can mention the jar too,
// and killing it would take the LB's session down with it.
func killStrayJVMs(match string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || len(raw) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		if filepath.Base(args[0]) != "java" || !strings.Contains(string(raw), match) {
			continue
		}
		if syscall.Kill(pid, syscall.SIGKILL) == nil {
			log.Printf("[chitchat] killed unsupervised JVM pid %d", pid)
		}
	}
}
