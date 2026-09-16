package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type ExperimentResult struct {
	Experiment     string  `json:"experiment"`
	URL            string  `json:"url"`
	Requests       int     `json:"requests"`
	Concurrency    int     `json:"concurrency"`
	Successful     uint64  `json:"successful"`
	Failed         uint64  `json:"failed"`
	ElapsedTimeSec float64 `json:"elapsed_time_sec"`
	ThroughputRPS  float64 `json:"throughput_rps"`
	DropoutPercent float64 `json:"dropout_percent"`
	P50Ms          float64 `json:"p50_ms"`
	P95Ms          float64 `json:"p95_ms"`
	P99Ms          float64 `json:"p99_ms"`
	Timestamp      string  `json:"timestamp"`
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		b[i] = letterBytes[num.Int64()]
	}
	return string(b)
}

func main() {
	targetURL := flag.String("url", "http://127.0.0.1:3297", "")
	requests := flag.Int("requests", 3000, "")
	concurrency := flag.Int("concurrency", 30, "")
	timeout := flag.Duration("timeout", 4*time.Second, "")
	minLen := flag.Int("min-len", 10, "")
	maxLen := flag.Int("max-len", 200, "")
	minIntervalMs := flag.Int("min-interval", 2, "")
	maxIntervalMs := flag.Int("max-interval", 25, "")
	experiment := flag.String("experiment", "dynamic_test", "")
	outFile := flag.String("out", "", "")
	csvFile := flag.String("csv", "", "")
	flag.Parse()

	transport := &http.Transport{
		MaxIdleConns:        *concurrency * 3,
		MaxIdleConnsPerHost: *concurrency * 3,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   *timeout,
	}

	var successful atomic.Uint64
	var failed atomic.Uint64
	latencies := make([]time.Duration, 0, *requests)
	var latMu sync.Mutex

	jobs := make(chan int, *requests)
	var wg sync.WaitGroup
	startTime := time.Now()

	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			clientName := fmt.Sprintf("user-%d", workerID+1)
			localLat := make([]time.Duration, 0, (*requests / *concurrency) + 10)

			for jobID := range jobs {
				diff := *maxIntervalMs - *minIntervalMs
				if diff > 0 {
					rInt, _ := rand.Int(rand.Reader, big.NewInt(int64(diff)))
					time.Sleep(time.Duration(int64(*minIntervalMs)+rInt.Int64()) * time.Millisecond)
				}

				lenDiff := *maxLen - *minLen
				msgLen := *minLen
				if lenDiff > 0 {
					lInt, _ := rand.Int(rand.Reader, big.NewInt(int64(lenDiff)))
					msgLen += int(lInt.Int64())
				}
				msgText := randomString(msgLen)

				reqStart := time.Now()
				var err error
				var resp *http.Response

				if jobID%10 == 0 {
					resp, err = client.Get(*targetURL + "/feed")
				} else {
					var msgID string
					if jobID%25 == 0 {
						h := sha256.Sum256([]byte(fmt.Sprintf("dup-%d", jobID/25)))
						msgID = hex.EncodeToString(h[:16])
					}

					payload := map[string]string{
						"client-name": clientName,
						"msg":         msgText,
					}
					if msgID != "" {
						payload["message-id"] = msgID
					}

					bodyBytes, _ := json.Marshal(payload)
					resp, err = client.Post(*targetURL+"/message", "application/json", bytes.NewReader(bodyBytes))
				}

				reqDur := time.Since(reqStart)

				if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 400 {
					successful.Add(1)
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				} else {
					failed.Add(1)
					if resp != nil {
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					}
				}
				localLat = append(localLat, reqDur)
			}

			latMu.Lock()
			latencies = append(latencies, localLat...)
			latMu.Unlock()
		}(w)
	}

	for i := 0; i < *requests; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	elapsed := time.Since(startTime)
	totalReq := *requests
	succ := successful.Load()
	fail := failed.Load()

	var throughputRPS float64
	if elapsed.Seconds() > 0 {
		throughputRPS = float64(succ) / elapsed.Seconds()
	}

	var dropoutPercent float64
	if totalReq > 0 {
		dropoutPercent = (float64(fail) / float64(totalReq)) * 100.0
	}

	var p50, p95, p99 float64
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})
		n := len(latencies)
		p50 = float64(latencies[int(float64(n)*0.50)].Microseconds()) / 1000.0
		p95 = float64(latencies[int(float64(n)*0.95)].Microseconds()) / 1000.0
		p99 = float64(latencies[int(float64(n)*0.99)].Microseconds()) / 1000.0
	}

	res := ExperimentResult{
		Experiment:     *experiment,
		URL:            *targetURL,
		Requests:       totalReq,
		Concurrency:    *concurrency,
		Successful:     succ,
		Failed:         fail,
		ElapsedTimeSec: elapsed.Seconds(),
		ThroughputRPS:  throughputRPS,
		DropoutPercent: dropoutPercent,
		P50Ms:          p50,
		P95Ms:          p95,
		P99Ms:          p99,
		Timestamp:      time.Now().Format(time.RFC3339),
	}

	fmt.Printf("\n--- Benchmark Result: %s ---\n", *experiment)
	fmt.Printf("Requests: %d | Workers: %d | Elapsed: %.2fs\n", totalReq, *concurrency, elapsed.Seconds())
	fmt.Printf("Throughput: %.2f RPS | Dropout: %.2f%%\n", throughputRPS, dropoutPercent)
	fmt.Printf("Latencies: p50=%.2fms, p95=%.2fms, p99=%.2fms\n\n", p50, p95, p99)

	if *outFile != "" {
		_ = os.MkdirAll(filepath.Dir(*outFile), 0755)
		data, _ := json.MarshalIndent(res, "", "  ")
		_ = os.WriteFile(*outFile, data, 0644)
	}

	if *csvFile != "" {
		_ = os.MkdirAll(filepath.Dir(*csvFile), 0755)
		fileExists := false
		if _, err := os.Stat(*csvFile); err == nil {
			fileExists = true
		}
		f, err := os.OpenFile(*csvFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			w := csv.NewWriter(f)
			if !fileExists {
				_ = w.Write([]string{"Experiment", "Requests", "Concurrency", "ThroughputRPS", "DropoutPercent", "P50Ms", "P95Ms", "P99Ms"})
			}
			_ = w.Write([]string{
				res.Experiment,
				fmt.Sprintf("%d", res.Requests),
				fmt.Sprintf("%d", res.Concurrency),
				fmt.Sprintf("%.2f", res.ThroughputRPS),
				fmt.Sprintf("%.2f", res.DropoutPercent),
				fmt.Sprintf("%.2f", res.P50Ms),
				fmt.Sprintf("%.2f", res.P95Ms),
				fmt.Sprintf("%.2f", res.P99Ms),
			})
			w.Flush()
		}
	}
}
