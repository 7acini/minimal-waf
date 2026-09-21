// Command stress runs a reproducible loopback load test against the real WAF
// handler and a deliberately minimal HTTP backend. It is not a Docker or PHP
// benchmark.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/7acini/minimal-waf/internal/config"
	"github.com/7acini/minimal-waf/internal/logging"
	"github.com/7acini/minimal-waf/internal/waf"
)

type result struct {
	Scenario        string  `json:"scenario"`
	Requests        int     `json:"requests"`
	Concurrency     int     `json:"concurrency"`
	Warmup          int     `json:"warmup"`
	GoVersion       string  `json:"go_version"`
	GOMAXPROCS      int     `json:"gomaxprocs"`
	DurationSeconds float64 `json:"duration_seconds"`
	RequestsPerSec  float64 `json:"requests_per_second"`
	P50Millis       float64 `json:"latency_p50_ms"`
	P95Millis       float64 `json:"latency_p95_ms"`
	P99Millis       float64 `json:"latency_p99_ms"`
	HTTP200         int64   `json:"http_200"`
	HTTP403         int64   `json:"http_403"`
	HTTPOther       int64   `json:"http_other"`
	RequestErrors   int64   `json:"request_errors"`
	BackendRequests int64   `json:"backend_requests"`
	WAFDetected     uint64  `json:"waf_detected"`
	WAFBlocked      uint64  `json:"waf_blocked"`
	WAFProxyErrors  uint64  `json:"waf_proxy_errors"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	scenario := flag.String("scenario", "allowed", "allowed, blocked, or monitor")
	requests := flag.Int("requests", 100000, "measured requests")
	concurrency := flag.Int("concurrency", 64, "concurrent HTTP clients")
	warmup := flag.Int("warmup", 2000, "unmeasured warmup requests")
	logFile := flag.String("log-file", "", "absolute rotating JSONL log path; empty disables file output")
	flag.Parse()
	if *requests < 1 || *concurrency < 1 || *warmup < 0 {
		return errors.New("requests and concurrency must be positive; warmup cannot be negative")
	}
	if *logFile != "" && !filepath.IsAbs(*logFile) {
		return errors.New("log-file must be an absolute path")
	}
	if *scenario != "allowed" && *scenario != "blocked" && *scenario != "monitor" {
		return errors.New("scenario must be allowed, blocked, or monitor")
	}

	var backendRequests atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		backendRequests.Add(1)
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "ok")
	}))
	defer backend.Close()

	cfg := config.Default()
	cfg.Upstream.URL = backend.URL
	cfg.Logging.FilePath = *logFile
	if *scenario == "monitor" {
		cfg.WAF.Mode = "monitor"
	}
	logger, logCloser, err := logging.New(cfg.Logging, io.Discard)
	if err != nil {
		return err
	}
	if logCloser != nil {
		defer logCloser.Close()
	}
	handler, err := waf.NewHandler(cfg, logger)
	if err != nil {
		return err
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	transport := &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        *concurrency,
		MaxIdleConnsPerHost: *concurrency,
		MaxConnsPerHost:     *concurrency,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	target := server.URL + "/api/search?q=green"
	if *scenario != "allowed" {
		target = server.URL + "/api/search?file=../../../../etc/passwd"
	}

	_ = load(client, target, *warmup, *concurrency)
	backendRequests.Store(0)
	before, err := counters(client, server.URL)
	if err != nil {
		return err
	}
	measured := load(client, target, *requests, *concurrency)
	after, err := counters(client, server.URL)
	if err != nil {
		return err
	}
	measured.Scenario = *scenario
	measured.Requests = *requests
	measured.Concurrency = *concurrency
	measured.Warmup = *warmup
	measured.GoVersion = runtime.Version()
	measured.GOMAXPROCS = runtime.GOMAXPROCS(0)
	measured.BackendRequests = backendRequests.Load()
	measured.WAFDetected = after["minimal_waf_detected_total"] - before["minimal_waf_detected_total"]
	measured.WAFBlocked = after["minimal_waf_blocked_total"] - before["minimal_waf_blocked_total"]
	measured.WAFProxyErrors = after["minimal_waf_proxy_errors_total"] - before["minimal_waf_proxy_errors_total"]
	if err := json.NewEncoder(os.Stdout).Encode(measured); err != nil {
		return err
	}

	expectedStatus := int64(*requests)
	if measured.RequestErrors != 0 || measured.HTTPOther != 0 || measured.WAFProxyErrors != 0 {
		return errors.New("unexpected HTTP or proxy errors during measured load")
	}
	if *scenario == "blocked" {
		if measured.HTTP403 != expectedStatus || measured.BackendRequests != 0 || measured.WAFDetected != uint64(*requests) || measured.WAFBlocked != uint64(*requests) {
			return errors.New("blocked requests did not remain entirely before the backend")
		}
	} else if measured.HTTP200 != expectedStatus || measured.BackendRequests != expectedStatus {
		return errors.New("allowed or monitored requests did not all reach the backend")
	} else if *scenario == "monitor" && (measured.WAFDetected != uint64(*requests) || measured.WAFBlocked != 0) {
		return errors.New("monitor mode did not detect and forward every request")
	} else if *scenario == "allowed" && (measured.WAFDetected != 0 || measured.WAFBlocked != 0) {
		return errors.New("benign requests unexpectedly matched a rule")
	}
	return nil
}

func load(client *http.Client, target string, count, concurrency int) result {
	latencies := make([]int64, count)
	var next, ok, blocked, other, failed atomic.Int64
	start := time.Now()
	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				index := int(next.Add(1)) - 1
				if index >= count {
					return
				}
				began := time.Now()
				response, err := client.Get(target)
				if err != nil {
					failed.Add(1)
					continue
				}
				_, readErr := io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil {
					failed.Add(1)
					continue
				}
				latencies[index] = time.Since(began).Nanoseconds()
				switch response.StatusCode {
				case http.StatusOK:
					ok.Add(1)
				case http.StatusForbidden:
					blocked.Add(1)
				default:
					other.Add(1)
				}
			}
		}()
	}
	workers.Wait()
	elapsed := time.Since(start).Seconds()
	valid := latencies[:0]
	for _, latency := range latencies {
		if latency > 0 {
			valid = append(valid, latency)
		}
	}
	slices.Sort(valid)
	return result{
		DurationSeconds: elapsed,
		RequestsPerSec:  float64(count) / elapsed,
		P50Millis:       percentile(valid, 50),
		P95Millis:       percentile(valid, 95),
		P99Millis:       percentile(valid, 99),
		HTTP200:         ok.Load(),
		HTTP403:         blocked.Load(),
		HTTPOther:       other.Load(),
		RequestErrors:   failed.Load(),
	}
}

func percentile(sorted []int64, percent int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := (len(sorted)*percent + 99) / 100
	return float64(sorted[index-1]) / float64(time.Millisecond)
}

func counters(client *http.Client, baseURL string) (map[string]uint64, error) {
	response, err := client.Get(baseURL + "/_minimal-waf/metrics")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics status: %d", response.StatusCode)
	}
	values := make(map[string]uint64)
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, err
		}
		values[fields[0]] = value
	}
	return values, scanner.Err()
}
