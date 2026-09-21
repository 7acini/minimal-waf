package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPercentile(t *testing.T) {
	values := []int64{int64(time.Millisecond), 2 * int64(time.Millisecond), 3 * int64(time.Millisecond), 4 * int64(time.Millisecond), 5 * int64(time.Millisecond)}
	if got := percentile(values, 50); got != 3 {
		t.Fatalf("p50=%v, want 3 ms", got)
	}
	if got := percentile(values, 95); got != 5 {
		t.Fatalf("p95=%v, want 5 ms", got)
	}
	if got := percentile(nil, 99); got != 0 {
		t.Fatalf("empty p99=%v, want 0", got)
	}
}

func TestLoadCountsResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	measured := load(server.Client(), server.URL, 100, 8)
	if measured.HTTP403 != 100 || measured.HTTP200 != 0 || measured.HTTPOther != 0 || measured.RequestErrors != 0 {
		t.Fatalf("unexpected load result: %#v", measured)
	}
	if measured.P99Millis <= 0 || measured.RequestsPerSec <= 0 {
		t.Fatalf("missing latency or throughput: %#v", measured)
	}
}
