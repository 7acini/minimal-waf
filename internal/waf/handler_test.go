package waf

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/7acini/minimal-waf/internal/config"
)

func TestBlocksMaliciousGETBeforeUpstream(t *testing.T) {
	upstreamCalls := 0
	handler := testHandler(t, "block", func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls++
		writer.WriteHeader(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "http://waf/index.php?e=../../../../etc/passwd", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", response.Code, response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream called %d times, want 0", upstreamCalls)
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID")
	}
}

func TestBlocksDoubleEncodedPayload(t *testing.T) {
	handler := testHandler(t, "block", func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream must not be called")
	})
	request := httptest.NewRequest(http.MethodGet, "http://waf/index.php?e=%252e%252e%252f%252e%252e%252fetc%252fpasswd", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestBlocksFormPOSTAndPreservesBenignBody(t *testing.T) {
	upstreamCalls := 0
	handler := testHandler(t, "block", func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls++
		body, _ := io.ReadAll(request.Body)
		_, _ = writer.Write(body)
	})

	malicious := url.Values{"e": {"../../../../etc/hosts"}}.Encode()
	request := httptest.NewRequest(http.MethodPost, "http://waf/index.php", strings.NewReader(malicious))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || upstreamCalls != 0 {
		t.Fatalf("malicious POST status=%d calls=%d", response.Code, upstreamCalls)
	}

	benign := url.Values{"name": {"Guilherme"}, "action": {"save"}}.Encode()
	request = httptest.NewRequest(http.MethodPost, "http://waf/index.php", strings.NewReader(benign))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != benign || upstreamCalls != 1 {
		t.Fatalf("benign POST status=%d body=%q calls=%d", response.Code, response.Body.String(), upstreamCalls)
	}
}

func TestBlocksJSONSQLiAndXSS(t *testing.T) {
	handler := testHandler(t, "block", func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream must not be called")
	})
	for _, body := range []string{
		`{"filter":"' UNION SELECT password FROM users"}`,
		`{"profile":{"bio":"<img src=x onerror=alert(1)>"}}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "http://waf/api", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Errorf("body %s: status=%d, want 403", body, response.Code)
		}
	}
}

func TestMonitorModeForwardsDetection(t *testing.T) {
	upstreamCalls := 0
	handler := testHandler(t, "monitor", func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls++
		writer.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "http://waf/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || upstreamCalls != 1 {
		t.Fatalf("status=%d calls=%d, want 204 and 1", response.Code, upstreamCalls)
	}
	if handler.detectedTotal.Load() != 1 || handler.blockedTotal.Load() != 0 {
		t.Fatalf("detected=%d blocked=%d", handler.detectedTotal.Load(), handler.blockedTotal.Load())
	}
}

func TestRejectsOversizedInspectedBody(t *testing.T) {
	handler := testHandler(t, "block", func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream must not be called")
	})
	handler.config.WAF.MaxBodyBytes = 8
	request := httptest.NewRequest(http.MethodPost, "http://waf/", bytes.NewBufferString("123456789"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413", response.Code)
	}
}

func TestMonitorModeForwardsOversizedBodyWithoutTruncation(t *testing.T) {
	body := "123456789"
	handler := testHandler(t, "monitor", func(writer http.ResponseWriter, request *http.Request) {
		forwarded, _ := io.ReadAll(request.Body)
		_, _ = writer.Write(forwarded)
	})
	handler.config.WAF.MaxBodyBytes = 8
	request := httptest.NewRequest(http.MethodPost, "http://waf/", strings.NewReader(body))
	request.ContentLength = -1 // Exercise the chunked/unknown-length replay path.
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != body {
		t.Fatalf("status=%d body=%q, want 200 and %q", response.Code, response.Body.String(), body)
	}
	if handler.skippedTotal.Load() != 1 {
		t.Fatalf("skipped=%d, want 1", handler.skippedTotal.Load())
	}
}

func TestExclusionIsNarrowlyApplied(t *testing.T) {
	cfg := config.Default()
	cfg.WAF.Exclusions = []config.Exclusion{{
		PathPrefix: "/admin/search", Methods: []string{"GET"}, Parameters: []string{"query"}, Categories: []string{"sqli"},
	}}
	inspector := NewInspector(cfg.WAF)
	request := httptest.NewRequest(http.MethodGet, "http://waf/admin/search?query=SELECT+id+FROM+products&other=../../etc/passwd", nil)
	detections := inspector.InspectRequest(request, nil)
	for _, detection := range detections {
		if detection.Category == "sqli" && detection.Parameter == "query" {
			t.Fatalf("excluded detection remains: %#v", detection)
		}
	}
	if len(detections) == 0 {
		t.Fatal("unrelated LFI detection was incorrectly excluded")
	}
}

func TestInternalHealthAndMetrics(t *testing.T) {
	handler := testHandler(t, "block", func(http.ResponseWriter, *http.Request) {})
	for _, path := range []string{"/_minimal-waf/healthz", "/_minimal-waf/metrics"} {
		request := httptest.NewRequest(http.MethodGet, "http://waf"+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("%s status=%d, want 200", path, response.Code)
		}
	}
}

func testHandler(t *testing.T, mode string, upstream http.HandlerFunc) *Handler {
	t.Helper()
	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)
	cfg := config.Default()
	cfg.Upstream.URL = server.URL
	cfg.WAF.Mode = mode
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
