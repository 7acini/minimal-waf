package waf

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/7acini/minimal-waf/internal/config"
)

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Handler struct {
	config    config.Config
	inspector *Inspector
	proxy     *httputil.ReverseProxy
	logger    *slog.Logger

	requestsTotal atomic.Uint64
	detectedTotal atomic.Uint64
	blockedTotal  atomic.Uint64
	tooLargeTotal atomic.Uint64
	skippedTotal  atomic.Uint64
	proxyErrors   atomic.Uint64
}

func NewHandler(cfg config.Config, logger *slog.Logger) (*Handler, error) {
	upstream, err := url.Parse(cfg.Upstream.URL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream: %w", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	director := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalHost := request.Host
		originalProto := "http"
		if request.TLS != nil {
			originalProto = "https"
		}
		if !cfg.Upstream.TrustForwardedHeaders {
			request.Header.Del("Forwarded")
			request.Header.Del("X-Forwarded-For")
			request.Header.Del("X-Forwarded-Host")
			request.Header.Del("X-Forwarded-Proto")
		}
		director(request)
		if cfg.Upstream.PreserveHost {
			request.Host = originalHost
		}
		if !cfg.Upstream.TrustForwardedHeaders {
			request.Header.Set("X-Forwarded-Host", originalHost)
			request.Header.Set("X-Forwarded-Proto", originalProto)
		}
	}
	proxy.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: cfg.Server.WriteTimeout.Duration,
	}

	handler := &Handler{
		config:    cfg,
		inspector: NewInspector(cfg.WAF),
		proxy:     proxy,
		logger:    logger,
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
		handler.proxyErrors.Add(1)
		// Transport errors may contain the request URL, including query secrets.
		logger.Error("upstream request failed", "request_id", requestID(request), "error_type", fmt.Sprintf("%T", proxyErr))
		writeJSONError(writer, http.StatusBadGateway, "upstream unavailable", requestID(request))
	}
	return handler, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.requestsTotal.Add(1)
	request = request.WithContext(withRequestID(request.Context(), chooseRequestID(request)))
	writer.Header().Set("X-Request-ID", requestID(request))

	if strings.HasPrefix(request.URL.Path, "/_minimal-waf/") {
		h.serveInternal(writer, request)
		return
	}

	body, err := h.readInspectionBody(request)
	if err != nil {
		if errors.Is(err, errInspectionSkipped) {
			h.skippedTotal.Add(1)
			h.logger.Warn("body inspection skipped", "request_id", requestID(request), "reason", "body_too_large_in_monitor_mode", "method", request.Method, "path", request.URL.Path)
			body = nil
		} else if errors.Is(err, errBodyTooLarge) {
			h.tooLargeTotal.Add(1)
			h.logger.Warn("request body rejected", "request_id", requestID(request), "reason", "body_too_large", "method", request.Method, "path", request.URL.Path)
			writeJSONError(writer, http.StatusRequestEntityTooLarge, "request body exceeds inspection limit", requestID(request))
			return
		} else {
			h.logger.Error("request body read failed", "request_id", requestID(request), "error", err)
			writeJSONError(writer, http.StatusBadRequest, "unable to read request body", requestID(request))
			return
		}
	}

	detections := h.inspector.InspectRequest(request, body)
	if len(detections) > 0 {
		h.detectedTotal.Add(1)
		h.logDetection(request, detections)
		if h.config.WAF.Mode == "block" {
			h.blockedTotal.Add(1)
			writeJSONError(writer, h.config.WAF.BlockStatus, "request blocked by security policy", requestID(request))
			return
		}
	}

	h.proxy.ServeHTTP(writer, request)
}

var (
	errBodyTooLarge      = errors.New("request body too large")
	errInspectionSkipped = errors.New("body inspection skipped")
)

func (h *Handler) readInspectionBody(request *http.Request) ([]byte, error) {
	if !h.inspector.inspectMethods[strings.ToUpper(request.Method)] || request.Body == nil {
		return nil, nil
	}
	if request.ContentLength > h.config.WAF.MaxBodyBytes {
		if h.config.WAF.Mode == "monitor" {
			return nil, errInspectionSkipped
		}
		return nil, errBodyTooLarge
	}
	limit := h.config.WAF.MaxBodyBytes + 1
	body, err := io.ReadAll(io.LimitReader(request.Body, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > h.config.WAF.MaxBodyBytes {
		if h.config.WAF.Mode == "monitor" {
			request.Body = &replayReadCloser{Reader: io.MultiReader(bytes.NewReader(body), request.Body), Closer: request.Body}
			return nil, errInspectionSkipped
		}
		_ = request.Body.Close()
		return nil, errBodyTooLarge
	}
	if err := request.Body.Close(); err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	return body, nil
}

func (h *Handler) logDetection(request *http.Request, detections []Detection) {
	ruleIDs := make([]string, 0, len(detections))
	categories := make([]string, 0, len(detections))
	locations := make([]string, 0, len(detections))
	parameters := make([]string, 0, len(detections))
	for _, detection := range detections {
		ruleIDs = appendUnique(ruleIDs, detection.RuleID)
		categories = appendUnique(categories, detection.Category)
		locations = appendUnique(locations, detection.Location)
		if detection.Parameter != "" {
			parameters = appendUnique(parameters, detection.Parameter)
		}
	}
	sort.Strings(ruleIDs)
	sort.Strings(categories)
	h.logger.Warn("WAF detection",
		"request_id", requestID(request),
		"mode", h.config.WAF.Mode,
		"method", request.Method,
		"path", request.URL.Path,
		"client_ip", clientIP(request, h.config.Upstream.TrustForwardedHeaders),
		"rule_ids", ruleIDs,
		"categories", categories,
		"locations", locations,
		"parameters", parameters,
	)
}

func (h *Handler) serveInternal(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	switch request.URL.Path {
	case "/_minimal-waf/healthz":
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"status":"ok"}`+"\n")
	case "/_minimal-waf/metrics":
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(writer, "minimal_waf_requests_total %d\nminimal_waf_detected_total %d\nminimal_waf_blocked_total %d\nminimal_waf_body_too_large_total %d\nminimal_waf_inspection_skipped_total %d\nminimal_waf_proxy_errors_total %d\n",
			h.requestsTotal.Load(), h.detectedTotal.Load(), h.blockedTotal.Load(), h.tooLargeTotal.Load(), h.skippedTotal.Load(), h.proxyErrors.Load())
	default:
		writeJSONError(writer, http.StatusNotFound, "not found", requestID(request))
	}
}

func writeJSONError(writer http.ResponseWriter, status int, message, id string) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": message, "request_id": id})
}

func appendUnique(values []string, candidate string) []string {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func clientIP(request *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if forwarded := strings.TrimSpace(strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
			return forwarded
		}
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil {
		return host
	}
	return request.RemoteAddr
}

type replayReadCloser struct {
	io.Reader
	io.Closer
}

func chooseRequestID(request *http.Request) string {
	if candidate := request.Header.Get("X-Request-ID"); validRequestID.MatchString(candidate) {
		return candidate
	}
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err == nil {
		return hex.EncodeToString(buffer)
	}
	return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
}
