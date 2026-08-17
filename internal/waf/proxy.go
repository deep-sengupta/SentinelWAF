package waf

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"sentinelwaf/internal/config"
	"sentinelwaf/internal/logging"
	"sentinelwaf/internal/rules"
	"sentinelwaf/internal/security"
	"sentinelwaf/internal/state"
)

var requestCounter uint64
var errBodyTooLarge = errors.New("request body too large")

type Server struct {
	cfg     *config.Config
	auditor *logging.Auditor
	state   *state.Store
	engine  *rules.Engine
	limiter *RateLimiter
	proxy   *httputil.ReverseProxy
	target  *url.URL
}

func NewServer(cfg *config.Config, auditor *logging.Auditor, stateStore *state.Store) (*Server, error) {
	target, err := url.Parse(cfg.WAF.TargetURL)
	if err != nil {
		return nil, err
	}
	engine, err := rules.New(cfg.CustomRules, cfg.DisabledRules, cfg.WAF.BlockingAnomalyThreshold, cfg.WAF.BlockingParanoiaLevel)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		if !cfg.WAF.PreserveHost {
			req.Host = target.Host
		}
		req.Header.Set("X-SentinelWAF", "active")
		req.Header.Set("X-Forwarded-Proto", forwardedProto(req))
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		security.Apply(resp.Header, cfg.SecurityHeaders)
		sentinelCSRFToken(resp, cfg)
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		security.Apply(w.Header(), cfg.SecurityHeaders)
		http.Error(w, "SentinelWAF proxy error", http.StatusBadGateway)
	}
	return &Server{
		cfg:     cfg,
		auditor: auditor,
		state:   stateStore,
		engine:  engine,
		limiter: NewRateLimiter(cfg.WAF.RateLimitRequests, cfg.WAF.RateLimitBurst, cfg.WAF.RateLimitWindowSeconds, cfg.WAF.RateLimitBlockSeconds),
		proxy:   proxy,
		target:  target,
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:              s.cfg.WAF.ListenAddress,
		Handler:           s.recoverer(s),
		ReadTimeout:       time.Duration(s.cfg.WAF.ReadTimeoutSeconds) * time.Second,
		ReadHeaderTimeout: time.Duration(s.cfg.WAF.ReadTimeoutSeconds) * time.Second,
		WriteTimeout:      time.Duration(s.cfg.WAF.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:       time.Duration(s.cfg.WAF.IdleTimeoutSeconds) * time.Second,
		MaxHeaderBytes:    s.cfg.WAF.MaxHeaderBytes,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := nextRequestID()
	if r.URL.Path == "/healthz" {
		security.Apply(w.Header(), s.cfg.SecurityHeaders)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("SentinelWAF healthy\n"))
		return
	}
	clientIP := s.clientIP(r)
	stateData, err := s.state.Read()
	wafEnabled := err == nil && stateData.Enabled
	if !wafEnabled {
		s.proxyRequest(w, r, requestID, clientIP, "waf disabled", false, requestBytes(r, nil))
		return
	}
	if s.cfg.IsIPAllowlisted(clientIP) || s.cfg.IsPathAllowlisted(r.URL.Path) {
		s.proxyRequest(w, r, requestID, clientIP, "allowlist", true, requestBytes(r, nil))
		return
	}
	if det := s.blocklistDetection(clientIP, r); det != nil {
		s.block(w, r, requestID, clientIP, http.StatusForbidden, *det, true, requestBytes(r, nil))
		return
	}
	if ok, retryAfter := s.limiter.Allow(clientIP); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		det := rules.Detection{
			RuleID:   "rate-limit",
			Name:     "rate limit exceeded",
			Category: "OWASP A04 Insecure Design",
			Severity: "medium",
			Reason:   "rate limit exceeded",
			Target:   "client_ip",
		}
		s.block(w, r, requestID, clientIP, http.StatusTooManyRequests, det, true, requestBytes(r, nil))
		return
	}
	if det := s.validateHeaders(r); det != nil {
		s.block(w, r, requestID, clientIP, http.StatusBadRequest, *det, true, requestBytes(r, nil))
		return
	}
	if r.ContentLength > s.cfg.WAF.MaxBodyBytes {
		det := rules.Detection{
			RuleID:   "request-size",
			Name:     "request body too large",
			Category: "OWASP A05 Security Misconfiguration",
			Severity: "medium",
			Reason:   "request body too large",
			Target:   "body",
		}
		s.block(w, r, requestID, clientIP, http.StatusRequestEntityTooLarge, det, true, r.ContentLength)
		return
	}
	body, err := s.readBody(r)
	if errors.Is(err, errBodyTooLarge) {
		det := rules.Detection{
			RuleID:   "request-size",
			Name:     "request body too large",
			Category: "OWASP A05 Security Misconfiguration",
			Severity: "medium",
			Reason:   "request body too large",
			Target:   "body",
		}
		s.block(w, r, requestID, clientIP, http.StatusRequestEntityTooLarge, det, true, int64(len(body)))
		return
	}
	if err != nil {
		det := rules.Detection{
			RuleID:   "malformed-body",
			Name:     "malformed request body",
			Category: "OWASP A05 Security Misconfiguration",
			Severity: "medium",
			Reason:   "malformed request body",
			Target:   "body",
		}
		s.block(w, r, requestID, clientIP, http.StatusBadRequest, det, true, requestBytes(r, body))
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	if det := s.csrfDetection(r); det != nil {
		s.block(w, r, requestID, clientIP, http.StatusForbidden, *det, true, requestBytes(r, body))
		return
	}
	inputs := s.inputs(r, body)
	if det := s.engine.Inspect(inputs); det != nil {
		s.block(w, r, requestID, clientIP, http.StatusForbidden, *det, true, requestBytes(r, body))
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	s.proxyRequest(w, r, requestID, clientIP, "clean", true, requestBytes(r, body))
}

func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request, requestID string, clientIP string, reason string, wafEnabled bool, bytesIn int64) {
	recorder := &statusRecorder{ResponseWriter: w}
	s.proxy.ServeHTTP(recorder, r)
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	_ = s.auditor.Write(logging.AuditEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Service:    config.ServiceName,
		RequestID:  requestID,
		Decision:   "allowed",
		RemoteIP:   clientIP,
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		Status:     status,
		Reason:     reason,
		UserAgent:  r.UserAgent(),
		Bytes:      bytesIn,
		WAFEnabled: wafEnabled,
		Target:     s.target.String(),
	})
}

func (s *Server) block(w http.ResponseWriter, r *http.Request, requestID string, clientIP string, status int, det rules.Detection, wafEnabled bool, bytesIn int64) {
	security.Apply(w.Header(), s.cfg.SecurityHeaders)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "SentinelWAF blocked the request: %s\n", det.Reason)
	_ = s.auditor.Write(logging.AuditEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Service:    config.ServiceName,
		RequestID:  requestID,
		Decision:   "blocked",
		RemoteIP:   clientIP,
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		Status:     status,
		Reason:     det.Reason,
		RuleID:     det.RuleID,
		Category:   det.Category,
		Severity:   det.Severity,
		UserAgent:  r.UserAgent(),
		Bytes:      bytesIn,
		WAFEnabled: wafEnabled,
		Target:     s.target.String(),
	})
}

func (s *Server) blocklistDetection(clientIP string, r *http.Request) *rules.Detection {
	if s.cfg.IsIPBlocklisted(clientIP) {
		return &rules.Detection{
			RuleID:   "blocklist-ip",
			Name:     "blocklisted client IP",
			Category: "OWASP A01 Broken Access Control",
			Severity: "high",
			Reason:   "blocklisted client IP",
			Target:   "client_ip",
		}
	}
	if s.cfg.IsPathBlocklisted(r.URL.Path) {
		return &rules.Detection{
			RuleID:   "blocklist-path",
			Name:     "blocklisted path",
			Category: "OWASP A01 Broken Access Control",
			Severity: "high",
			Reason:   "blocklisted path",
			Target:   "path",
		}
	}
	if s.cfg.IsUserAgentBlocklisted(r.UserAgent()) {
		return &rules.Detection{
			RuleID:   "blocklist-user-agent",
			Name:     "blocklisted user-agent",
			Category: "OWASP A09 Security Logging and Monitoring Failures",
			Severity: "medium",
			Reason:   "blocklisted user-agent",
			Target:   "user_agent",
		}
	}
	return nil
}

func (s *Server) validateHeaders(r *http.Request) *rules.Detection {
	if r.Host == "" {
		return headerDetection("missing host header")
	}
	if len(r.Header) > s.cfg.WAF.MaxHeaders {
		return headerDetection("too many request headers")
	}
	for name, values := range r.Header {
		if !validHeaderName(name) {
			return headerDetection("invalid request header name")
		}
		for _, value := range values {
			if len(value) > s.cfg.WAF.MaxHeaderValueBytes {
				return headerDetection("request header value too large")
			}
			if strings.ContainsAny(value, "\x00\r\n") {
				return headerDetection("invalid request header value")
			}
		}
	}
	return nil
}

func headerDetection(reason string) *rules.Detection {
	return &rules.Detection{
		RuleID:   "header-validation",
		Name:     reason,
		Category: "OWASP A05 Security Misconfiguration",
		Severity: "medium",
		Reason:   reason,
		Target:   "headers",
	}
}

func (s *Server) csrfDetection(r *http.Request) *rules.Detection {
	if !s.cfg.WAF.CSRFProtectionEnabled || s.cfg.IsCSRFExempt(r.URL.Path) {
		return nil
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil
	}
	headerToken := r.Header.Get(s.cfg.WAF.CSRFTokenHeader)
	cookie, err := r.Cookie(s.cfg.WAF.CSRFCookieName)
	if err != nil || headerToken == "" || cookie.Value == "" {
		return csrfFailure("csrf token missing")
	}
	if subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookie.Value)) != 1 {
		return csrfFailure("csrf token mismatch")
	}
	return nil
}

func csrfFailure(reason string) *rules.Detection {
	return &rules.Detection{
		RuleID:   "csrf-protection",
		Name:     reason,
		Category: "OWASP A01 Broken Access Control",
		Severity: "medium",
		Reason:   reason,
		Target:   "headers",
	}
}

func sentinelCSRFToken(resp *http.Response, cfg *config.Config) {
	if !cfg.WAF.CSRFProtectionEnabled || resp.Request == nil {
		return
	}
	switch resp.Request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		return
	}
	if _, err := resp.Request.Cookie(cfg.WAF.CSRFCookieName); err == nil {
		return
	}
	token := randomToken(32)
	if token == "" {
		return
	}
	cookie := &http.Cookie{
		Name:     cfg.WAF.CSRFCookieName,
		Value:    token,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	}
	resp.Header.Add("Set-Cookie", cookie.String())
}

func randomToken(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func (s *Server) readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.WAF.MaxBodyBytes+1))
	if err != nil {
		return body, err
	}
	if int64(len(body)) > s.cfg.WAF.MaxBodyBytes {
		return body, errBodyTooLarge
	}
	return body, nil
}

func (s *Server) inputs(r *http.Request, body []byte) map[string]string {
	headerBuilder := strings.Builder{}
	for name, values := range r.Header {
		for _, value := range values {
			headerBuilder.WriteString(name)
			headerBuilder.WriteString(": ")
			headerBuilder.WriteString(value)
			headerBuilder.WriteByte('\n')
		}
	}
	return map[string]string{
		"method":     r.Method,
		"url":        r.URL.String(),
		"path":       r.URL.EscapedPath() + "\n" + r.URL.Path,
		"query":      r.URL.RawQuery,
		"headers":    headerBuilder.String(),
		"body":       string(body),
		"user_agent": r.UserAgent(),
	}
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.WAF.TrustProxyHeaders {
		if value := r.Header.Get("X-Forwarded-For"); value != "" {
			parts := strings.Split(value, ",")
			if ip := strings.TrimSpace(parts[0]); net.ParseIP(ip) != nil {
				return ip
			}
		}
		if value := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(value) != nil {
			return value
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				security.Apply(w.Header(), s.cfg.SecurityHeaders)
				http.Error(w, "SentinelWAF handled a malformed request safely", http.StatusBadRequest)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func requestBytes(r *http.Request, body []byte) int64 {
	if body != nil {
		return int64(len(body))
	}
	if r.ContentLength > 0 {
		return r.ContentLength
	}
	return 0
}

func nextRequestID() string {
	value := atomic.AddUint64(&requestCounter, 1)
	return strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.FormatUint(value, 36)
}

func forwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !isTokenChar(c) {
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
		r.ResponseWriter.WriteHeader(status)
	}
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(data)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) Flush() {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}
