package dataplane

import (
	"bufio"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type responseWriter struct {
	http.ResponseWriter

	status       int
	bytes        uint64
	bodyDeadline time.Duration
	upgrade      *idleStream
}

func (w *responseWriter) WriteHeader(status int) {
	if status >= 200 && w.status == 0 {
		w.status = status
		if w.bodyDeadline != 0 {
			setResponseDeadline(w.ResponseWriter, w.bodyDeadline)
		}
		securityHeaders(w.Header())
	}
	w.ResponseWriter.WriteHeader(status)
}

func setResponseDeadline(w http.ResponseWriter, limit time.Duration) {
	controller := http.NewResponseController(w)
	//nolint:errcheck // the writer may be closed or may not support deadlines.
	_ = controller.SetWriteDeadline(time.Now().Add(limit))
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	if n > 0 {
		w.bytes += uint64(n)
	}
	return n, err
}

func (w *responseWriter) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.status = http.StatusSwitchingProtocols
		if w.upgrade != nil {
			w.upgrade.attach(c)
		}
	}
	return c, rw, err
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

var securityValues = map[string][]string{
	"Strict-Transport-Security": {"max-age=31536000; includeSubDomains; preload"},
	"X-Frame-Options":           {"SAMEORIGIN"},
	"X-Content-Type-Options":    {"nosniff"},
	"X-Xss-Protection":          {"1; mode=block"},
	"Referrer-Policy":           {"strict-origin-when-cross-origin"},
	"Permissions-Policy": {
		"geolocation=(), midi=(), camera=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=(), microphone=()",
	},
	"Cross-Origin-Embedder-Policy": {"unsafe-none"},
	"Cross-Origin-Opener-Policy":   {"same-origin"},
	"Cross-Origin-Resource-Policy": {"same-site"},
	"X-Robots-Tag":                 {"none,noarchive,nosnippet,notranslate,noimageindex"},
	"X-Forwarded-Proto":            {"https"},
}

func securityHeaders(h http.Header) {
	maps.Copy(h, securityValues)
	h.Del("Server")
	h.Del("X-Powered-By")
}

type requestRecord struct {
	client       netip.Addr
	listener     uint16
	route        string
	backend      string
	identity     string
	deny         string
	requestBytes *atomicCounter
	upstream     time.Duration
	logOff       bool
}

type accessEntry struct {
	Time       time.Time `json:"time"`
	RequestID  string    `json:"request_id"`
	Listener   uint16    `json:"listener"`
	ClientIP   string    `json:"client_ip"`
	Identity   string    `json:"client_identity,omitempty"`
	TLSVersion uint16    `json:"tls.version,omitempty"`
	SNI        string    `json:"tls.sni,omitempty"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	Query      string    `json:"query,omitempty"`
	Protocol   string    `json:"proto"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Referer    string    `json:"referer,omitempty"`
	Status     int       `json:"status"`
	BytesIn    uint64    `json:"bytes_in"`
	BytesOut   uint64    `json:"bytes_out"`
	Duration   float64   `json:"duration_ms"`
	Upstream   float64   `json:"upstream_ms"`
	Route      string    `json:"route"`
	Backend    string    `json:"backend"`
	Deny       string    `json:"deny_reason,omitempty"`
}

func (p *Plane) observe(w *responseWriter, r *http.Request, entry requestRecord, start time.Time) {
	status := w.status
	if status == 0 {
		status = 499
	}
	elapsed := time.Since(start)
	in := entry.requestBytes.Load()
	p.metrics.request(entry, status, r.Method, elapsed, in, w.bytes)
	if p.opts.AccessLog == nil || entry.logOff {
		return
	}
	ip := ""
	if entry.client.IsValid() {
		ip = entry.client.String()
	}
	logged := accessEntry{
		Time:      start.UTC(),
		RequestID: fmt.Sprintf("%x-%x", start.UnixNano(), p.metrics.ids.Add(1)),
		Listener:  entry.listener,
		ClientIP:  ip,
		Identity:  entry.identity,
		Status:    status,
		Method:    r.Method,
		Host:      r.Host,
		Path:      r.URL.EscapedPath(),
		Query:     redactedQuery(r.URL.RawQuery),
		Protocol:  r.Proto,
		UserAgent: r.UserAgent(),
		Referer:   redactedReferer(r.Referer()),
		BytesIn:   in,
		BytesOut:  w.bytes,
		Duration:  elapsed.Seconds() * 1000,
		Upstream:  entry.upstream.Seconds() * 1000,
		Route:     entry.route,
		Backend:   entry.backend,
		Deny:      entry.deny,
	}
	if r.TLS != nil {
		logged.TLSVersion, logged.SNI = r.TLS.Version, r.TLS.ServerName
	}
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if err := json.NewEncoder(p.opts.AccessLog).Encode(logged); err != nil {
		p.metrics.logErrors.Add(1)
	}
}

func redactedQuery(raw string) string {
	if raw == "" {
		return ""
	}
	var result strings.Builder
	for pair := range strings.SplitSeq(strings.ReplaceAll(raw, ";", "&"), "&") {
		key, value, hasValue := strings.Cut(pair, "=")
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			return "[redacted]"
		}
		if result.Len() > 0 {
			result.WriteByte('&')
		}
		result.WriteString(key)
		if !hasValue {
			continue
		}
		result.WriteByte('=')
		switch strings.ToLower(decoded) {
		case "code", "state", "id_token", "access_token", "token", "x-amz-signature",
			"x-amz-credential", "x-amz-security-token", "signature", "awsaccesskeyid":
			result.WriteString("[redacted]")
		default:
			result.WriteString(value)
		}
	}
	return result.String()
}

func redactedReferer(value string) string {
	if value == "" {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil || u.Opaque != "" {
		return "[redacted]"
	}
	u.User, u.Fragment, u.RawFragment = nil, "", ""
	u.RawQuery = redactedQuery(u.RawQuery)
	return u.String()
}

type metricKey struct {
	port                   uint16
	code                   int
	route, backend, method string
}

type series struct {
	count, bytesIn, bytesOut uint64
	elapsed, upstream        time.Duration
	latency, upstreamLatency [8]uint64
}

type metrics struct {
	mu         sync.Mutex
	ids        atomicCounter
	logErrors  atomicCounter
	requests   map[metricKey]series
	handshakes map[string]uint64
	denies     map[string]uint64
}

var latencyBounds = []time.Duration{
	500 * time.Microsecond, time.Millisecond, 5 * time.Millisecond, 25 * time.Millisecond,
	100 * time.Millisecond, 500 * time.Millisecond, time.Second, 10 * time.Second,
}

func (m *metrics) request(
	entry requestRecord,
	status int,
	method string,
	elapsed time.Duration,
	in, out uint64,
) {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE":
	default:
		method = "OTHER"
	}
	key := metricKey{
		port:    entry.listener,
		code:    status,
		route:   entry.route,
		backend: entry.backend,
		method:  method,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.requests == nil {
		m.requests = make(map[metricKey]series)
		m.denies = make(map[string]uint64)
	}
	s := m.requests[key]
	s.count++
	s.bytesIn += in
	s.bytesOut += out
	s.elapsed += elapsed
	s.upstream += entry.upstream
	for i, limit := range latencyBounds {
		if elapsed <= limit {
			s.latency[i]++
		}
		if entry.upstream <= limit {
			s.upstreamLatency[i]++
		}
	}
	m.requests[key] = s
	if entry.deny != "" {
		m.denies[entry.deny]++
	}
}

func (m *metrics) handshake(result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.handshakes == nil {
		m.handshakes = make(map[string]uint64)
	}
	m.handshakes[result]++
}

func (p *Plane) Metrics() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var text strings.Builder
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		p.metrics.render(&text)
		if s := p.state.Load(); s != nil {
			fmt.Fprintf(&text, "gatehouse_snapshot_digest_info{digest=%q} 1\n", s.digest)
			for number, port := range s.ports {
				for name, host := range port.hosts {
					if host.tls != nil {
						fmt.Fprintf(
							&text,
							"gatehouse_certificate_expiry_timestamp_seconds{listener=%q,host=%q} %d\n",
							listenerName(
								number,
							),
							name,
							host.tls.Certificates[0].Leaf.NotAfter.Unix(),
						)
					}
				}
			}
		}
		fmt.Fprintf(&text, "gatehouse_access_log_errors_total %d\n", p.metrics.logErrors.Load())
		if _, err := fmt.Fprint(w, text.String()); err != nil {
			return
		}
	})
}

func (m *metrics) render(out *strings.Builder) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]metricKey, 0, len(m.requests))
	for key := range m.requests {
		keys = append(keys, key)
	}
	formatLabels := func(k metricKey) string {
		return fmt.Sprintf("route=%q,listener=%q,backend=%q,code=%q,method=%q",
			k.route, listenerName(k.port), k.backend, strconv.Itoa(k.code), k.method)
	}
	slices.SortFunc(keys, func(a, b metricKey) int {
		return strings.Compare(formatLabels(a), formatLabels(b))
	})
	for _, key := range keys {
		labels := formatLabels(key)
		s := m.requests[key]
		fmt.Fprintf(out, "gatehouse_requests_total{%s} %d\n", labels, s.count)
		fmt.Fprintf(out, "gatehouse_request_bytes_total{%s} %d\n", labels, s.bytesIn)
		fmt.Fprintf(out, "gatehouse_response_bytes_total{%s} %d\n", labels, s.bytesOut)
		writeHistogram(
			out,
			"gatehouse_request_duration_seconds",
			labels,
			s.latency,
			s.elapsed,
			s.count,
		)
		writeHistogram(
			out,
			"gatehouse_upstream_duration_seconds",
			labels,
			s.upstreamLatency,
			s.upstream,
			s.count,
		)
	}
	for result, n := range m.handshakes {
		fmt.Fprintf(out, "gatehouse_tls_handshakes_total{result=%q} %d\n", result, n)
	}
	for reason, n := range m.denies {
		fmt.Fprintf(out, "gatehouse_denies_total{reason=%q} %d\n", reason, n)
	}
}

func writeHistogram(
	out *strings.Builder,
	name, labels string,
	buckets [8]uint64,
	sum time.Duration,
	count uint64,
) {
	for i, n := range buckets {
		fmt.Fprintf(
			out,
			"%s_bucket{%s,le=%q} %d\n",
			name,
			labels,
			fmt.Sprint(latencyBounds[i].Seconds()),
			n,
		)
	}
	fmt.Fprintf(out, "%s_bucket{%s,le=\"+Inf\"} %d\n%s_sum{%s} %g\n%s_count{%s} %d\n",
		name, labels, count, name, labels, sum.Seconds(), name, labels, count)
}
