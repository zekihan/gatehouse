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
	"strings"
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

func (r *requestRecord) policyDeny(reason string) {
	if r.deny == "" {
		r.deny = reason
	}
}

func incomingRequest(r *http.Request) accessEntry {
	entry := accessEntry{
		Method:    r.Method,
		Host:      r.Host,
		Path:      r.URL.EscapedPath(),
		Query:     r.URL.RawQuery,
		Protocol:  r.Proto,
		UserAgent: r.UserAgent(),
		Referer:   r.Referer(),
	}
	if strings.ContainsAny(r.URL.Path, "?#") {
		entry.Path = "[redacted]"
	}
	if r.TLS != nil {
		entry.TLSVersion, entry.SNI = r.TLS.Version, r.TLS.ServerName
	}
	return entry
}

func (p *Plane) observe(
	w *responseWriter,
	record requestRecord,
	entry accessEntry,
	method string,
	start time.Time,
) {
	status := w.status
	if status == 0 {
		status = 499
	}
	elapsed := time.Since(start)
	in := record.requestBytes.Load()
	p.metrics.request(record, status, method, elapsed, in, w.bytes)
	if p.opts.AccessLog == nil || record.logOff {
		return
	}

	entry.Time = start.UTC()
	entry.Listener = record.listener
	if record.client.IsValid() {
		entry.ClientIP = record.client.String()
	}
	entry.Identity, entry.Deny = record.identity, record.deny
	entry.Route, entry.Backend = record.route, record.backend
	entry.Status, entry.BytesIn, entry.BytesOut = status, in, w.bytes
	entry.Duration, entry.Upstream = milliseconds(elapsed), milliseconds(record.upstream)
	p.writeAccess(entry)
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func (p *Plane) writeAccess(entry accessEntry) {
	if p.opts.AccessLog == nil {
		return
	}
	entry.RequestID = fmt.Sprintf("%x-%x", entry.Time.UnixNano(), p.metrics.ids.Add(1))
	entry.Query, entry.Referer = redactedQuery(entry.Query), redactedReferer(entry.Referer)
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if err := json.NewEncoder(p.opts.AccessLog).Encode(entry); err != nil {
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
