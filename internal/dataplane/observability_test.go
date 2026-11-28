package dataplane

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/observability"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

type logCase struct {
	name, path, mode, reason, route string
	port                            uint16
	status                          int
	off                             bool
}

var sensitiveParameters = []string{
	"code", "state", "id_token", "access_token", "token", "X-Amz-Signature",
	"X-Amz-Credential", "X-Amz-Security-Token", "Signature", "AWSAccessKeyId",
}

func TestAccessLogRedaction(t *testing.T) {
	pair, _ := makeCertificate(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil || n != 5 {
			t.Errorf("upstream read %d bytes: %v", n, err)
		}
		_, _ = io.WriteString(w, "hello")
	}))
	defer upstream.Close()
	be := &snapshot.Backend{
		Service:   "app/upstream",
		Port:      80,
		Endpoints: []string{strings.TrimPrefix(upstream.URL, "http://")},
	}
	routes := []snapshot.Route{
		{Name: "full", Namespace: "app", Path: "/ok", Backend: be},
		{Name: "off", Namespace: "app", Path: "/off", Backend: be, AccessLogOff: true},
		{Name: "error", Path: "/error", InvalidPolicy: true},
		{Name: "off-error", Path: "/off-error", InvalidPolicy: true, AccessLogOff: true},
	}
	const tlsPort, redirectPort = 8443, 8080
	s := testSnapshot(
		tlsPort,
		config.Port{Identity: "direct"},
		snapshot.Host{Certificate: pair, Routes: routes},
	)
	host := s.Config.Hosts[fixtureHost]
	host.Namespace = "app"
	s.Config.Hosts[fixtureHost] = host
	s.Config.Ports[redirectPort] = config.Port{Identity: "direct", Mode: redirectMode}
	var logs bytes.Buffer
	p := New(Options{AccessLog: &logs})
	if err := p.Update(s); err != nil {
		t.Fatal(err)
	}

	for _, name := range sensitiveParameters {
		t.Run(name, func(t *testing.T) {
			mixed := strings.ToUpper(name)
			encoded := fmt.Sprintf("%%%02x%s", mixed[0], mixed[1:])
			query := name + "=disposable-original;" + encoded + "=disposable-encoded&safe=visible"
			referer := "https://user:disposable-userinfo@origin.test/path?" + query + "#disposable-fragment"
			tests := []logCase{
				{name: "full", path: "/ok", route: "app/full", port: tlsPort, status: 200},
				{name: "off", path: "/off", port: tlsPort, status: 200, off: true},
				{
					name:   "error",
					path:   "/error",
					reason: "invalid_policy",
					route:  "error",
					port:   tlsPort,
					status: 503,
				},
				{name: "off error", path: "/off-error", port: tlsPort, status: 503, off: true},
				{
					name:   "parse failure",
					path:   "/%252F",
					reason: "ambiguous_path",
					port:   tlsPort,
					status: 400,
				},
				{
					name:   "redirect",
					path:   "/ok",
					mode:   redirectMode,
					port:   redirectPort,
					status: 301,
				},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					wantQuery := name + "=[redacted]&" + encoded + "=[redacted]&safe=visible"
					logs.Reset()
					checkAccessLog(t, p, &logs, tc, query, referer, wantQuery)
				})
			}
		})
	}

	var metrics bytes.Buffer
	p.WriteMetrics(&metrics)
	if !strings.Contains(
		metrics.String(),
		`gatehouse_requests_total{route="app/off",listener="8443"`,
	) {
		t.Fatal("accessLog off also suppressed request metrics")
	}
}

func checkAccessLog(
	t *testing.T,
	p *Plane,
	logs *bytes.Buffer,
	tc logCase,
	query, referer, wantQuery string,
) {
	t.Helper()
	r := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		tc.path+"?"+query,
		strings.NewReader("hello"),
	)
	r.Host = fixtureHost
	r.Header.Set("Referer", referer)
	w := httptest.NewRecorder()
	p.serveRequest(tc.port, tc.mode, w, r)
	if w.Code != tc.status {
		t.Fatalf("status = %d, want %d", w.Code, tc.status)
	}
	if tc.mode == redirectMode && !strings.HasSuffix(w.Header().Get("Location"), "?"+query) {
		t.Fatal("redirect changed the request query")
	}
	if tc.off {
		if logs.Len() != 0 {
			t.Fatal("off route emitted an access record")
		}
		return
	}
	checkRedactedEntry(t, logs, tc, wantQuery)
}

func checkRedactedEntry(t *testing.T, logs *bytes.Buffer, tc logCase, wantQuery string) {
	t.Helper()
	entry := readAccess(t, logs.Bytes())
	if entry.Status != tc.status || entry.Deny != tc.reason || entry.Route != tc.route {
		t.Fatalf("unexpected access fields: %+v", entry)
	}
	if entry.Query != wantQuery || entry.Referer != "https://origin.test/path?"+wantQuery {
		t.Fatalf("query or referer redaction failed: %+v", entry)
	}
	if strings.Contains(logs.String(), "disposable-") {
		t.Fatal("access log retained a credential")
	}
	if tc.status == http.StatusOK {
		if entry.BytesIn != 5 || entry.BytesOut != 5 || entry.Upstream <= 0 ||
			entry.RequestID == "" {
			t.Fatalf("unexpected successful request measurements: %+v", entry)
		}
	}
}

func TestMalformedLogInputs(t *testing.T) {
	for _, query := range []string{"safe=visible&bad%zz=value", "bad%=value&code=disposable"} {
		if got := redactedQuery(query); got != "[redacted]" {
			t.Errorf("malformed query escaped redaction: %q", got)
		}
	}
	for _, referer := range []string{"https:opaque?code=disposable", "https://example.test/%zz?code=disposable"} {
		if got := redactedReferer(referer); got != "[redacted]" {
			t.Errorf("malformed or opaque referer escaped redaction: %q", got)
		}
	}
}

func TestWireParseFailureLog(t *testing.T) {
	for _, mode := range []string{redirectMode, "tls"} {
		t.Run(mode, func(t *testing.T) {
			listener, port := newListener(t)
			pair, roots := makeCertificate(t)
			var logs synchronizedLog
			p := New(Options{AccessLog: &logs})
			listen := config.Port{Identity: "direct"}
			if mode == redirectMode {
				listen.Mode = mode
			}
			s := testSnapshot(port, listen, snapshot.Host{Certificate: pair})
			if err := p.Update(s); err != nil {
				t.Fatal(err)
			}
			startListener(t, listener, p, port, listen.Mode)
			raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(
				t.Context(),
				"tcp",
				listener.Addr().String(),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			conn := raw
			if mode != redirectMode {
				conn = tls.Client(raw, &tls.Config{
					MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: fixtureHost,
					NextProtos: []string{"http/1.1"},
				})
			}

			checkWireParseLog(t, conn, &logs)
		})
	}
}

func checkWireParseLog(t *testing.T, conn net.Conn, logs *synchronizedLog) {
	t.Helper()
	reader := bufio.NewReader(conn)
	// A valid request first checks that keep-alive responses and the following
	// invalid request are accounted for separately.
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", fixtureHost); err != nil {
		t.Fatal(err)
	}
	readWireResponse(t, reader)
	fields := make([]string, 0, len(sensitiveParameters))
	for _, name := range sensitiveParameters {
		fields = append(fields, url.QueryEscape(name)+"=disposable-wire")
	}
	query := strings.Join(fields, "&")
	if _, err := fmt.Fprintf(
		conn,
		"GET /%%zz?%s HTTP/1.1\r\nHost: %s\r\nReferer: https://example.test/?%s\r\n\r\n",
		query,
		fixtureHost,
		query,
	); err != nil {
		t.Fatal(err)
	}
	if code := readWireResponse(t, reader); code != http.StatusBadRequest {
		t.Fatalf("wire parse status = %d", code)
	}
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 2 || strings.Contains(logs.String(), "disposable-wire") {
		t.Fatal("unexpected wire parse access log")
	}
	entry := readAccess(t, []byte(lines[1]))
	if entry.Status != http.StatusBadRequest || entry.Deny != "http_parse_error" ||
		entry.Query != "" || entry.Referer != "" {
		t.Fatalf("unexpected wire parse access entry: %+v", entry)
	}
}

func readWireResponse(t *testing.T, r *bufio.Reader) int {
	t.Helper()
	resp, err := http.ReadResponse(r, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}

func readAccess(t *testing.T, line []byte) accessEntry {
	t.Helper()
	var entry accessEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

type synchronizedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *synchronizedLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestObservabilityMetrics(t *testing.T) {
	l, port := newListener(t)
	pair, _ := makeCertificate(t)
	p := New(Options{
		CrowdSecMetrics: func() observability.CrowdSecMetrics {
			return observability.CrowdSecMetrics{Decisions: 23, Staleness: 1500 * time.Millisecond}
		},
		LimiterMetrics: func() observability.LimiterMetrics {
			return observability.LimiterMetrics{
				GossipPeers: 1, PeerStaleness: map[string]time.Duration{"peer-1": 2 * time.Second},
				Isolated: true, CapacityOverflow: 9, ResyncPending: true,
				RoutePressure: map[string]float64{"app/route": 0.75},
			}
		},
	})
	s := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{Certificate: pair})
	s.Digest = "test-digest"
	s.Config.DeviceTrust.Exceptions = []config.DeviceException{{Service: "app/device", Port: 443}}
	if err := p.Update(s); err != nil {
		t.Fatal(err)
	}
	p.metrics.request(requestRecord{
		listener: port,
		route:    "app/route",
		backend:  "app/service:8080",
		upstream: 7 * time.Millisecond,
	}, 200, http.MethodPost, 11*time.Millisecond, 12, 34)
	p.metrics.request(
		requestRecord{listener: port, deny: "synthetic_deny"},
		403,
		http.MethodGet,
		time.Millisecond,
		0,
		0,
	)
	p.metrics.handshake("unrecognized_name")
	startListener(t, l, p, port, "")
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(
		t.Context(),
		"tcp",
		l.Addr().String(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	awaitOpenConnections(t, p, 1)
	w := httptest.NewRecorder()
	p.Metrics().
		ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body := w.Body.String()
	listener := strconv.Itoa(int(port))
	labels := `{route="app/route",listener="` + listener + `",backend="app/service:8080",code="200",method="POST"}`
	want := []string{
		"gatehouse_requests_total" + labels + " 1\n",
		"gatehouse_request_duration_seconds_sum" + labels + " 0.011\n",
		"gatehouse_upstream_duration_seconds_sum" + labels + " 0.007\n",
		"gatehouse_request_bytes_total" + labels + " 12\n",
		"gatehouse_response_bytes_total" + labels + " 34\n",
		`gatehouse_certificate_expiry_timestamp_seconds{listener="` + listener + `",host="edge.test"} `,
		`gatehouse_tls_handshakes_total{result="unrecognized_name"} 1`,
		`gatehouse_denies_total{reason="synthetic_deny"} 1`,
		"gatehouse_crowdsec_decisions 23",
		"gatehouse_crowdsec_staleness_seconds 1.5",
		"gatehouse_gossip_peers 1",
		`gatehouse_gossip_peer_staleness_seconds{peer="peer-1"} 2`,
		"gatehouse_limiter_isolated 1",
		"gatehouse_limiter_capacity_overflow_total 9",
		"gatehouse_limiter_resync_pending 1",
		`gatehouse_limiter_pressure{route="app/route"} 0.75`,
		`gatehouse_snapshot_digest_info{digest="test-digest"} 1`,
		"gatehouse_device_tls_exceptions 1",
		`gatehouse_open_connections{listener="` + listener + `"} 1`,
	}
	for _, sample := range want {
		if !strings.Contains(body, sample) {
			t.Errorf("scrape missing %q", sample)
		}
	}
	if strings.Contains(body, `gatehouse_upstream_duration_seconds_count{route="",`) {
		t.Error("upstream histogram includes a request that never reached a backend")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	awaitOpenConnections(t, p, 0)
}

func awaitOpenConnections(t *testing.T, p *Plane, want int64) {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for p.State().Listeners[0].OpenConnections != want {
		select {
		case <-tick.C:
		case <-timeout.C:
			t.Fatalf("open connections = %d, want %d", p.State().Listeners[0].OpenConnections, want)
		}
	}
}
