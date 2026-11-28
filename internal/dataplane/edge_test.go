package dataplane

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

func TestCloudflareIdentity(t *testing.T) {
	p, err := newPort(config.Port{
		Identity: "cloudflare", TrustedCIDRs: []string{"192.0.2.0/24", "2001:db8:100::/64"},
		EdgeSecret: &config.EdgeSecret{
			Header: "X-Edge-Test", Secret: "edge", Keys: []string{"current", "previous"},
		},
	}, map[string]map[string]string{"edge": {"current": "synthetic-current", "previous": "synthetic-previous"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, peer, ip, secret, connection string
		code                               int
	}{
		{name: "IPv4", ip: "198.51.100.3"},
		{name: "IPv6", peer: "[2001:db8:100::2]:42", ip: "2001:db8::73", secret: "synthetic-previous"},
		{name: "wrong peer", peer: "203.0.113.5:42", ip: "198.51.100.3", code: 403},
		{name: "wrong secret", ip: "198.51.100.3", secret: "incorrect", code: 403},
		{name: "missing IP", code: 403},
		{name: "malformed IP", ip: "not-an-address", code: 400},
		{name: "nominated edge header", ip: "198.51.100.3", connection: "X_Edge_Test", code: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://"+fixtureHost,
				nil,
			)
			r.RemoteAddr = "192.0.2.2:42"
			if tc.peer != "" {
				r.RemoteAddr = tc.peer
			}
			secret := tc.secret
			if secret == "" {
				secret = "synthetic-current"
			}
			r.Header.Set("X-Edge-Test", secret)
			r.Header.Set("Cf-Ray", "kept")
			if tc.ip != "" {
				r.Header.Set("Cf-Connecting-Ip", tc.ip)
			}
			if tc.connection != "" {
				r.Header.Set("Connection", tc.connection)
			}
			assertCloudflareIP(t, p, r, tc.code, tc.ip)
		})
	}
}

func assertCloudflareIP(t *testing.T, p *edgePort, r *http.Request, code int, ip string) {
	t.Helper()
	w := httptest.NewRecorder()
	got := requestIP(w, r, p)
	if code != 0 {
		if w.Code != code || got.IsValid() {
			t.Fatalf("response %d, address %v, wanted status %d", w.Code, got, code)
		}
		return
	}
	state := &compiled{edgeHeaders: map[string]bool{"x-edge-test": true}}
	state.stripHeaders(r.Header)
	if got.String() != ip || r.Header.Get("Cf-Ray") != "kept" || r.Header.Get("X-Edge-Test") != "" {
		t.Fatalf("address %v or incorrect sanitized headers", got)
	}
}

func TestTLSPassthroughAndRevocation(t *testing.T) {
	up, upPort := newListener(t)
	edge, port := newListener(t)
	pair, roots := makeCertificate(t)
	cert, err := tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	peers := make(chan netip.AddrPort, 1)
	go echoTLS(t, up, cert, peers)
	p := New(Options{})
	input := testSnapshot(
		port,
		config.Port{Identity: "proxyProtocol", TrustedCIDRs: []string{"127.0.0.0/8"}},
		snapshot.Host{Passthrough: &snapshot.Backend{
			Service: "ns/tcp", Port: upPort, Endpoints: []string{up.Addr().String()}, ProxyV2: true,
		}},
	)
	if err := p.Update(input); err != nil {
		t.Fatal(err)
	}
	startListener(t, edge, p, port, "")
	raw := dialTest(t, edge.Addr().String())
	ip := netip.MustParseAddrPort("[2001:db8::2]:3000")
	if err := writeProxyV2(raw, ip, addrPort(edge.Addr())); err != nil {
		t.Fatal(err)
	}
	client := tls.Client(
		raw,
		&tls.Config{RootCAs: roots, ServerName: fixtureHost, MinVersion: tls.VersionTLS12},
	)
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if got := <-peers; got != ip {
		t.Fatalf("passthrough source %v, want %v", got, ip)
	}
	if _, err := io.WriteString(client, "echo\n"); err != nil {
		t.Fatal(err)
	}
	if text, err := bufio.NewReader(client).ReadString('\n'); err != nil || text != "echo\n" {
		t.Fatalf("passthrough read %q: %v", text, err)
	}
	revoked := testSnapshot(port, input.Config.Ports[port], snapshot.Host{})
	if err := p.Update(revoked); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("revoked stream did not close: %v", err)
	}
}

func echoTLS(t *testing.T, up net.Listener, cert tls.Certificate, peers chan<- netip.AddrPort) {
	t.Helper()

	raw, err := up.Accept()
	if err != nil {
		return
	}
	defer raw.Close()
	addr, err := readProxyV2(raw)
	if err != nil {
		t.Error(err)
		return
	}
	peers <- addr
	server := tls.Server(
		raw,
		&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	)
	text, err := bufio.NewReader(server).ReadString('\n')
	if err != nil {
		t.Error(err)
		return
	}
	if _, err := io.WriteString(server, text); err != nil {
		t.Error(err)
		return
	}
	_, _ = io.Copy(io.Discard, server)
}

func TestBackendDialRetryAndResponseDeadline(t *testing.T) {
	dead, _ := newListener(t)
	deadAddr := dead.Addr().String()
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "request" {
			http.Error(w, "test payload mismatch", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(back.Close)
	l, port := newListener(t)
	pair, roots := makeCertificate(t)
	be := &snapshot.Backend{
		Port:      80,
		Endpoints: []string{deadAddr, strings.TrimPrefix(back.URL, "http://")},
	}
	p := New(Options{})
	input := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{
		Certificate: pair,
		Routes: []snapshot.Route{
			{
				Name:      "slow",
				Exact:     true,
				Path:      "/slow",
				Backend:   be,
				Deadlines: snapshot.Deadlines{ResponseHeader: 50 * time.Millisecond},
			},
			{Name: "upload", Path: "/", Backend: be},
		},
	})
	if err := p.Update(input); err != nil {
		t.Fatal(err)
	}
	startListener(t, l, p, port, "")
	client := testClient(t, l, roots)
	for path, want := range map[string]int{"/slow": 504, "/upload": 204} {
		req, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"https://"+fixtureHost+path,
			strings.NewReader("request"),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Idempotency-Key", "fixture")
		status, _, _ := doRequest(t, client, req)
		if status != want {
			t.Errorf("%s got %d, want %d", path, status, want)
		}
	}
}

func TestTLSBackendSNI(t *testing.T) {
	pair, roots := makeCertificate(t)
	cert, err := tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	back := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || r.TLS.ServerName != "other.test" || r.Host != fixtureHost {
				t.Error("transport did not preserve authority and use the configured upstream SNI")
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	back.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	back.StartTLS()
	t.Cleanup(back.Close)
	l, port := newListener(t)
	backend := snapshot.Backend{
		Service:     "external-secrets/external-secrets-sops-api",
		Port:        8080,
		Endpoints:   []string{strings.TrimPrefix(back.URL, "https://")},
		TLSRequired: true,
		TLS:         &snapshot.BackendTLS{ServerName: "other.test", CAPEM: pair.CertPEM},
	}
	wrong := backend
	wrong.TLS = &snapshot.BackendTLS{ServerName: "wrong.test", CAPEM: pair.CertPEM}
	p := New(Options{})
	input := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{
		Certificate: pair,
		Routes: []snapshot.Route{
			{Name: "sops", Path: "/", Backend: &backend},
			{Name: "sops-wrong-name", Path: "/wrong-name", Exact: true, Backend: &wrong},
		},
	})
	if err := p.Update(input); err != nil {
		t.Fatal(err)
	}
	startListener(t, l, p, port, "")
	client := testClient(t, l, roots)
	for path, want := range map[string]int{"/": http.StatusNoContent, "/wrong-name": http.StatusBadGateway} {
		req, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"https://"+fixtureHost+path,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		status, _, _ := doRequest(t, client, req)
		if status != want {
			t.Errorf("%s got %d, want %d", path, status, want)
		}
	}
}
