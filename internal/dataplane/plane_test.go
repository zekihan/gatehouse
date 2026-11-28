package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

const fixtureHost = "edge.test"

func newListener(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	var cfg net.ListenConfig
	l, err := cfg.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, addrPort(l.Addr()).Port()
}

func startListener(t *testing.T, l net.Listener, plane *Plane, port uint16, mode string) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- plane.serve(ctx, port, mode, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

func makeCertificate(t *testing.T) (*snapshot.KeyPair, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{fixtureHost, "other.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair := &snapshot.KeyPair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}),
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pair.CertPEM) {
		t.Fatal("append test CA")
	}
	return pair, pool
}

func testSnapshot(port uint16, options config.Port, host snapshot.Host) *snapshot.Snapshot {
	return &snapshot.Snapshot{
		Config: &config.Config{
			Ports: map[uint16]config.Port{port: options},
			Hosts: map[string]config.Host{
				fixtureHost: {Namespace: "ns", Ports: []uint16{port}, Protection: "public"},
			},
		},
		DataPlane: &snapshot.DataPlane{Ports: map[uint16]map[string]snapshot.Host{
			port: {fixtureHost: host},
		}},
	}
}

func TestRedirectAndProxyProtocol(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proxy bool
		cidrs []string
		code  int
	}{
		{name: "direct", code: 301},
		{name: "trusted v2", proxy: true, cidrs: []string{"127.0.0.0/8"}, code: 301},
		{name: "untrusted v2", proxy: true, cidrs: []string{"10.0.0.0/8"}},
		{name: "missing v2", cidrs: []string{"127.0.0.0/8"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, port := newListener(t)
			identity := "direct"
			if len(tc.cidrs) > 0 {
				identity = "proxyProtocol"
			}
			p := New(Options{})
			s := testSnapshot(
				port,
				config.Port{Mode: redirectMode, Identity: identity, TrustedCIDRs: tc.cidrs},
				snapshot.Host{},
			)
			if err := p.Update(s); err != nil {
				t.Fatal(err)
			}
			startListener(t, l, p, port, redirectMode)
			conn := dialTest(t, l.Addr().String())
			if tc.proxy {
				err := writeProxyV2(
					conn,
					netip.MustParseAddrPort("[2001:db8::2]:3312"),
					netip.MustParseAddrPort("[2001:db8::1]:80"),
				)
				if err != nil && tc.code != 0 {
					t.Fatal(err)
				}
			}
			_, err := io.WriteString(conn, "GET /a%2Bb?x=1 HTTP/1.1\r\nHost: [::1]:80\r\n\r\n")
			if err != nil && tc.code != 0 {
				t.Fatal(err)
			}
			assertRedirect(t, conn, tc.code)
		})
	}
}

func assertRedirect(t *testing.T, conn net.Conn, status int) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if status == 0 {
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("untrusted connection got a response")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != status ||
		resp.Header.Get("Location") != "https://[::1]/a%2Bb?x=1" {
		t.Fatalf(
			"redirect status %d location %q",
			resp.StatusCode,
			resp.Header.Get("Location"),
		)
	}
}

func dialTest(t *testing.T, address string) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestTLSGroupAndUnknownAlert(t *testing.T) {
	l, port := newListener(t)
	cert, roots := makeCertificate(t)
	p := New(Options{})
	if err := p.Update(
		testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{Certificate: cert}),
	); err != nil {
		t.Fatal(err)
	}
	startListener(t, l, p, port, "")
	client := tls.Client(dialTest(t, l.Addr().String()), &tls.Config{
		RootCAs: roots, ServerName: fixtureHost, MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		NextProtos:       []string{"h2", "http/1.1"},
	})
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if state := client.ConnectionState(); state.CurveID != tls.X25519MLKEM768 ||
		state.NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated %s and %q", state.CurveID, state.NegotiatedProtocol)
	}
	for _, sni := range []string{"unused.test", ""} {
		// Capture a real ClientHello, send it in two separate TLS records,
		// and assert the exact fatal alert bytes before any TLS response.
		wire := clientHello(t, sni)
		conn := dialTest(t, l.Addr().String())
		original := wire[5:]
		first := append([]byte{22, 3, 1, 0, 2}, original[:2]...)
		second := append(
			[]byte{22, 3, 1, byte((len(original) - 2) >> 8), byte((len(original) - 2) & 255)},
			original[2:]...)
		if _, err := conn.Write(append(first, second...)); err != nil {
			t.Fatal(err)
		}
		var alert [7]byte
		if _, err := io.ReadFull(conn, alert[:]); err != nil {
			t.Fatal(err)
		}
		if alert != [7]byte{21, 3, 3, 0, 2, 2, 112} {
			t.Fatalf("SNI %q alert %x", sni, alert)
		}
	}
}

func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })
	client := tls.Client(a, &tls.Config{
		ServerName: sni, MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: sni == "", //nolint:gosec // no peer accepts this synthetic ClientHello.
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer a.Close()
		if err := client.HandshakeContext(t.Context()); err == nil {
			t.Error("synthetic client unexpectedly completed a handshake")
		}
	}()
	_, wire, err := peekHello(b)
	_ = b.Close()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestRouteHeadersAndRewrites(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		//nolint:gosec // localhost fixture echoes plain text for the assertions below.
		_, _ = fmt.Fprintf(
			w,
			"%s|%s|%s|%s|%s|%s|%s",
			r.Host,
			r.RequestURI,
			r.Header.Get("X-Real-Ip"),
			r.Header.Get(
				"X-Forwarded-For",
			),
			r.Header.Get("Remote-User"),
			r.Header.Get("X-Mtls-Identity"),
			r.Header.Get("X-Safe"),
		)
	}))
	t.Cleanup(back.Close)
	l, port := newListener(t)
	pair, roots := makeCertificate(t)
	be := &snapshot.Backend{
		Service:   "ns/app",
		Port:      80,
		Endpoints: []string{strings.TrimPrefix(back.URL, "http://")},
	}
	s := testSnapshot(
		port,
		config.Port{Identity: "direct"},
		snapshot.Host{Certificate: pair, Routes: []snapshot.Route{
			{Name: "root", Path: "/", Backend: be},
			{
				Name:    "prefix",
				Path:    "/apps",
				Backend: be,
				Rewrite: &snapshot.Rewrite{Path: "/service", Prefix: true},
			},
			{
				Name:    "exact",
				Path:    "/apps/a",
				Exact:   true,
				Method:  "GET",
				Backend: be,
				Rewrite: &snapshot.Rewrite{Path: "/winner"},
				Headers: []snapshot.Match{{Name: "X-Select", Value: "yes"}},
				Query:   []snapshot.Match{{Name: "needle", Value: "true"}},
				RequestHeaders: snapshot.HeaderFilter{
					Set: map[string]string{"X-Safe": "set", "X_Real_Ip": "wrong"},
				},
			},
			{Name: "invalid", Path: "/invalid", Exact: true},
			{Name: "protected", Path: "/private", Exact: true, Backend: be},
			{
				Name:    "metrics",
				Path:    "/metrics",
				Backend: be,
				Rewrite: &snapshot.Rewrite{Path: "/wrong"},
			},
		}},
	)
	registry := s.Config.Hosts[fixtureHost]
	registry.Deny = &config.Deny{Prefixes: []string{"/private"}}
	s.Config.Hosts[fixtureHost] = registry
	// Registered on a different listener only. A compatible public certificate
	// on this socket is insufficient to route the authority.
	s.Config.Hosts["other.test"] = config.Host{Ports: []uint16{8444}, Protection: "public"}
	var logs bytes.Buffer
	p := New(Options{AccessLog: &logs})
	if err := p.Update(s); err != nil {
		t.Fatal(err)
	}
	startListener(t, l, p, port, "")
	client := testClient(t, l, roots)
	for _, tc := range []struct {
		path      string
		authority string
		code      int
		want      string
	}{
		{path: "/apps/a?needle=true&z=1", code: 200, want: "/winner?needle=true&z=1|127.0.0.1|127.0.0.1|||set"},
		{path: "/apps/a?z=1", code: 200, want: "/service/a?z=1|127.0.0.1|127.0.0.1|||"},
		{path: "/apps2/../%61pp?x=%2b&bad=%zz", code: 200, want: "/apps2/../%61pp?x=%2b&bad=%zz|127.0.0.1|127.0.0.1|||"},
		{path: "/metrics/?raw=%2b", code: 200, want: "/?raw=%2b|127.0.0.1|127.0.0.1|||"},
		{path: "/else/../%70rivate", code: 403},
		{path: "/private%2Fa", code: 400},
		{path: "/%252e", code: 400},
		{path: "/invalid", code: 500},
		{path: "/", authority: "other.test", code: 421},
	} {
		t.Run(tc.path+tc.authority, func(t *testing.T) {
			request, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://"+fixtureHost+tc.path,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			if tc.authority != "" {
				request.Host = tc.authority
			}
			request.Header.Set("X-Select", "yes")
			request.Header.Add("X-Forwarded-For", "spoof")
			request.Header.Add("X-Forwarded-For", "duplicate")
			request.Header.Set("X_Mtls_Identity", "spoof")
			request.Header.Set("Remote_User", "spoof")
			request.Header.Set("Connection", "X-Real-Ip")
			status, body, headers := doRequest(t, client, request)
			if status != tc.code || tc.want != "" && body != fixtureHost+"|"+tc.want {
				t.Fatalf("status %d body %q", status, body)
			}
			if headers.Get("Strict-Transport-Security") == "" {
				t.Fatal("mandatory security headers absent")
			}
		})
	}
}

func testClient(t *testing.T, l net.Listener, roots *x509.CertPool) *http.Client {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableCompression: true,
	}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, l.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func doRequest(t *testing.T, client *http.Client, req *http.Request) (int, string, http.Header) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body), resp.Header
}

func TestBackendSelectionAndTrust(t *testing.T) {
	tlsPolicy := &snapshot.BackendTLS{ServerName: "webhook.test", CAPEM: []byte("broken")}
	pair, _ := makeCertificate(t)
	good := &snapshot.BackendTLS{ServerName: "webhook.test", CAPEM: pair.CertPEM}
	for _, tc := range []struct {
		name      string
		tls       *snapshot.BackendTLS
		exception string
		want      bool
	}{
		{name: "verified", tls: good, want: true},
		{name: "missing"},
		{name: "broken CA", tls: tlsPolicy},
		{name: "exception", exception: "2099-01-01", want: true},
		{name: "expired", exception: "2000-01-01"},
		{name: "conflict", tls: good, exception: "2099-01-01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				LANBackends: []config.LANBackend{{CIDR: "192.0.2.0/24", Ports: []uint16{8080}}},
			}
			if tc.exception != "" {
				cfg.DeviceTrust.Exceptions = []config.DeviceException{
					{Service: "ns/device", Port: 8080, Expires: tc.exception},
				}
			}
			base := snapshot.Backend{
				Service:     "ns/device",
				Port:        8080,
				TLSRequired: true,
				TLS:         tc.tls,
				LAN:         true,
				Endpoints: []string{
					"192.0.2.1:8080",
					"192.0.2.1:8080",
					"192.0.2.2:8080",
				},
				StickyCookie: "sticky",
			}
			b := newBackend(cfg, &base, snapshot.Deadlines{}, false)
			if b.available() != tc.want {
				t.Fatalf("backend available=%t", b.available())
			}
			if !tc.want {
				return
			}
			a, second, third := b.nextEndpoint(), b.nextEndpoint(), b.nextEndpoint()
			if a == second || a != third || len(b.targets) != 2 ||
				!b.transport(false).DisableCompression {
				t.Fatal("expected round robin, deduplication and transparent transport")
			}
			r := &http.Request{Header: make(http.Header), URL: &url.URL{Host: fixtureHost}}
			r.AddCookie(
				&http.Cookie{
					Name:     "sticky",
					Value:    second.id,
					Secure:   true,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				},
			)
			if b.selectEndpoint(r) != second {
				t.Fatal("sticky endpoint did not win")
			}
			base.ClusterIP = "192.0.2.3:8080"
			if c := newBackend(
				cfg,
				&base,
				snapshot.Deadlines{},
				false,
			); c == nil || len(c.targets) != 1 ||
				c.targets[0].addr.String() != base.ClusterIP {
				t.Fatal("ClusterIP was not selected")
			}
			base.ClusterIP = net.JoinHostPort("192.0.2.3", strconv.Itoa(8081))
			if newBackend(cfg, &base, snapshot.Deadlines{}, false) != nil {
				t.Fatal("unapproved LAN port accepted")
			}
		})
	}
}
