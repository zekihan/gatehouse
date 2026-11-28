package dataplane

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

const secondIdentity = "urn:noqer:mtls:clients:second"

func protectedSnapshot(port uint16, server *snapshot.KeyPair, ca []byte,
	backend string, anchors ...string,
) *snapshot.Snapshot {
	s := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{
		Certificate: server,
		ClientCA:    ca,
		Routes: []snapshot.Route{{
			Name: "protected", Path: "/", Namespace: "ns",
			Backend: &snapshot.Backend{Port: 80, Endpoints: []string{backend}},
			MTLS: &snapshot.MTLSPolicy{
				Identities:     []string{testIdentity, secondIdentity},
				TrustedAnchors: anchors,
				ForwardHeaders: []string{
					"X-Mtls-Mesh-Viewer",
					"X-Mtls-Mesh-Fingerprint",
					"X-Mtls-Mesh-Not-After",
				},
			},
		}},
	})
	s.Config.ClientCertProfiles = map[string]config.ClientCertProfile{
		"clients": {MinVersion: "1.2"},
	}
	s.Config.Hosts[fixtureHost] = config.Host{
		Namespace: "ns", Ports: []uint16{port}, Protection: "mtls:clients",
		Identities: []string{testIdentity, secondIdentity},
	}
	return s
}

// Port the certificate identity and constraint cases from traefik-mtls-authz
// v0.2.1 to Gatehouse's raw-path contract.
func TestMTLSPluginPolicyFixtures(t *testing.T) {
	pair, roots := makeCertificate(t)
	_, anchor := clientCertificate(t, pair)
	back := httptest.NewServer(mtlsFixtureBackend(t))
	t.Cleanup(back.Close)
	l, port := newListener(t)
	input := protectedSnapshot(
		port,
		pair,
		pair.CertPEM,
		strings.TrimPrefix(back.URL, "http://"),
		anchor,
	)
	registry := input.Config.Hosts[fixtureHost]
	registry.Identities = []string{testIdentity}
	registry.IdentityConstraints = map[string]config.IdentityConstraint{
		testIdentity: {Methods: []string{http.MethodGet}, Paths: []string{"/manifest.json"}},
	}
	input.Config.Hosts[fixtureHost] = registry
	input.DataPlane.Ports[port][fixtureHost].Routes[0].MTLS.Constraints = map[string]config.IdentityConstraint{
		testIdentity: {
			Methods: []string{http.MethodGet, http.MethodPost},
			Paths:   []string{"/manifest.json", "/"},
		},
	}
	p := New(Options{})
	if err := p.Update(input); err != nil {
		t.Fatal(err)
	}
	startListener(t, l, p, port, "")
	for _, tc := range []struct {
		name, identity, method, path string
		modify                       func(*x509.Certificate)
		code                         int
		reason                       string
	}{
		{name: "manifest", code: 204},
		{name: "outside ceiling", identity: secondIdentity, code: 403, reason: "not_enrolled"},
		{name: "wider policy path", path: "/", code: 403, reason: "constraint_path"},
		{name: "wider policy method", method: http.MethodPost, code: 403, reason: "constraint_method"},
		{name: "escaped path", path: "/m%61nifest.json", code: 403, reason: "constraint_path"},
		{name: "dot segment", path: "/x/../manifest.json", code: 403, reason: "constraint_path"},
		{name: "encoded separator", path: "/x%2fmanifest.json", code: 400},
		{name: "uppercase identity", identity: "urn:noqer:mtls:clients:Fixture", code: 403, reason: "identity_invalid"},
		{name: "no identity", modify: func(c *x509.Certificate) { c.URIs = nil }, code: 403, reason: "identity_missing"},
		{name: "two URIs", modify: func(c *x509.Certificate) {
			c.URIs = append(c.URIs, &url.URL{Scheme: "urn", Opaque: "noqer:mtls:clients:second"})
		}, code: 403, reason: "identity_ambiguous"},
		{name: "extra SAN", modify: func(c *x509.Certificate) {
			c.DNSNames = []string{"synthetic.test"}
		}, code: 403, reason: "identity_ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := tc.identity
			if identity == "" {
				identity = testIdentity
			}
			leaf, _ := issueClientCertificate(t, pair, identity, tc.modify)
			client := authorizationClient(t, l, roots, leaf, false)
			method, path := tc.method, tc.path
			if path == "" {
				path = "/manifest.json"
			}
			req, err := http.NewRequestWithContext(
				t.Context(),
				method,
				"https://"+fixtureHost+path,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = http.Header{
				"Connection": {
					"X-Mtls-Mesh-Viewer, X-Mtls-Mesh-Fingerprint, X-Real-Ip",
				},
				"X-Mtls-Mesh-Viewer":          {"untrusted", "duplicate"},
				"X_Mtls_Mesh_Viewer":          {"alias"},
				"X-Forwarded-Tls-Client-Cert": {"untrusted"},
				"X-Real-Ip":                   {"192.0.2.99"},
				"X-Is-Trusted":                {"true"},
			}
			status, _, headers := doRequest(t, client, req)
			if status != tc.code || headers.Get("X-Mtls-Authz-Reason") != tc.reason {
				t.Fatalf(
					"got %d %q, want %d %q",
					status,
					headers.Get("X-Mtls-Authz-Reason"),
					tc.code,
					tc.reason,
				)
			}
		})
	}
}

func TestForwardAuthRegistryGrants(t *testing.T) {
	auth := httptest.NewServer(forwardAuthFixture(t))
	defer auth.Close()
	back := httptest.NewServer(forwardAuthFixtureBackend(t))
	defer back.Close()
	l, port := newListener(t)
	_, cloudflarePort := newListener(t)
	pair, roots := makeCertificate(t)
	backend := &snapshot.Backend{
		Port:      80,
		Endpoints: []string{strings.TrimPrefix(back.URL, "http://")},
	}
	input := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{
		Certificate: pair,
		Routes: []snapshot.Route{
			{Name: "default", Path: "/", Namespace: "ns", Backend: backend},
			{
				Name: "health", Path: "/health", Exact: true, Method: "GET", Namespace: "ns",
				ForwardAuth: "exception", Backend: backend,
			},
			{
				Name: "probe", Path: "/probe", Exact: true, Method: "GET", Namespace: "probe",
				ForwardAuth: "machine", Backend: backend,
				Rewrite: &snapshot.Rewrite{Path: "/unregistered", Host: "other.test"},
				RequestHeaders: snapshot.HeaderFilter{
					Set: map[string]string{
						"Authorization":   "filter",
						"Cookie":          "filter",
						"X-Consent-Token": "filter",
					},
				},
			},
			{
				Name:        "prefix",
				Path:        "/prefix",
				Method:      "GET",
				Namespace:   "probe",
				ForwardAuth: "machine",
				Backend:     backend,
			},
		},
	})
	input.Config.Ports[cloudflarePort] = config.Port{
		Identity:     "cloudflare",
		TrustedCIDRs: []string{"127.0.0.0/8"},
		EdgeSecret: &config.EdgeSecret{
			Header: "X-Edge-Test",
			Secret: "edge",
			Keys:   []string{"current"},
		},
	}
	input.Config.ForwardAuthClasses = map[string]config.ForwardAuthClass{
		"exception": {
			Address:        auth.URL + "/exception",
			RequestHeaders: []string{"Authorization", "X-Edge-Test"},
			StripAfter: []string{
				"Authorization",
				"Cookie",
				"X-Consent-Token",
			},
			MaxResponseBytes: 32,
		},
		"machine": {
			Address:        auth.URL + "/machine",
			RequestHeaders: []string{"Authorization", "X-Untrusted"},
			StripAfter: []string{
				"Authorization",
				"Cookie",
				"X-Consent-Token",
			},
			MaxResponseBytes: 32,
		},
	}
	registry := input.Config.Hosts[fixtureHost]
	registry.Protection = "oidc:user"
	registry.Exceptions = []config.Exception{
		{Path: "/health", Methods: []string{"GET"}, ForwardAuth: "exception"},
	}
	registry.Delegate = []config.Delegation{
		{
			Namespace:   "probe",
			Paths:       []string{"/probe"},
			Methods:     []string{"GET"},
			ForwardAuth: "machine",
			Rewrite:     "/upstream",
		},
		{
			Namespace:   "probe",
			Paths:       []string{"/prefix"},
			Methods:     []string{"GET"},
			ForwardAuth: "machine",
		},
	}
	input.Config.Hosts[fixtureHost] = registry
	p := New(Options{OIDC: func(w http.ResponseWriter, _ *http.Request, _ RequestInfo) bool {
		w.WriteHeader(http.StatusTeapot)
		return false
	}})
	if err := p.Update(input); err != nil {
		t.Fatal(err)
	}
	startListener(t, l, p, port, "")
	client := testClient(t, l, roots)
	for _, tc := range []struct {
		name, method, path, credential, connection string
		code                                       int
		body                                       string
	}{
		{name: "delegation", path: "/probe", credential: "Bearer fixture", code: 200, body: "/upstream"},
		{name: "exception", path: "/health?from=fixture", credential: "Bearer fixture", code: 200, body: "/health?from=fixture"},
		{name: "mandatory auth", path: "/probe", code: 401},
		{name: "nominated credential", path: "/probe", credential: "Bearer fixture", connection: ", Authorization", code: 401},
		{name: "oversized auth", path: "/probe", credential: "Bearer oversized", code: 503},
		{name: "wrong method", path: "/probe", method: http.MethodPost, credential: "Bearer fixture", code: 403},
		{name: "prefix grant requires exact match", path: "/prefix", credential: "Bearer fixture", code: 403},
		{name: "encoded grant", path: "/%70robe", credential: "Bearer fixture", code: 403},
		{name: "ordinary OIDC", path: "/", code: 418},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				t.Context(),
				tc.method,
				"https://"+fixtureHost+tc.path,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Connection", "X_Untrusted, X-Forwarded-For"+tc.connection)
			req.Header.Set("X_Untrusted", "nominated")
			req.Header.Set("Authorization", tc.credential)
			req.Header.Set("Cookie", "fixture=client")
			req.Header.Set("X_Consent_Token", "fixture")
			req.Header.Set("X-Forwarded-For", "192.0.2.99")
			req.Header.Set("X-Edge-Test", "synthetic-edge-secret")
			req.Header.Set("X_Edge_Test", "synthetic-edge-alias")
			req.Header.Set("X-Noqer-Edge-Auth", "synthetic-default-secret")
			status, body, headers := doRequest(t, client, req)
			if status != tc.code || (tc.body != "" && body != tc.body) {
				t.Fatalf(
					"status %d body %q, want status %d and body %q",
					status,
					body,
					tc.code,
					tc.body,
				)
			}
			if tc.code == 401 && headers.Get("WWW-Authenticate") != "Bearer" {
				t.Error("auth challenge was lost")
			}
		})
	}
}

func mtlsFixtureBackend(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if values := r.Header.Values(
			"X-Mtls-Mesh-Viewer",
		); len(values) != 1 ||
			values[0] != testIdentity {
			t.Errorf("expected the verified identity once, got %q", values)
		}
		if r.Header.Get("X-Mtls-Mesh-Fingerprint") == "" ||
			r.Header.Get("X-Mtls-Mesh-Not-After") == "" ||
			r.Header.Get("X_Mtls_Mesh_Viewer") != "" ||
			r.Header.Get(identityHeader) != "" ||
			r.Header.Get("X-Forwarded-Tls-Client-Cert") != "" ||
			r.Header.Get("X-Real-Ip") != "127.0.0.1" ||
			r.Header.Get("X-Is-Trusted") != "" {
			t.Error("unexpected forwarding headers")
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func forwardAuthFixture(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("X-Forwarded-Method") != http.MethodGet ||
			r.Header.Get(
				"X-Forwarded-Host",
			) != fixtureHost || r.Header.Get("X-Forwarded-Proto") != "https" ||
			r.Header.Get(
				"X-Forwarded-For",
			) != "127.0.0.1" || r.Header.Get("X-Real-Ip") != "127.0.0.1" ||
			r.Header.Get("X-Noqer-Edge-Auth") != "" || r.Header.Get("X-Edge-Test") != "" ||
			r.Header.Get("X_Untrusted") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected auth subrequest")
		}
		switch r.Header.Get("Authorization") {
		case "Bearer fixture":
			if want := map[string]string{"/exception": "/health?from=fixture", "/machine": "/probe"}[r.URL.Path]; r.Header.Get(
				"X-Forwarded-Uri",
			) != want {
				t.Error("auth did not receive the original request target")
			}
			w.WriteHeader(http.StatusNoContent)
		case "Bearer oversized":
			_, _ = io.WriteString(w, strings.Repeat("a", 33))
		default:
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
}

func forwardAuthFixtureBackend(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{
			"Authorization", "Cookie", "X-Noqer-Edge-Auth", "X_Edge_Test",
			"X-Edge-Test", "X_Consent_Token", "X-Consent-Token", "X-Untrusted", "X_Untrusted",
		} {
			if r.Header.Get(name) != "" {
				t.Errorf("unexpected upstream header %s", name)
			}
		}
		if r.Host != fixtureHost {
			t.Error("delegation changed authority")
		}
		//nolint:gosec // echo a disposable request target into the fixture.
		_, _ = io.WriteString(w, r.RequestURI)
	})
}
