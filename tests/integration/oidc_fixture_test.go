//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/dataplane"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

const (
	autheliaImage = "ghcr.io/authelia/authelia:4.39.28@" +
		"sha256:bd97cff4fcbf715b5ff1f9ae286afbe6033afce385302520b0368122d43a6f54"
	issuerHost    = "auth.gatehouse.test"
	protectedHost = "app.gatehouse.test"
	callbackHost  = "callback.gatehouse.test"
	callbackPath  = "/oauth2/callback"
	appURL        = "https://" + protectedHost
	issuerURL     = "https://" + issuerHost
	callbackURL   = "https://" + callbackHost + callbackPath
	softExpiry    = 3 * time.Second
	hardExpiry    = 8 * time.Second
	testUser      = "gatehouse"
	testClient    = "gatehouse-test"
)

type oidcFixture struct {
	cert        *snapshot.KeyPair
	roots       *x509.CertPool
	issuer      string
	dockerID    string
	dir         string
	spec        string
	password    string
	secret      string
	jwks        atomic.Int32
	discover    atomic.Int32
	tokenStatus atomic.Int64
	tokenError  atomic.Pointer[string]
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	cert, roots := testCertificate(t)
	f := &oidcFixture{
		cert:     cert,
		roots:    roots,
		dir:      t.TempDir(),
		password: rand.Text(),
		secret:   rand.Text(),
	}
	clientHash := autheliaHash(t, f.secret)
	userHash := autheliaHash(t, f.password)
	f.spec = fmt.Sprintf(autheliaConfig, rand.Text(), rand.Text(), rand.Text(), clientHash)
	writeFixture(t, f.dir, "users.yml", fmt.Sprintf(autheliaUsers, userHash))
	f.writeConfig(t, "initial")
	user := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	port := net.JoinHostPort("127.0.0.1", loopbackPort(t))
	id := docker(t, "run", "--detach", "--publish", port+":9091",
		"--user", user, "--entrypoint", "/app/authelia",
		"--volume", f.dir+":/config", autheliaImage, "--config", "/config/configuration.yml")
	f.dockerID = id
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "docker", "rm", "--force", id).Run(); err != nil {
			t.Errorf("remove disposable Authelia: %v", err)
		}
	})
	target, err := url.Parse("http://" + port)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{
		ModifyResponse: f.recordTokenResponse,
		ErrorLog:       log.New(io.Discard, "", 0),
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
			r.SetXForwarded()
		},
	}
	issuer := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/jwks.json":
				f.jwks.Add(1)
			case "/.well-known/openid-configuration":
				f.discover.Add(1)
			}
			proxy.ServeHTTP(w, r)
		}),
	)
	pair, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	issuer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	issuer.StartTLS()
	t.Cleanup(issuer.Close)
	t.Cleanup(func() {
		if t.Failed() {
			code := f.tokenError.Load()
			if code == nil {
				unknown := ""
				code = &unknown
			}
			t.Logf("Authelia exchange HTTP status=%d error=%q discovery=%d JWKS=%d",
				f.tokenStatus.Load(), *code, f.discover.Load(), f.jwks.Load())
		}
	})
	f.issuer = issuer.Listener.Addr().String()
	f.waitForIssuer(t, "initial")
	return f
}

func (f *oidcFixture) recordTokenResponse(resp *http.Response) error {
	if resp.Request.URL.Path != "/api/oidc/token" {
		return nil
	}
	f.tokenStatus.Store(int64(resp.StatusCode))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var failure struct {
		Code string `json:"error"`
	}
	if err := json.Unmarshal(body, &failure); err == nil {
		code := safeOAuthError(failure.Code)
		f.tokenError.Store(&code)
	}
	return nil
}

func safeOAuthError(code string) string {
	switch code {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
		"access_denied", "server_error", "temporarily_unavailable", "consent_required",
		"interaction_required", "login_required", "invalid_scope":
		return code
	case "":
		return "(none)"
	default:
		return "(unknown)"
	}
}

func (f *oidcFixture) rotateSigningKey(t *testing.T) {
	t.Helper()
	f.writeConfig(t, "rotated")
	docker(t, "restart", "--time", "0", f.dockerID)
	f.waitForIssuer(t, "rotated")
}

func (f *oidcFixture) waitForIssuer(t *testing.T, key string) {
	t.Helper()
	client := &http.Client{Transport: f.transport(t, ""), Timeout: time.Second}
	f.wait(t, func() bool {
		req, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			issuerURL+"/jwks.json",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return false
		}
		var jwks struct {
			Keys []struct {
				ID string `json:"kid"`
			} `json:"keys"`
		}
		readJSON(t, captureResponse(t, resp), &jwks)
		return resp.StatusCode == http.StatusOK && len(jwks.Keys) == 1 && jwks.Keys[0].ID == key
	})
	f.jwks.Store(0)
	f.discover.Store(0)
}

func (f *oidcFixture) wait(t *testing.T, check func() bool) {
	t.Helper()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for {
		if check() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf(
				"Authelia did not become ready: %s",
				docker(t, "logs", "--tail", "15", f.dockerID),
			)
		case <-tick.C:
		}
	}
}

func (f *oidcFixture) writeConfig(t *testing.T, id string) {
	t.Helper()
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signingKey),
	})
	key := strings.Join(strings.Split(strings.TrimSpace(string(encoded)), "\n"), "\n          ")
	writeFixture(t, f.dir, "configuration.yml", fmt.Sprintf(f.spec, id, key))
}

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v", args[0], err)
	}
	return strings.TrimSpace(string(output))
}

func autheliaHash(t *testing.T, password string) string {
	t.Helper()
	out := docker(t, "run", "--rm", autheliaImage, "authelia", "crypto", "hash", "generate",
		"pbkdf2", "--password", password, "--no-confirm")
	for line := range strings.SplitSeq(out, "\n") {
		if hash, found := strings.CutPrefix(line, "Digest: "); found {
			return hash
		}
	}
	t.Fatal("Authelia did not return a password digest")
	return ""
}

func testCertificate(t *testing.T) (*snapshot.KeyPair, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Gatehouse OIDC integration"},
		DNSNames:     []string{protectedHost, callbackHost, issuerHost},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pair.CertPEM) {
		t.Fatal("load disposable trust")
	}
	return pair, roots
}

func (f *oidcFixture) transport(t *testing.T, edge string) *http.Transport {
	t.Helper()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			name, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			dialer := net.Dialer{Timeout: time.Second}
			switch name {
			case issuerHost:
				return dialer.DialContext(ctx, network, f.issuer)
			case protectedHost, callbackHost:
				return dialer.DialContext(ctx, network, edge)
			default:
				return nil, fmt.Errorf("unexpected fixture host %q", name)
			}
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

func (f *oidcFixture) newReplica(
	t *testing.T,
	app, key, previous string,
) (*dataplane.Plane, *snapshot.Snapshot, *http.Transport) {
	t.Helper()
	port := loopbackPort(t)
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	snap := f.edgeSnapshot(uint16(portNumber), app, key, previous)
	addr := net.JoinHostPort("127.0.0.1", port)
	transport := f.transport(t, addr)
	ready := make(chan struct{})
	plane := dataplane.New(dataplane.Options{
		OIDCTransport: transport, OnListening: func() { close(ready) },
	})
	if err := plane.Update(snap); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- plane.Serve(ctx, "127.0.0.1") }()
	select {
	case <-ready:
		t.Cleanup(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("serve test replica: %v", err)
			}
		})
	case err := <-done:
		cancel()
		t.Fatalf("start replica: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("test replica did not start")
	}
	return plane, snap, transport
}

func (f *oidcFixture) edgeSnapshot(port uint16, app, key, previous string) *snapshot.Snapshot {
	return &snapshot.Snapshot{
		Config: &config.Config{
			Ports: map[uint16]config.Port{port: {Identity: "direct"}},
			Hosts: map[string]config.Host{
				protectedHost: {Namespace: "app", Protection: "oidc:user", Ports: []uint16{port}},
				callbackHost: {
					Namespace:  "gatehouse",
					Protection: "oidcCallback:user",
					Ports:      []uint16{port},
				},
			},
			AuthClasses: map[string]config.AuthClass{"user": {
				Issuer:        issuerURL,
				ClientID:      testClient,
				Callback:      callbackURL,
				CookieDomain:  ".gatehouse.test",
				RedirectHosts: []string{protectedHost},
				Scopes: []string{
					"openid",
					"profile",
					"email",
					"groups",
				},
				Groups:     []string{"test-users"},
				SoftExpiry: softExpiry.String(),
				HardExpiry: hardExpiry.String(),
			}},
		},
		DataPlane: &snapshot.DataPlane{
			Hosts: map[string]snapshot.Host{
				protectedHost: {Certificate: f.cert, Routes: []snapshot.Route{
					{
						Name:      "app",
						Namespace: "app",
						Path:      "/",
						Backend: &snapshot.Backend{
							Service:   "app/test",
							Port:      80,
							Endpoints: []string{app},
						},
					},
				}},
				callbackHost: {Certificate: f.cert},
			},
			OIDCSecrets: map[string]string{
				"oidc-user-client-secret": f.secret,
				"cookie-user-current":     key,
				"cookie-user-previous":    previous,
			},
		},
	}
}

func testCookieKey() string {
	key := make([]byte, 32)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

const autheliaConfig = `
server:
  address: tcp://0.0.0.0:9091
log:
  level: info
authentication_backend:
  password_reset:
    disable: true
  file:
    path: /config/users.yml
access_control:
  default_policy: one_factor
session:
  secret: %s
  cookies:
    - domain: gatehouse.test
      authelia_url: https://auth.gatehouse.test
storage:
  encryption_key: %s
  local:
    path: /config/db.sqlite3
notifier:
  filesystem:
    filename: /config/notification.txt
identity_providers:
  oidc:
    hmac_secret: %s
    enforce_pkce: always
    claims_policies:
      gateway:
        id_token: [preferred_username, email, email_verified, groups]
    clients:
      - client_id: gatehouse-test
        client_secret: '%s'
        authorization_policy: one_factor
        claims_policy: gateway
        consent_mode: pre-configured
        pre_configured_consent_duration: 1y
        require_pkce: true
        pkce_challenge_method: S256
        redirect_uris: [https://callback.gatehouse.test/oauth2/callback]
        scopes: [openid, profile, email, groups]
        grant_types: [authorization_code]
        response_types: [code]
        token_endpoint_auth_method: client_secret_basic
    jwks:
      - key_id: %%s
        algorithm: RS256
        use: sig
        key: |
          %%s
`

const autheliaUsers = `
users:
  gatehouse:
    displayname: Gatehouse Tester
    password: '%s'
    email: tester@gatehouse.test
    groups: [test-users]
`
