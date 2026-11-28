package dataplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

const testIdentity = "urn:noqer:mtls:clients:fixture"

func TestExistingHTTP2ConnectionReverifiesClientCA(t *testing.T) {
	pair, roots := makeCertificate(t)
	replacement, _ := makeCertificate(t)
	leaf, original := clientCertificate(t, pair)
	_, rotated := clientCertificate(t, replacement)
	listener, port := newListener(t)
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Mtls-Mesh-Viewer") != testIdentity ||
			r.Header.Get(identityHeader) != "" {
			t.Error("expected only the configured alias for the verified identity")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(back.Close)
	p := New(Options{})
	input := func(ca *snapshot.KeyPair, anchor string) *snapshot.Snapshot {
		s := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{
			Certificate: pair, ClientCA: ca.CertPEM,
			Routes: []snapshot.Route{
				{
					Name:      "protected",
					Path:      "/",
					Namespace: "ns",
					Backend: &snapshot.Backend{
						Port:      80,
						Endpoints: []string{strings.TrimPrefix(back.URL, "http://")},
					},
					MTLS: &snapshot.MTLSPolicy{
						Identities: []string{testIdentity},
						TrustedAnchors: []string{
							anchor,
						},
						ForwardHeaders: []string{"X-Mtls-Mesh-Viewer"},
					},
				},
			},
		})
		s.Config.ClientCertProfiles = map[string]config.ClientCertProfile{
			"clients": {MinVersion: "1.2"},
		}
		s.Config.Hosts[fixtureHost] = config.Host{
			Namespace:  "ns",
			Ports:      []uint16{port},
			Protection: "mtls:clients",
			Identities: []string{testIdentity},
			IdentityConstraints: map[string]config.IdentityConstraint{
				testIdentity: {Methods: []string{http.MethodGet}, Paths: []string{"/"}},
			},
		}
		return s
	}
	if err := p.Update(input(pair, original)); err != nil {
		t.Fatal(err)
	}
	startListener(t, listener, p, port, "")
	client := testClient(t, listener, roots)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("missing fixture transport")
	}
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP2(true)
	transport.TLSClientConfig.Certificates = []tls.Certificate{leaf}

	assertMTLSRequest(t, client, "/", http.StatusNoContent, false)
	assertMTLSRequest(t, client, "/%2e", http.StatusForbidden, true)
	if err := p.Update(input(replacement, rotated)); err != nil {
		t.Fatal(err)
	}
	assertMTLSRequest(t, client, "/", http.StatusForbidden, true)
}

func assertMTLSRequest(t *testing.T, client *http.Client, path string, status int, reused bool) {
	t.Helper()
	gotConnection := make(chan bool, 1)
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		gotConnection <- info.Reused
	}}
	ctx := httptrace.WithClientTrace(t.Context(), trace)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+fixtureHost+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Mtls-Mesh-Viewer", "spoof")
	req.Header.Add("X-Mtls-Mesh-Viewer", "duplicate")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != status || resp.ProtoMajor != 2 || <-gotConnection != reused {
		t.Fatalf(
			"got %s %d, wanted h2 %d with reuse=%t",
			resp.Proto,
			resp.StatusCode,
			status,
			reused,
		)
	}
}

func clientCertificate(t *testing.T, pair *snapshot.KeyPair) (tls.Certificate, string) {
	t.Helper()
	return issueClientCertificate(t, pair, testIdentity, nil)
}

func issueClientCertificate(t *testing.T, pair *snapshot.KeyPair, identity string,
	modify func(*x509.Certificate),
) (tls.Certificate, string) {
	t.Helper()
	caBlock, rest := pem.Decode(pair.CertPEM)
	keyBlock, extra := pem.Decode(pair.KeyPEM)
	if caBlock == nil || keyBlock == nil || len(rest)+len(extra) != 0 {
		t.Fatal("invalid fixture CA or private key")
	}
	root, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		URIs:         []*url.URL{uri},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if modify != nil {
		modify(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(root.Raw)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
}
