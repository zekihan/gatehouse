package dataplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

// insideSkew is within the design's ±60s chain-validity window and far enough
// from the inclusive boundary that the assertion does not race the clock.
const insideSkew = 59 * time.Second

type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

type skewCase struct {
	name                  string
	leafNotBefore         time.Duration
	leafNotAfter          time.Duration
	intermediateNotBefore time.Duration
	intermediateNotAfter  time.Duration
}

func (c *issued) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

func (c *issued) fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return hex.EncodeToString(sum[:])
}

func testSerial(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func mintCert(t *testing.T, parent *issued, template *x509.Certificate) *issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := template
	var signer any = key
	if parent != nil {
		issuer = parent.cert
		signer = parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &issued{cert: cert, key: key, der: der}
}

func caTemplate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func leafTemplate(t *testing.T, identity string) *x509.Certificate {
	t.Helper()
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{
		SerialNumber: testSerial(t),
		Subject:      pkix.Name{CommonName: "client"},
		URIs:         []*url.URL{uri},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func insideSkewCases() []skewCase {
	return []skewCase{
		{name: "leaf 59s before NotBefore", leafNotBefore: insideSkew},
		{name: "leaf 59s after NotAfter", leafNotAfter: -insideSkew},
		{name: "intermediate 59s before NotBefore", intermediateNotBefore: insideSkew},
		{name: "intermediate 59s after NotAfter", intermediateNotAfter: -insideSkew},
	}
}

func issueSkewed(t *testing.T, root *issued, tc skewCase) (*issued, *issued) {
	t.Helper()
	now := time.Now()
	intermediateTemplate := caTemplate(t, "intermediate")
	if tc.intermediateNotBefore != 0 {
		intermediateTemplate.NotBefore = now.Add(tc.intermediateNotBefore)
	}
	if tc.intermediateNotAfter != 0 {
		intermediateTemplate.NotBefore = now.Add(-time.Hour)
		intermediateTemplate.NotAfter = now.Add(tc.intermediateNotAfter)
	}
	intermediate := mintCert(t, root, intermediateTemplate)
	leafTpl := leafTemplate(t, testIdentity)
	if tc.leafNotBefore != 0 {
		leafTpl.NotBefore = now.Add(tc.leafNotBefore)
	}
	if tc.leafNotAfter != 0 {
		leafTpl.NotBefore = now.Add(-time.Hour)
		leafTpl.NotAfter = now.Add(tc.leafNotAfter)
	}
	return mintCert(t, intermediate, leafTpl), intermediate
}

type profileHost struct {
	name, profile string
	clientCA      []byte
	anchors       []string
	identities    []string
}

func serveHosts(t *testing.T, hosts ...profileHost) (net.Listener, *x509.CertPool) {
	t.Helper()
	server, roots := makeCertificate(t)
	listener, port := newListener(t)
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(back.Close)
	endpoint := strings.TrimPrefix(back.URL, "http://")
	snap := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{Certificate: server})
	snap.Config.ClientCertProfiles = map[string]config.ClientCertProfile{}
	for _, host := range hosts {
		snap.Config.ClientCertProfiles[host.profile] = config.ClientCertProfile{MinVersion: "1.2"}
		snap.Config.Hosts[host.name] = config.Host{
			Namespace: "ns", Ports: []uint16{port}, Protection: "mtls:" + host.profile,
			Identities: host.identities,
		}
		snap.DataPlane.Ports[port][host.name] = snapshot.Host{
			Certificate: server, ClientCA: host.clientCA,
			Routes: []snapshot.Route{{
				Name: "protected", Path: "/", Namespace: "ns",
				Backend: &snapshot.Backend{Port: 80, Endpoints: []string{endpoint}},
				MTLS: &snapshot.MTLSPolicy{
					Identities: host.identities, TrustedAnchors: host.anchors,
				},
			}},
		}
	}
	plane := New(Options{})
	if err := plane.Update(snap); err != nil {
		t.Fatal(err)
	}
	startListener(t, listener, plane, port, "")
	return listener, roots
}

func serveClientCA(
	t *testing.T, clientCA []byte, anchors, identities []string, profile string,
) (net.Listener, *x509.CertPool) {
	t.Helper()
	return serveHosts(t, profileHost{
		name: fixtureHost, profile: profile, clientCA: clientCA,
		anchors: anchors, identities: identities,
	})
}

func presentChain(
	t *testing.T, listener net.Listener, roots *x509.CertPool,
	leaf *issued, intermediates ...*issued,
) (int, string, error) {
	t.Helper()
	chain := make([][]byte, 1, 1+len(intermediates))
	chain[0] = leaf.der
	for _, cert := range intermediates {
		chain = append(chain, cert.der)
	}
	client := testClient(t, listener, roots)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("missing fixture transport")
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{{
		Certificate: chain, PrivateKey: leaf.key,
	}}
	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "https://"+fixtureHost+"/", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	_, _ = resp.Body.Read(make([]byte, 1))
	return resp.StatusCode, resp.Header.Get("X-Mtls-Authz-Reason"), nil
}

func chainAccepted(status int, err error) bool {
	return err == nil && status >= 200 && status < 300
}

func compiledChainHost(t *testing.T, root *issued) *edgeHost {
	t.Helper()
	server, _ := makeCertificate(t)
	const port = 18080
	snap := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{
		Certificate: server, ClientCA: root.pem(),
		Routes: []snapshot.Route{{
			Name: "protected", Path: "/", Namespace: "ns",
			Backend: &snapshot.Backend{Port: 80, Endpoints: []string{"127.0.0.1:9"}},
			MTLS: &snapshot.MTLSPolicy{
				Identities: []string{testIdentity}, TrustedAnchors: []string{root.fingerprint()},
			},
		}},
	})
	snap.Config.ClientCertProfiles = map[string]config.ClientCertProfile{
		"clients": {MinVersion: "1.2"},
	}
	snap.Config.Hosts[fixtureHost] = config.Host{
		Namespace: "ns", Ports: []uint16{port}, Protection: "mtls:clients",
		Identities: []string{testIdentity},
	}
	plane := New(Options{})
	if err := plane.Update(snap); err != nil {
		t.Fatal(err)
	}
	host := plane.state.Load().ports[port].hosts[fixtureHost]
	if host == nil || len(host.routes) == 0 || host.routes[0].mtls == nil || host.tls == nil {
		t.Fatal("mTLS trust was not compiled")
	}
	return host
}

func authorizeChain(
	t *testing.T, host *edgeHost, peers []*x509.Certificate, sameTrust bool,
) bool {
	t.Helper()
	conn := &sourceConn{}
	if sameTrust {
		conn.trustKey = host.authKey
	}
	verified := [][]*x509.Certificate{peers}
	req := &http.Request{
		Method: http.MethodGet, Host: fixtureHost, Header: make(http.Header),
		URL: &url.URL{Path: "/"},
		TLS: &tls.ConnectionState{
			Version: tls.VersionTLS12, ServerName: fixtureHost,
			PeerCertificates: peers, VerifiedChains: verified,
		},
	}
	req = req.WithContext(context.WithValue(req.Context(), connKey{}, conn))
	_, allowed := authorizeMTLS(httptest.NewRecorder(), req, host.routes[0].mtls, host)
	return allowed
}

func TestMTLSChainInsideSkewWindow(t *testing.T) {
	root := mintCert(t, nil, caTemplate(t, "root"))
	for _, tc := range insideSkewCases() {
		t.Run(tc.name, func(t *testing.T) {
			leaf, intermediate := issueSkewed(t, root, tc)
			listener, roots := serveClientCA(
				t, root.pem(), []string{root.fingerprint()}, []string{testIdentity}, "clients",
			)
			status, reason, err := presentChain(t, listener, roots, leaf, intermediate)
			if !chainAccepted(status, err) {
				t.Fatalf(
					"certificate inside ±60s was rejected: status %d reason %q err %v",
					status, reason, err,
				)
			}
		})
	}
}

func TestMTLSChainReverifyInsideSkew(t *testing.T) {
	root := mintCert(t, nil, caTemplate(t, "root"))
	host := compiledChainHost(t, root)
	for _, tc := range insideSkewCases() {
		t.Run(tc.name, func(t *testing.T) {
			leaf, intermediate := issueSkewed(t, root, tc)
			peers := []*x509.Certificate{leaf.cert, intermediate.cert}
			if !authorizeChain(t, host, peers, false) {
				t.Fatal("reverify rejected a certificate inside the ±60s window")
			}
		})
	}
}

func TestMTLSChainExtraUntrustedIntermediate(t *testing.T) {
	root := mintCert(t, nil, caTemplate(t, "root"))
	other := mintCert(t, nil, caTemplate(t, "other-root"))
	intermediate := mintCert(t, root, caTemplate(t, "intermediate"))
	leaf := mintCert(t, intermediate, leafTemplate(t, testIdentity))
	extra := mintCert(t, other, caTemplate(t, "untrusted-intermediate"))

	t.Run("handshake", func(t *testing.T) {
		listener, roots := serveClientCA(
			t, root.pem(), []string{root.fingerprint()}, []string{testIdentity}, "clients",
		)
		status, reason, err := presentChain(t, listener, roots, leaf, intermediate, extra)
		if chainAccepted(status, err) {
			t.Fatalf(
				"extra untrusted intermediate was accepted: status %d reason %q",
				status, reason,
			)
		}
	})
	t.Run("reverify", func(t *testing.T) {
		host := compiledChainHost(t, root)
		peers := make([]*x509.Certificate, 0, 3)
		peers = append(peers, leaf.cert, intermediate.cert)
		if !authorizeChain(t, host, peers, false) {
			t.Fatal("reverify rejected the trusted chain without the extra intermediate")
		}
		peers = append(peers, extra.cert)
		if authorizeChain(t, host, peers, false) {
			t.Fatal("reverify accepted a chain that included an untrusted intermediate")
		}
	})
}
