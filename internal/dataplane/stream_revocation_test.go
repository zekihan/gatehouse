package dataplane

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/snapshot"
)

func authorizationClient(t *testing.T, l net.Listener, roots *x509.CertPool, leaf tls.Certificate,
	h2 bool,
) *http.Client {
	t.Helper()
	client := testClient(t, l, roots)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("missing fixture transport")
	}
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP2(h2)
	transport.Protocols.SetHTTP1(!h2)
	transport.TLSClientConfig.Certificates = []tls.Certificate{leaf}
	client.Timeout = 5 * time.Second
	return client
}

func TestMTLSStreamRevocation(t *testing.T) {
	caA, _ := makeCertificate(t)
	caB, _ := makeCertificate(t)
	server, roots := makeCertificate(t)
	alice, anchorA := clientCertificate(t, caA)
	bob, anchorB := issueClientCertificate(t, caB, secondIdentity, nil)
	fingerprint := sha256.Sum256(alice.Certificate[0])

	for _, tc := range []struct {
		name   string
		update func(*snapshot.Snapshot, uint16)
	}{
		{"disabled identity", func(s *snapshot.Snapshot, port uint16) {
			s.DataPlane.Ports[port][fixtureHost].Routes[0].MTLS.DisabledIdentities = []string{testIdentity}
		}},
		{"blocked fingerprint", func(s *snapshot.Snapshot, port uint16) {
			s.DataPlane.Ports[port][fixtureHost].Routes[0].MTLS.BlockedFingerprints = []string{hex.EncodeToString(fingerprint[:])}
		}},
		{"anchor removed", func(s *snapshot.Snapshot, port uint16) {
			s.DataPlane.Ports[port][fixtureHost].Routes[0].MTLS.TrustedAnchors = []string{anchorB}
		}},
		{"TLS CA removed", func(s *snapshot.Snapshot, port uint16) {
			host := s.DataPlane.Ports[port][fixtureHost]
			host.ClientCA = caB.CertPEM
			s.DataPlane.Ports[port][fixtureHost] = host
		}},
		{"ceiling narrowed", func(s *snapshot.Snapshot, _ uint16) {
			host := s.Config.Hosts[fixtureHost]
			host.Identities = []string{secondIdentity}
			s.Config.Hosts[fixtureHost] = host
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, port := newListener(t)
			release := make(chan struct{})
			back := httptest.NewServer(revocationBackend(t, release))
			t.Cleanup(back.Close)
			p := New(Options{})
			input := func() *snapshot.Snapshot {
				return protectedSnapshot(
					port,
					server,
					bytes.Join([][]byte{caA.CertPEM, caB.CertPEM}, nil),
					strings.TrimPrefix(back.URL, "http://"),
					anchorA,
					anchorB,
				)
			}
			if err := p.Update(input()); err != nil {
				t.Fatal(err)
			}
			startListener(t, l, p, port, "")
			h2Alice := authorizationClient(t, l, roots, alice, true)
			http1Alice := authorizationClient(t, l, roots, alice, false)
			h2Bob := authorizationClient(t, l, roots, bob, true)
			a := openRevocationStream(t, h2Alice, false)
			b := openRevocationStream(t, h2Bob, false)
			ws := openRevocationStream(t, http1Alice, true)

			next := input()
			tc.update(next, port)
			if err := p.Update(next); err != nil {
				t.Fatal(err)
			}
			// The updated policy applies to the original HTTP/2 connection.
			assertMTLSRequest(t, h2Alice, "/", http.StatusForbidden, true)
			requireRevoked(t, a)
			requireRevoked(t, ws)
			close(release)
			if line, err := b.ReadString('\n'); err != nil || line != "second\n" {
				t.Fatalf("still authorized stream got %q, %v", line, err)
			}
			assertMTLSRequest(t, h2Bob, "/", http.StatusNoContent, true)
		})
	}
}

func revocationBackend(t *testing.T, release <-chan struct{}) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/events":
			if _, err := io.WriteString(w, "first\n"); err != nil {
				t.Error(err)
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error(err)
				return
			}
			select {
			case <-release:
				_, _ = io.WriteString(w, "second\n")
			case <-r.Context().Done():
			}
		case "/ws":
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			const handshake = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
			if _, err := rw.WriteString(handshake); err != nil {
				t.Error(err)
				return
			}
			// One unmasked server-to-client text frame proves the upgraded
			// stream is usable before the snapshot changes.
			if _, err := rw.Write([]byte{0x81, 2, 'o', 'k'}); err != nil {
				t.Error(err)
				return
			}
			if err := rw.Flush(); err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, rw)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

func openRevocationStream(t *testing.T, client *http.Client, websocket bool) *bufio.Reader {
	t.Helper()
	path := "/events"
	if websocket {
		path = "/ws"
	}
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://"+fixtureHost+path,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if websocket {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	reader := bufio.NewReader(resp.Body)
	if websocket {
		frame := make([]byte, 4)
		_, err := io.ReadFull(reader, frame)
		if resp.StatusCode != http.StatusSwitchingProtocols || err != nil ||
			!bytes.Equal(frame, []byte{0x81, 2, 'o', 'k'}) {
			t.Fatalf("WebSocket got %d, frame %v, %v", resp.StatusCode, frame, err)
		}
	} else {
		if line, err := reader.ReadString(
			'\n',
		); resp.ProtoMajor != 2 || line != "first\n" ||
			err != nil {
			t.Fatalf("initial stream got %s %d, %q, %v", resp.Proto, resp.StatusCode, line, err)
		}
	}
	return reader
}

func requireRevoked(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	var timeout net.Error
	if _, err := reader.ReadByte(); err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatalf("revocation did not close the stream: %v", err)
	}
}
