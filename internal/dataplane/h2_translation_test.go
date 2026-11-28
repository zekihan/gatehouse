package dataplane

import (
	"bytes"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

func TestExactDenyBypassedByDotAndSlashNormalization(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // localhost fixture echoes the request target for the assertion below.
		_, _ = io.WriteString(w, r.RequestURI+"|"+path.Clean(r.URL.Path))
	}))
	t.Cleanup(back.Close)
	client := startH2Edge(t, back, func(s *snapshot.Snapshot) {
		registry := s.Config.Hosts[fixtureHost]
		registry.Deny = &config.Deny{Exact: []string{"/secret"}}
		s.Config.Hosts[fixtureHost] = registry
	})

	// want is the only acceptable status. Zero means the decoded path cleans
	// to the denied target, so either rejecting it or denying it is safe.
	for _, tc := range []struct {
		path string
		want int
	}{
		{path: "/secret", want: http.StatusForbidden},
		{path: "/secret%2Ffile", want: http.StatusBadRequest},
		{path: "/public", want: http.StatusOK},
		{path: "/./secret"},
		{path: "//secret"},
		{path: "/secret/foo/%2e%2e"},
		{path: "/secret/./"},
		{path: "/secret//"},
		{path: "/secret/%2e/"},
		{path: "/secret/foo/../"},
		{path: "/secret/foo/%2e%2e/"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			status, body := h2Get(t, client, tc.path)
			switch tc.want {
			case http.StatusOK:
				if status != http.StatusOK || body != tc.path+"|"+tc.path {
					t.Fatalf("status %d body %q", status, body)
				}
			case 0:
				if status != http.StatusBadRequest && status != http.StatusForbidden {
					t.Fatalf("status %d body %q, want 400 or 403", status, body)
				}
			default:
				if status != tc.want {
					t.Fatalf("status %d body %q, want %d", status, body, tc.want)
				}
			}
		})
	}
}

func TestH2ExpectContinueNotForwarded(t *testing.T) {
	release, finish := singleClose()
	t.Cleanup(finish)
	seen := make(chan string, 1)
	client := startH2Edge(t, continueBackend(t, seen, release), nil)
	client.Timeout = 8 * time.Second
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("missing fixture transport")
	}
	transport.ExpectContinueTimeout = 5 * time.Second

	premature := make(chan struct{}, 1)
	decided := make(chan struct{})
	done := postExpectContinue(t, client, premature, decided)
	expect, early := observeContinue(t, seen, premature)
	close(decided)
	if expect != "100-continue" || early {
		t.Errorf(
			"upstream Expect %q, client received 100 before the upstream decided: %v",
			expect,
			early,
		)
	}
	finish()
	assertContinueResult(t, done)
}

func h2Get(t *testing.T, client *http.Client, target string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://"+fixtureHost+target,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	status, body, _ := doRequest(t, client, req)
	return status, body
}

func continueBackend(t *testing.T, seen chan<- string, release <-chan struct{}) *httptest.Server {
	t.Helper()
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Expect")
		<-release
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(back.Close)
	return back
}

func postExpectContinue(
	t *testing.T,
	client *http.Client,
	premature chan<- struct{},
	decided <-chan struct{},
) <-chan continueResult {
	t.Helper()
	payload := []byte("continue-body")
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://"+fixtureHost+"/upload",
		bytes.NewReader(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(payload))
	req.Header.Set("Expect", "100-continue")
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
			notePrematureContinue(code, decided, premature)
			return nil
		},
	}))
	done := make(chan continueResult, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil && resp.Body != nil {
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}
		done <- continueResult{resp: resp, err: err}
	}()
	return done
}

func notePrematureContinue(code int, decided <-chan struct{}, premature chan<- struct{}) {
	if code != http.StatusContinue {
		return
	}
	select {
	case <-decided:
	default:
		select {
		case premature <- struct{}{}:
		default:
		}
	}
}

func observeContinue(t *testing.T, seen <-chan string, premature <-chan struct{}) (string, bool) {
	t.Helper()
	var expect string
	select {
	case expect = <-seen:
	case <-time.After(2 * time.Second):
		t.Error("upstream did not observe the request")
	}
	select {
	case <-premature:
		return expect, true
	case <-time.After(500 * time.Millisecond):
		return expect, false
	}
}

func assertContinueResult(t *testing.T, done <-chan continueResult) {
	t.Helper()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.resp.ProtoMajor != 2 || result.resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("proto %s status %d", result.resp.Proto, result.resp.StatusCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not finish")
	}
}

type continueResult struct {
	resp *http.Response
	err  error
}

func singleClose() (<-chan struct{}, func()) {
	ch := make(chan struct{})
	var once sync.Once
	return ch, func() { once.Do(func() { close(ch) }) }
}

func startH2Edge(
	t *testing.T,
	back *httptest.Server,
	mutate func(*snapshot.Snapshot),
) *http.Client {
	t.Helper()
	l, port := newListener(t)
	pair, roots := makeCertificate(t)
	be := &snapshot.Backend{
		Service:   "ns/app",
		Port:      80,
		Endpoints: []string{strings.TrimPrefix(back.URL, "http://")},
	}
	s := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{
		Certificate: pair,
		Routes:      []snapshot.Route{{Name: "root", Path: "/", Backend: be}},
	})
	if mutate != nil {
		mutate(s)
	}
	p := New(Options{})
	if err := p.Update(s); err != nil {
		t.Fatal(err)
	}
	startListener(t, l, p, port, "")
	return h2Client(t, l, roots)
}

func h2Client(t *testing.T, l net.Listener, roots *x509.CertPool) *http.Client {
	t.Helper()
	client := testClient(t, l, roots)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("missing fixture transport")
	}
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP2(true)
	transport.Protocols.SetHTTP1(false)
	return client
}
