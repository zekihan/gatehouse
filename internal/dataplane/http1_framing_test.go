package dataplane

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

// foldFraming splits one upstream message the way an origin that applies
// gatehouse's own header folding (underscore equals hyphen) would. Chunked
// wins over Content-Length. A non-empty remainder is a second request.
func foldFraming(raw string) (string, string, bool) {
	head, payload, found := strings.Cut(raw, "\r\n\r\n")
	if !found {
		return "", "", false
	}
	var lengths []string
	chunked := false
	for line := range strings.SplitSeq(head, "\r\n") {
		name, value, cut := strings.Cut(line, ":")
		if !cut {
			continue
		}
		name = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "_", "-"))
		value = strings.TrimSpace(value)
		switch name {
		case "content-length":
			lengths = append(lengths, value)
		case "transfer-encoding":
			if strings.EqualFold(value, "chunked") {
				chunked = true
			}
		default:
		}
	}
	if len(lengths) > 1 {
		return "", "multiple-lengths:" + strings.Join(lengths, ","), true
	}
	if chunked {
		const end = "0\r\n\r\n"
		if strings.HasPrefix(payload, end) {
			return "", payload[len(end):], true
		}
		return payload, "", true
	}
	if len(lengths) == 0 {
		return "", payload, true
	}
	n, err := strconv.Atoi(lengths[0])
	if err != nil || n < 0 || n > len(payload) {
		return "", "", false
	}
	return payload[:n], payload[n:], true
}

func http1Head(method, target, host, headers string) string {
	return method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\n" + headers + "\r\n"
}

type http1Client struct {
	conn net.Conn
	r    *bufio.Reader
}

func openHTTP1(t *testing.T, ln net.Listener, roots *x509.CertPool) *http1Client {
	t.Helper()
	conn := tls.Client(dialTest(t, ln.Addr().String()), &tls.Config{
		RootCAs: roots, ServerName: fixtureHost, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := conn.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != "http/1.1" {
		t.Fatalf("negotiated %q", proto)
	}
	return &http1Client{conn: conn, r: bufio.NewReader(conn)}
}

func openPlain(t *testing.T, ln net.Listener) *http1Client {
	t.Helper()
	conn := dialTest(t, ln.Addr().String())
	return &http1Client{conn: conn, r: bufio.NewReader(conn)}
}

func (c *http1Client) exchange(t *testing.T, payload string) (int, http.Header, string) {
	t.Helper()
	if _, err := io.WriteString(c.conn, payload); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return c.read(t)
}

func (c *http1Client) read(t *testing.T) (int, http.Header, string) {
	t.Helper()
	resp, err := http.ReadResponse(c.r, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header, string(body)
}

func echoBackend(t *testing.T, tag string) *snapshot.Backend {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		//nolint:gosec // localhost fixture echoes the request target for the assertions below.
		if _, err := io.WriteString(w, tag+" "+r.RequestURI); err != nil {
			t.Errorf("echo: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return backendAt(t, tag, strings.TrimPrefix(server.URL, "http://"))
}

func backendAt(t *testing.T, tag, addr string) *snapshot.Backend {
	t.Helper()
	if _, _, err := net.SplitHostPort(addr); err != nil {
		t.Fatal(err)
	}
	return &snapshot.Backend{Service: "ns/" + tag, Port: 80, Endpoints: []string{addr}}
}

func startCapture(t *testing.T) (*snapshot.Backend, <-chan string) {
	t.Helper()
	var cfg net.ListenConfig
	ln, err := cfg.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	seen := make(chan string, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				raw, err := readUpstream(conn)
				if err != nil {
					seen <- "read error: " + err.Error() + "\n" + raw
					return
				}
				seen <- raw
				reply := "ok"
				header := "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
				header += strconv.Itoa(len(reply)) + "\r\nConnection: close\r\n\r\n"
				if _, err := io.WriteString(conn, header+reply); err != nil {
					return
				}
			}(conn)
		}
	}()
	return backendAt(t, "capture", ln.Addr().String()), seen
}

func readUpstream(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	var buf bytes.Buffer
	for {
		line, err := reader.ReadSlice('\n')
		buf.Write(line)
		if err != nil {
			return buf.String(), err
		}
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			break
		}
	}
	n, chunked := upstreamFraming(buf.String())
	if chunked {
		err := readChunked(reader, &buf)
		return buf.String(), err
	}
	if n > 0 {
		body := make([]byte, n)
		if _, err := io.ReadFull(reader, body); err != nil {
			return buf.String(), err
		}
		buf.Write(body)
	}
	return buf.String(), nil
}

func upstreamFraming(header string) (int, bool) {
	chunked := false
	length := -1
	for line := range strings.SplitSeq(header, "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil {
				length = n
			}
		case "transfer-encoding":
			chunked = strings.EqualFold(strings.TrimSpace(value), "chunked")
		default:
		}
	}
	if chunked {
		return 0, true
	}
	if length > 0 {
		return length, false
	}
	return 0, false
}

func readChunked(reader *bufio.Reader, buf *bytes.Buffer) error {
	for {
		line, err := reader.ReadSlice('\n')
		buf.Write(line)
		if err != nil {
			return err
		}
		sizeText, _, _ := strings.Cut(string(line), ";")
		sizeText = strings.TrimRight(strings.TrimSpace(sizeText), "\r")
		size, err := strconv.ParseInt(sizeText, 16, 64)
		if err != nil {
			return err
		}
		if size == 0 {
			for {
				trailer, err := reader.ReadSlice('\n')
				buf.Write(trailer)
				if err != nil {
					return err
				}
				if len(bytes.TrimRight(trailer, "\r\n")) == 0 {
					return nil
				}
			}
		}
		chunk := make([]byte, size+2)
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return err
		}
		buf.Write(chunk)
	}
}

func startEdge(
	t *testing.T,
	mode string,
	host snapshot.Host,
	deny *config.Deny,
) (net.Listener, *x509.CertPool) {
	t.Helper()
	ln, port := newListener(t)
	pair, roots := makeCertificate(t)
	if mode != redirectMode {
		host.Certificate = pair
	}
	plane := New(Options{})
	snap := testSnapshot(port, config.Port{Mode: mode, Identity: "direct"}, host)
	if deny != nil {
		registry := snap.Config.Hosts[fixtureHost]
		registry.Deny = deny
		snap.Config.Hosts[fixtureHost] = registry
	}
	if err := plane.Update(snap); err != nil {
		t.Fatal(err)
	}
	startListener(t, ln, plane, port, mode)
	return ln, roots
}

func takeCapture(t *testing.T, seen <-chan string) string {
	t.Helper()
	select {
	case raw := <-seen:
		return raw
	default:
		t.Fatal("backend received nothing")
	}
	return ""
}

func noCapture(t *testing.T, seen <-chan string) {
	t.Helper()
	select {
	case raw := <-seen:
		t.Fatalf("backend was contacted: %q", raw)
	default:
	}
}

func TestHTTP1ForwardedTargetMatchesAuthorizedPath(t *testing.T) {
	safe := echoBackend(t, "safe")
	secret := echoBackend(t, "secret")
	ln, roots := startEdge(t, "", snapshot.Host{Routes: []snapshot.Route{
		{Name: "safe", Path: "/safe", Backend: safe},
		{Name: "secret", Path: "/secret", Backend: secret},
	}}, &config.Deny{Prefixes: []string{"/secret"}})

	// The policy view is the once-decoded path with dot segments removed.
	// A forwarded target must be that path, or the request must be rejected.
	cases := []struct {
		name   string
		target string
		want   string
		reject bool
		status int
	}{
		{
			name:   "dot escape into allowed prefix",
			target: "/secret/../safe/item",
			want:   "safe /safe/item",
		},
		{
			name:   "encoded dots into allowed prefix",
			target: "/secret/%2e%2e/safe/item",
			want:   "safe /safe/item",
		},
		{
			name:   "dot segment inside allowed prefix",
			target: "/safe/./item",
			want:   "safe /safe/item",
		},
		{name: "empty segment", target: "/safe//item", want: "safe /safe/item"},
		{name: "overlong slash", target: "/safe/%c0%af../secret", reject: true},
		{name: "fullwidth slash", target: "/safe/%ef%bc%8f../secret", reject: true},
		{
			name:   "dot with path parameter",
			target: "/safe/..;/secret",
			reject: true,
			status: http.StatusBadRequest,
		},
		{
			name:   "encoded dot path parameter",
			target: "/safe/..%3b/secret",
			reject: true,
			status: http.StatusBadRequest,
		},
		{
			name:   "dots clean into deny",
			target: "/safe/../secret",
			reject: true,
			status: http.StatusForbidden,
		},
		{
			name:   "encoded dots clean into deny",
			target: "/safe/%2e%2e/secret",
			reject: true,
			status: http.StatusForbidden,
		},
		{
			name:   "encoded slash",
			target: "/safe/%2fsecret",
			reject: true,
			status: http.StatusBadRequest,
		},
		{
			name:   "encoded backslash",
			target: "/safe/%5csecret",
			reject: true,
			status: http.StatusBadRequest,
		},
		{
			name:   "encoded null",
			target: "/safe/%00secret",
			reject: true,
			status: http.StatusBadRequest,
		},
		{
			name:   "double encoded dot",
			target: "/safe/%252e%252e/secret",
			reject: true,
			status: http.StatusBadRequest,
		},
		{name: "canonical allowed path", target: "/safe/item", want: "safe /safe/item"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := openHTTP1(t, ln, roots)
			status, _, body := conn.exchange(
				t,
				http1Head(http.MethodGet, tc.target, fixtureHost, ""),
			)
			if tc.reject {
				if status == http.StatusOK || strings.HasPrefix(body, "safe ") ||
					strings.HasPrefix(body, "secret ") {
					t.Fatalf("status %d body %q; target %q was forwarded", status, body, tc.target)
				}
				if tc.status != 0 && status != tc.status {
					t.Fatalf("status %d body %q, want %d", status, body, tc.status)
				}
				return
			}
			if status != http.StatusOK || body != tc.want {
				t.Fatalf("status %d body %q, want 200 %q", status, body, tc.want)
			}
		})
	}
}

func TestHTTP1AbsoluteFormAuthority(t *testing.T) {
	safe := echoBackend(t, "safe")
	ln, roots := startEdge(t, "", snapshot.Host{Routes: []snapshot.Route{
		{Name: "safe", Path: "/safe", Backend: safe},
	}}, nil)
	for _, tc := range []struct {
		target string
		status int
	}{
		{target: "http://other.test/safe/item", status: http.StatusMisdirectedRequest},
		{target: "http://" + fixtureHost + "/safe/item", status: http.StatusBadRequest},
	} {
		conn := openHTTP1(t, ln, roots)
		status, _, body := conn.exchange(t, http1Head(http.MethodGet, tc.target, "other.test", ""))
		if status != tc.status || strings.Contains(body, "safe ") {
			t.Fatalf(
				"absolute-form %q status %d body %q, want %d and no upstream",
				tc.target,
				status,
				body,
				tc.status,
			)
		}
	}

	redirectLn, _ := startEdge(t, redirectMode, snapshot.Host{}, nil)
	plain := openPlain(t, redirectLn)
	status, header, body := plain.exchange(
		t,
		http1Head(http.MethodGet, "http://evil.example/secret", fixtureHost, ""),
	)
	location := header.Get("Location")
	if status == http.StatusBadRequest {
		return
	}
	if status != http.StatusMovedPermanently || location != "https://"+fixtureHost+"/secret" {
		t.Fatalf("absolute-form redirect status %d location %q body %q", status, location, body)
	}
}

func framingEdge(t *testing.T) (net.Listener, *x509.CertPool, <-chan string) {
	t.Helper()
	backend, seen := startCapture(t)
	ln, roots := startEdge(t, "", snapshot.Host{Routes: []snapshot.Route{
		{Name: "safe", Path: "/safe", Backend: backend},
	}}, &config.Deny{Prefixes: []string{"/secret"}})
	return ln, roots, seen
}

func TestHTTP1UnderscoreFraming(t *testing.T) {
	ln, roots, seen := framingEdge(t)

	t.Run("transfer-encoding", func(t *testing.T) {
		smuggle := "0\r\n\r\nGET /secret HTTP/1.1\r\nHost: " + fixtureHost + "\r\n\r\n"
		payload := http1Head(
			http.MethodPost,
			"/safe/item",
			fixtureHost,
			"Content-Length: "+strconv.Itoa(len(smuggle))+"\r\nTransfer_Encoding: chunked\r\n",
		) + smuggle
		conn := openHTTP1(t, ln, roots)
		status, _, body := conn.exchange(t, payload)
		if status != http.StatusOK {
			noCapture(t, seen)
			return
		}
		if body != "ok" {
			t.Fatalf("status %d body %q", status, body)
		}
		raw := takeCapture(t, seen)
		_, rest, ok := foldFraming(raw)
		if !ok || rest != "" || strings.Contains(strings.ToLower(raw), "transfer_encoding") {
			t.Fatalf("forwarded framing splits under underscore folding: rest %q raw %q", rest, raw)
		}
	})

	t.Run("underscore content-length", func(t *testing.T) {
		payload := http1Head(
			http.MethodPost,
			"/safe/item",
			fixtureHost,
			"Content-Length: 5\r\nContent_Length: 0\r\n",
		) + "hello"
		conn := openHTTP1(t, ln, roots)
		status, _, _ := conn.exchange(t, payload)
		if status != http.StatusOK {
			noCapture(t, seen)
			return
		}
		raw := takeCapture(t, seen)
		if strings.Contains(strings.ToLower(raw), "content_length") {
			t.Fatalf("forwarded a second length header: %q", raw)
		}
		body, rest, ok := foldFraming(raw)
		if !ok || rest != "" || body != "hello" {
			t.Fatalf("body %q rest %q raw %q", body, rest, raw)
		}
	})
}

func TestHTTP1RejectedFraming(t *testing.T) {
	ln, roots, seen := framingEdge(t)
	rejected := []struct {
		name    string
		payload string
	}{
		{
			name: "disagreeing content-lengths",
			payload: http1Head(http.MethodPost, "/safe/item", fixtureHost,
				"Content-Length: 1\r\nContent-Length: 2\r\n") + "ab",
		},
		{
			name: "numerically equal content-lengths",
			payload: http1Head(http.MethodPost, "/safe/item", fixtureHost,
				"Content-Length: 1\r\nContent-Length: 01\r\n") + "a",
		},
		{
			name:    "duplicate host",
			payload: http1Head(http.MethodGet, "/safe/item", fixtureHost, "Host: other.test\r\n"),
		},
		{
			name: "spaced transfer-encoding name",
			payload: http1Head(http.MethodPost, "/safe/item", fixtureHost,
				"Transfer-Encoding : chunked\r\nContent-Length: 0\r\n"),
		},
		{
			name: "multiple transfer-encoding headers",
			payload: http1Head(http.MethodPost, "/safe/item", fixtureHost,
				"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n") + "0\r\n\r\n",
		},
		{
			name: "transfer-encoding list",
			payload: http1Head(http.MethodPost, "/safe/item", fixtureHost,
				"Transfer-Encoding: chunked, identity\r\n") + "0\r\n\r\n",
		},
		{
			name: "obs-fold transfer-encoding",
			payload: http1Head(http.MethodPost, "/safe/item", fixtureHost,
				"Transfer-Encoding: chunked\r\n identity\r\n") + "0\r\n\r\n",
		},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			conn := openHTTP1(t, ln, roots)
			status, _, body := conn.exchange(t, tc.payload)
			if status == http.StatusOK {
				raw := takeCapture(t, seen)
				t.Fatalf("accepted ambiguous framing: status %d body %q raw %q", status, body, raw)
			}
			noCapture(t, seen)
			again := openHTTP1(t, ln, roots)
			status, _, body = again.exchange(
				t,
				http1Head(http.MethodGet, "/safe/item", fixtureHost, ""),
			)
			if status != http.StatusOK || body != "ok" {
				t.Fatalf("listener died after reject: status %d body %q", status, body)
			}
			if raw := takeCapture(t, seen); !strings.Contains(raw, "GET /safe/item ") {
				t.Fatalf("follow-up request was not forwarded intact: %q", raw)
			}
		})
	}
}

func TestHTTP1ContentLengthWithChunked(t *testing.T) {
	ln, roots, seen := framingEdge(t)
	payload := http1Head(http.MethodPost, "/safe/item", fixtureHost,
		"Content-Length: 48\r\nTransfer-Encoding: chunked\r\n") +
		"0\r\n\r\nGET /secret HTTP/1.1\r\nHost: " + fixtureHost + "\r\n\r\n"
	conn := openHTTP1(t, ln, roots)
	status, _, body := conn.exchange(t, payload)
	if status != http.StatusOK || body != "ok" {
		t.Fatalf("status %d body %q", status, body)
	}
	raw := takeCapture(t, seen)
	forwarded, rest, ok := foldFraming(raw)
	if !ok || rest != "" || strings.Contains(forwarded, "GET /secret") {
		t.Fatalf(
			"smuggled request reached the backend: body %q rest %q raw %q",
			forwarded,
			rest,
			raw,
		)
	}
	// The bytes after the chunked terminator are a second client request.
	status, _, body = conn.read(t)
	if status == http.StatusOK && strings.Contains(body, "GET /secret") {
		t.Fatal("second request was glued to the first body")
	}
	noCapture(t, seen)
}

func TestHTTP1DuplicateEqualContentLengths(t *testing.T) {
	ln, roots, seen := framingEdge(t)
	payload := http1Head(http.MethodPost, "/safe/item", fixtureHost,
		"Content-Length: 3\r\nContent-Length: 3\r\n") + "abc"
	conn := openHTTP1(t, ln, roots)
	status, _, body := conn.exchange(t, payload)
	if status != http.StatusOK || body != "ok" {
		t.Fatalf("status %d body %q", status, body)
	}
	raw := takeCapture(t, seen)
	forwarded, rest, ok := foldFraming(raw)
	if !ok || rest != "" || forwarded != "abc" || strings.Count(raw, "Content-Length:") != 1 {
		t.Fatalf(
			"duplicate lengths were not collapsed: body %q rest %q raw %q",
			forwarded,
			rest,
			raw,
		)
	}
}

func TestHTTP1ChunkExtension(t *testing.T) {
	ln, roots, seen := framingEdge(t)
	payload := http1Head(http.MethodPost, "/safe/item", fixtureHost,
		"Transfer-Encoding: chunked\r\n") + "3;ext=foo\r\nabc\r\n0;drop=this\r\n\r\n"
	conn := openHTTP1(t, ln, roots)
	status, _, body := conn.exchange(t, payload)
	if status != http.StatusOK || body != "ok" {
		t.Fatalf("status %d body %q", status, body)
	}
	raw := takeCapture(t, seen)
	forwarded, rest, ok := foldFraming(raw)
	if !ok || rest != "" || strings.Contains(forwarded, "ext=foo") ||
		strings.Contains(raw, "ext=foo") {
		t.Fatalf("chunk extension leaked downstream: body %q rest %q raw %q", forwarded, rest, raw)
	}
	if !strings.Contains(forwarded, "abc") && !strings.Contains(raw, "abc") {
		t.Fatalf("chunk data missing: %q", raw)
	}
}

func TestHTTP1ObsFoldHeader(t *testing.T) {
	ln, roots, seen := framingEdge(t)
	payload := http1Head(http.MethodGet, "/safe/item", fixtureHost, "X-Fold: alpha\r\n beta\r\n")
	conn := openHTTP1(t, ln, roots)
	status, _, body := conn.exchange(t, payload)
	if status == http.StatusBadRequest {
		noCapture(t, seen)
		return
	}
	if status != http.StatusOK || body != "ok" {
		t.Fatalf("status %d body %q", status, body)
	}
	raw := takeCapture(t, seen)
	if strings.Contains(raw, "\n beta") || !strings.Contains(raw, "X-Fold: alpha beta") {
		t.Fatalf("obs-fold was forwarded unfolded differently than parsed: %q", raw)
	}
}

func TestHTTP1ChunkedOptionalWhitespace(t *testing.T) {
	ln, roots, seen := framingEdge(t)
	headers := []string{
		"Transfer-Encoding: chunked \r\n",
		"Transfer-Encoding: chunked\t\r\n",
		"Transfer-Encoding:\tchunked\r\n",
	}
	for _, header := range headers {
		payload := http1Head(
			http.MethodPost,
			"/safe/item",
			fixtureHost,
			header,
		) + "3\r\nabc\r\n0\r\n\r\n"
		conn := openHTTP1(t, ln, roots)
		status, _, body := conn.exchange(t, payload)
		if status != http.StatusOK || body != "ok" {
			t.Fatalf("header %q status %d body %q", header, status, body)
		}
		raw := takeCapture(t, seen)
		forwarded, rest, ok := foldFraming(raw)
		clean := !strings.Contains(raw, "chunked ") && !strings.Contains(raw, "chunked\t")
		if !ok || rest != "" || !clean || !strings.Contains(forwarded, "abc") {
			t.Fatalf(
				"header %q was not re-encoded cleanly: body %q rest %q raw %q",
				header,
				forwarded,
				rest,
				raw,
			)
		}
	}
}
