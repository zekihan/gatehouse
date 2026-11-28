package dataplane

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"runtime/debug"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func FuzzClientHello(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{22, 3, 1, 0, 4, 1, 0, 0, 0})
	var body cryptobyte.Builder
	body.AddBytes(make([]byte, 34))
	body.AddUint8(0)
	body.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x1301) })
	body.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
	body.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(0)
				b.AddUint16LengthPrefixed(
					func(b *cryptobyte.Builder) { b.AddBytes([]byte(fixtureHost)) },
				)
			})
		})
	})
	var record cryptobyte.Builder
	record.AddBytes([]byte{22, 3, 3})
	record.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body.BytesOrPanic()) })
	})
	f.Add(record.BytesOrPanic())
	f.Fuzz(func(t *testing.T, input []byte) {
		defer rejectPanic(t)
		r := bytes.NewReader(input)
		_, replay, err := peekHello(r)
		if err == nil && !bytes.Equal(replay, input[:len(input)-r.Len()]) {
			t.Fatal("accepted ClientHello must replay every byte consumed")
		}
	})
}

func FuzzProxyProtocol(f *testing.F) {
	f.Add([]byte{})
	f.Add(append(append([]byte(nil), proxySignature...), 0x21, 0x11, 0, 12,
		192, 0, 2, 1, 192, 0, 2, 2, 0x20, 0, 0x20, 0))
	f.Fuzz(func(t *testing.T, input []byte) {
		defer rejectPanic(t)
		r := bytes.NewReader(input)
		source, err := readProxyV2(r)
		if err != nil {
			return
		}
		if !source.IsValid() {
			t.Fatal("accepted PROXY header without a valid source")
		}
		var encoded bytes.Buffer
		if err := writeProxyV2(&encoded, source, source); err != nil {
			t.Fatal(err)
		}
		got, err := readProxyV2(&encoded)
		if err != nil || got != source || encoded.Len() != 0 {
			t.Fatal("PROXY address failed to round-trip")
		}
	})
}

func FuzzNormalizedPath(f *testing.F) {
	f.Add("/alpha/../beta/?page=1")
	f.Add("/café")
	f.Add("/")
	f.Fuzz(func(t *testing.T, target string) {
		defer rejectPanic(t)
		u, err := url.ParseRequestURI(target)
		if err != nil {
			return
		}
		original := *u
		request := &http.Request{Method: http.MethodGet, URL: u, RequestURI: target}
		parsed, ok := normalizedPath(request)
		if !ok {
			return
		}
		if !strings.HasPrefix(parsed, "/") || strings.ContainsAny(parsed, "\\%;?#\x00") {
			t.Fatal("normalization produced an ambiguous path")
		}
		cleaned := path.Clean(parsed)
		if parsed != cleaned && parsed != cleaned+"/" {
			t.Fatal("normalization left non-canonical path segments")
		}
		if request.RequestURI != target || *request.URL != original {
			t.Fatal("normalization changed the request target")
		}
	})
}

func FuzzQueryRedaction(f *testing.F) {
	f.Add("", "fixture")
	f.Add("view=grid", "value with separators &=;")
	f.Fuzz(func(t *testing.T, extra, value string) {
		defer rejectPanic(t)
		secret := url.QueryEscape("synthetic-redaction-marker:" + value)
		other := url.QueryEscape(extra)
		for _, name := range sensitiveParameters {
			encoded := fmt.Sprintf("%%%02X%s", name[0], name[1:])
			checkRedacted(t, name+"="+secret+"&other="+other, name)
			checkRedacted(t, encoded+"="+secret+"&other="+other, encoded)
		}
	})
}

func checkRedacted(t *testing.T, query, name string) {
	t.Helper()
	redacted := redactedQuery(query)
	if !strings.HasPrefix(redacted, name+"=[redacted]&") {
		t.Fatalf("sensitive query field %s was not redacted: %q", name, redacted)
	}
	if redactedQuery(redacted) != redacted {
		t.Fatal("query redaction is not idempotent")
	}
}

func FuzzStripHeaders(f *testing.F) {
	f.Add("X-Real-IP", "203.0.113.5", "X-App", "ok", "close")
	f.Add("X_Forwarded_For", "203.0.113.9", "Upgrade", "websocket", "upgrade, X-App")
	f.Add("X-Edge-Secret", "synthetic", "Cf-Connecting-IP", "203.0.113.8", "")
	f.Fuzz(func(t *testing.T, left, leftValue, right, rightValue, connection string) {
		defer rejectPanic(t)
		headers := make(http.Header)
		if left != "" {
			headers.Add(left, leftValue)
		}
		if right != "" {
			headers.Add(right, rightValue)
		}
		if connection != "" {
			headers.Add("Connection", connection)
		}
		headers.Add("X-Real-IP", "192.0.2.1")
		headers.Add("X-Edge-Secret", "synthetic")
		headers.Add("X-App-User", "ada")
		state := &compiled{edgeHeaders: map[string]bool{"x-edge-secret": true}}
		state.stripHeaders(headers)
		for name := range headers {
			if state.reserved(name) {
				t.Fatalf("reserved header %q survived", name)
			}
		}
		switch values := headers.Values("Connection"); len(values) {
		case 0:
			if _, ok := headers["Upgrade"]; ok {
				t.Fatal("upgrade header survived without an upgrade connection")
			}
		case 1:
			if values[0] != "Upgrade" {
				t.Fatalf("connection header %q", values)
			}
		default:
			t.Fatalf("connection header %q", values)
		}
	})
}

func rejectPanic(t *testing.T) {
	t.Helper()
	if recovered := recover(); recovered != nil {
		t.Fatalf("panic: %v\n%s", recovered, debug.Stack())
	}
}
