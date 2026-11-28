package dataplane

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/zekihan/gatehouse/internal/config"
)

func TestCompressionNegotiation(t *testing.T) {
	for _, tc := range []struct {
		header, want string
	}{
		{},
		{header: "gzip", want: "gzip"},
		{header: "gzip;q=0.9, br;q=0.5, zstd;q=0.1", want: "gzip"},
		{header: "br;q=0.9, zstd;q=0.9, gzip;q=0.9", want: "zstd"},
		{header: "br;q=0.9, gzip;q=0.9", want: "br"},
		{header: "*;q=0.6, zstd;q=0, gzip;q=0.4", want: "br"},
		{header: "*;q=0, gzip;q=0.5", want: "gzip"},
		{header: "identity;q=0, *;q=0"},
		{header: "gzip;q=0, br;q=0, zstd;q=0"},
		{header: "zstd;q=1.001, gzip;q=0.4", want: "gzip"},
	} {
		if got := negotiate([]string{tc.header}, encodings); got != tc.want {
			t.Errorf("Accept-Encoding %q selected %q, want %q", tc.header, got, tc.want)
		}
	}
}

type compressionCase struct {
	name, method, header, value, body, coding string
	code                                      int
	unknown                                   bool
	want                                      string
}

func TestCompressionBypassAndMetadata(t *testing.T) {
	text := strings.Repeat("<p>gatehouse</p>", 100)
	cfg := config.Compression{Encodings: encodings, MinBytes: 1024}
	for _, tc := range []compressionCase{
		{name: "identity"},
		{name: "existing encoding", header: "Content-Encoding", value: "custom", coding: "gzip", want: "custom"},
		{name: "no transform", header: "Cache-Control", value: "private, no-transform", coding: "gzip"},
		{name: "no content", code: 204, coding: "gzip"},
		{name: "not modified", code: 304, coding: "gzip"},
		{name: "partial", code: 206, coding: "gzip"},
		{name: "HEAD", method: "HEAD", coding: "gzip"},
		{name: "event stream", header: "Content-Type", value: "text/event-stream; charset=utf-8", coding: "gzip"},
		{name: "grpc", header: "Content-Type", value: "application/grpc+proto", coding: "gzip"},
		{name: "small", body: "small", coding: "gzip"},
		{name: "small unknown length", body: "small", coding: "gzip", unknown: true},
		{name: "gzip", coding: "gzip", want: "gzip"},
		{name: "brotli", coding: "br", want: "br"},
		{name: "streaming zstd", coding: "zstd", want: "zstd", unknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertCompression(t, cfg, tc, text)
		})
	}
}

func assertCompression(t *testing.T, cfg config.Compression, tc compressionCase, text string) {
	t.Helper()

	method, code, body := tc.method, tc.code, tc.body
	if method == "" {
		method = http.MethodGet
	}
	if code == 0 {
		code = http.StatusOK
	}
	if body == "" {
		body = text
	}
	resp := &http.Response{
		StatusCode: code, Request: &http.Request{Method: method}, Header: make(http.Header),
		ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body)),
	}
	if tc.unknown {
		resp.ContentLength = -1
	} else {
		resp.Header.Set("Content-Length", "1600")
	}
	if tc.header != "" {
		resp.Header.Set(tc.header, tc.value)
	}
	resp.Header.Set("ETag", "\"strong\"")
	if err := compressResponse(resp, cfg, tc.coding); err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Content-Encoding"); got != tc.want {
		t.Fatalf("encoding %q, want %q", got, tc.want)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	assertCompressionOutput(t, resp, data, body, tc.want)
}

func assertCompressionOutput(t *testing.T, resp *http.Response, data []byte, body, coding string) {
	t.Helper()
	if coding == "" || coding == "custom" {
		if string(data) != body || resp.Header.Get("ETag") != "\"strong\"" {
			t.Fatal("identity body or metadata was changed")
		}
		return
	}
	if resp.ContentLength != -1 || resp.Header.Get("Content-Length") != "" ||
		resp.Header.Get("ETag") != "W/\"strong\"" ||
		!headerToken(resp.Header.Values("Vary"), "Accept-Encoding") {
		t.Fatalf("compressed metadata: %v", resp.Header)
	}
	if out := decompress(t, data, coding); string(out) != body {
		t.Fatalf(
			"compressed response roundtrip produced %d bytes, wanted %d",
			len(out),
			len(body),
		)
	}
}

func decompress(t *testing.T, data []byte, coding string) []byte {
	t.Helper()
	var reader io.Reader
	switch coding {
	case "gzip":
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer gz.Close()
		reader = gz
	case "br":
		reader = brotli.NewReader(bytes.NewReader(data))
	case "zstd":
		zs, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer zs.Close()
		reader = zs
	default:
		t.Fatalf("unexpected coding %q", coding)
	}
	result, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
