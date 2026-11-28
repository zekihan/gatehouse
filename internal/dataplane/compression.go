package dataplane

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/zekihan/gatehouse/internal/config"
)

var encodings = []string{"zstd", "br", "gzip"}

// negotiate uses integer thousandths and never lets a wildcard override an
// explicitly refused coding. Identity is always the fallback.
func negotiate(values, enabled []string) string {
	var q [4]int
	for i := range q {
		q[i] = -1
	}
	for _, line := range values {
		for item := range strings.SplitSeq(line, ",") {
			name, param, _ := strings.Cut(item, ";")
			name = strings.ToLower(strings.TrimSpace(name))
			index := slices.Index(encodings, name)
			if name == "*" {
				index = 3
			}
			if index < 0 {
				continue
			}
			weight := 1000
			if param != "" {
				key, value, ok := strings.Cut(param, "=")
				weight = 0
				if ok && strings.EqualFold(strings.TrimSpace(key), "q") {
					weight = quality(strings.TrimSpace(value))
				}
			}
			q[index] = max(q[index], weight)
		}
	}
	var best string
	var highest int
	for i, name := range encodings {
		weight := q[i]
		if weight < 0 {
			weight = q[3]
		}
		if weight > highest && slices.Contains(enabled, name) {
			best, highest = name, weight
		}
	}
	return best
}

func quality(value string) int {
	whole, decimal, _ := strings.Cut(value, ".")
	if whole != "0" && whole != "1" || len(decimal) > 3 {
		return 0
	}
	q := 0
	for _, digit := range decimal {
		if digit < '0' || digit > '9' || (whole == "1" && digit != '0') {
			return 0
		}
		q = q*10 + int(digit-'0')
	}
	if whole == "1" {
		return 1000
	}
	for range 3 - len(decimal) {
		q *= 10
	}
	return q
}

func compressResponse(resp *http.Response, cfg config.Compression, coding string) error {
	if !canCompress(resp, cfg) {
		return nil
	}
	h := resp.Header
	if !headerToken(h.Values("Vary"), "Accept-Encoding") && !headerToken(h.Values("Vary"), "*") {
		h.Add("Vary", "Accept-Encoding")
	}
	if coding == "" {
		return nil
	}
	var prefix bytes.Buffer
	if resp.ContentLength < 0 && cfg.MinBytes > 0 {
		n, err := io.CopyN(&prefix, resp.Body, int64(cfg.MinBytes))
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if n < int64(cfg.MinBytes) {
			resp.Body = &prefixBody{Reader: io.MultiReader(&prefix, resp.Body), Closer: resp.Body}
			return nil
		}
	}
	h.Del("Content-Length")
	h.Set("Content-Encoding", coding)
	if etag := h.Get("ETag"); strings.HasPrefix(etag, "\"") {
		h.Set("ETag", "W/"+etag)
	}
	resp.ContentLength = -1
	source := resp.Body
	reader, pipe := io.Pipe()
	resp.Body = &compressedBody{PipeReader: reader, source: source}
	go writeCompressed(pipe, io.MultiReader(&prefix, source), coding)
	return nil
}

func canCompress(resp *http.Response, cfg config.Compression) bool {
	h := resp.Header
	media, _, _ := strings.Cut(strings.ToLower(h.Get("Content-Type")), ";")
	media = strings.TrimSpace(media)
	if len(cfg.Encodings) == 0 || resp.Request.Method == http.MethodHead ||
		resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified || resp.StatusCode == http.StatusPartialContent ||
		media == "text/event-stream" || strings.HasPrefix(media, "application/grpc") ||
		len(
			h.Values("Content-Encoding"),
		) != 0 || headerToken(h.Values("Cache-Control"), "no-transform") ||
		resp.ContentLength == 0 || resp.ContentLength >= 0 && resp.ContentLength < int64(cfg.MinBytes) {
		return false
	}
	return true
}

func headerToken(values []string, token string) bool {
	for _, line := range values {
		for value := range strings.SplitSeq(line, ",") {
			if strings.EqualFold(strings.TrimSpace(value), token) {
				return true
			}
		}
	}
	return false
}

type prefixBody struct {
	io.Reader
	io.Closer
}

type compressedBody struct {
	*io.PipeReader

	source io.Closer
}

func (b *compressedBody) Close() error {
	_ = b.PipeReader.Close()
	return b.source.Close()
}

type compressor interface {
	io.WriteCloser
	Flush() error
}

var gzipPool, brotliPool, zstdPool, flushPool sync.Pool

//nolint:ireturn // one stream encoder contract across three libraries.
func getCompressor(
	w io.Writer,
	encoding string,
) (compressor, func(), error) {
	switch encoding {
	case "zstd":
		writer, ok := zstdPool.Get().(*zstd.Encoder)
		if !ok {
			var err error
			writer, err = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1),
				zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithWindowSize(128<<10))
			if err != nil {
				return nil, nil, err
			}
		}
		writer.Reset(w)
		return writer, func() {
			writer.Reset(nil)
			zstdPool.Put(writer)
		}, nil
	case "br":
		writer, ok := brotliPool.Get().(*brotli.Writer)
		if !ok {
			writer = brotli.NewWriterLevel(w, brotli.BestSpeed)
		} else {
			writer.Reset(w)
		}
		return writer, func() {
			writer.Reset(io.Discard)
			brotliPool.Put(writer)
		}, nil
	default:
		writer, ok := gzipPool.Get().(*gzip.Writer)
		if !ok {
			var err error
			writer, err = gzip.NewWriterLevel(w, gzip.BestSpeed)
			if err != nil {
				return nil, nil, err
			}
		} else {
			writer.Reset(w)
		}
		return writer, func() {
			writer.Reset(io.Discard)
			gzipPool.Put(writer)
		}, nil
	}
}

func writeCompressed(dst *io.PipeWriter, src io.Reader, encoding string) {
	output, ok := flushPool.Get().(*bufio.Writer)
	if !ok {
		output = bufio.NewWriterSize(dst, 16<<10)
	} else {
		output.Reset(dst)
	}
	defer func() {
		output.Reset(io.Discard)
		flushPool.Put(output)
	}()
	writer, release, err := getCompressor(output, encoding)
	if err != nil {
		_ = dst.CloseWithError(err)
		return
	}
	defer release()
	buf := buffers.Get()
	defer buffers.Put(buf)
	for {
		n, err := src.Read(buf)
		if n != 0 {
			if _, writeErr := writer.Write(buf[:n]); writeErr != nil {
				_ = dst.CloseWithError(writeErr)
				return
			}
		}
		if errors.Is(err, io.EOF) {
			_ = dst.CloseWithError(errors.Join(writer.Close(), output.Flush()))
			return
		}
		if err == nil && n != 0 {
			err = errors.Join(writer.Flush(), output.Flush())
		}
		if err != nil {
			_ = dst.CloseWithError(err)
			return
		}
	}
}
