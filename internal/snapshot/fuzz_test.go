package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/zekihan/gatehouse/internal/config"
)

func FuzzDigest(f *testing.F) {
	f.Add("Secret", "app", "tls", int64(1), []byte(`{"cert":"fixture","ca":"test"}`))
	f.Add("HTTPRoute", "app", "api", int64(0), []byte(`{"rules":[]}`))
	f.Add("Namespace", "app", "app", int64(0), []byte(`null`))
	f.Add("Secret", "app", "tls", int64(1), []byte(`{`))
	f.Fuzz(func(t *testing.T, kind, namespace, name string, generation int64, content []byte) {
		defer rejectPanic(t)
		cfg := &config.Config{}
		input := Input{
			Kind:       kind,
			Namespace:  namespace,
			Name:       name,
			Generation: generation,
			Content:    json.RawMessage(content),
		}
		if _, err := Digest(nil, []Input{input}); err == nil {
			t.Fatal("nil configuration accepted")
		}
		first, err := Digest(cfg, []Input{input})
		if err != nil {
			return
		}
		if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
			t.Fatalf("digest %q", first)
		}
		second, err := Digest(cfg, []Input{input})
		if err != nil || second != first {
			t.Fatal("digest is not stable")
		}
		if _, err := Digest(cfg, []Input{input, input}); err == nil {
			t.Fatal("duplicate snapshot input accepted")
		}
		pretty, ok := prettyJSON(content)
		if !ok {
			t.Fatal("accepted content that is not one JSON value")
		}
		prettyDigest, err := Digest(cfg, []Input{{
			Kind: kind, Namespace: namespace, Name: name, Generation: generation, Content: pretty,
		}})
		if err != nil || prettyDigest != first {
			t.Fatal("JSON whitespace changed the digest")
		}
	})
}

func prettyJSON(data []byte) ([]byte, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, false
	}
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, false
	}
	return pretty, true
}

func rejectPanic(t *testing.T) {
	t.Helper()
	if recovered := recover(); recovered != nil {
		t.Fatalf("panic: %v\n%s", recovered, debug.Stack())
	}
}
