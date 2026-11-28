package config

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime/debug"
	"testing"
)

func FuzzParse(f *testing.F) {
	sample, err := os.ReadFile("../../examples/operator.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sample)
	f.Add([]byte("ports: {}\n"))
	f.Add([]byte("ports:\n  8443: {identity: direct}\n"))
	f.Add([]byte("[]\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer rejectPanic(t)
		cfg, err := Parse(data)
		if err != nil {
			if cfg != nil {
				t.Fatal("parse error returned a configuration")
			}
			return
		}
		if cfg == nil {
			t.Fatal("successful parse returned nil configuration")
		}
		again, err := Parse(data)
		if err != nil || again == nil {
			t.Fatal("parse is not stable")
		}
		left, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		right, err := json.Marshal(again)
		if err != nil || !bytes.Equal(left, right) {
			t.Fatal("parsed configuration encoding is not stable")
		}
	})
}

func rejectPanic(t *testing.T) {
	t.Helper()
	if recovered := recover(); recovered != nil {
		t.Fatalf("panic: %v\n%s", recovered, debug.Stack())
	}
}
