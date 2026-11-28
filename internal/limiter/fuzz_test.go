package limiter

import (
	"bytes"
	"compress/flate"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func FuzzGossipFrame(f *testing.F) {
	raw := gossipSeed(false)
	f.Add(raw)
	f.Add(gossipSeed(true))
	f.Add(compressFrame(raw))
	f.Add([]byte(nil))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer rejectPanic(t)
		first, ok := decodeFrame(data)
		second, again := decodeFrame(data)
		if ok != again || !reflect.DeepEqual(first, second) {
			t.Fatal("decodeFrame is not stable")
		}
		if !ok {
			return
		}
		exerciseMerge(t, data, first)
	})
}

func gossipSeed(full bool) []byte {
	now := time.Now().Unix()
	message := frame{
		Version: wireVersion,
		From:    origin{Name: "peer", Epoch: 2},
		At:      now,
		Full:    full,
		Changes: []change{{
			Key:   strings.Repeat("a", 43),
			Node:  origin{Name: "peer", Epoch: 2},
			Slots: map[int64]uint64{now: 3},
			Gauge: gauge{Seq: 4, Value: 5, At: now},
		}},
	}
	data, err := encodeFrame(message)
	if err != nil {
		panic(err)
	}
	return data
}

func compressFrame(raw []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0)
	writer, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		panic(err)
	}
	if _, err := writer.Write(raw); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func exerciseMerge(t *testing.T, data []byte, message frame) {
	t.Helper()
	node := NewLocal()
	node.merge(data, message.Full)
	node.merge(data, !message.Full)
	if len(data) <= 256<<10 {
		message.At = time.Now().Unix()
		if !validOrigin(message.From) || message.From == node.local {
			message.From = origin{Name: "peer", Epoch: 2}
		}
		encoded, err := encodeFrame(message)
		if err != nil {
			t.Fatalf("encode decoded frame: %v", err)
		}
		node.merge(encoded, message.Full)
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	for key, group := range node.shared {
		if _, exists := group[node.local]; exists {
			t.Fatalf("merge stored the local origin under %q", key)
		}
	}
}

func rejectPanic(t *testing.T) {
	t.Helper()
	if recovered := recover(); recovered != nil {
		t.Fatalf("panic: %v\n%s", recovered, debug.Stack())
	}
}
