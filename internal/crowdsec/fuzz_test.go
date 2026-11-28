package crowdsec

import (
	"bytes"
	"reflect"
	"runtime/debug"
	"testing"
	"time"
)

func FuzzSnapshot(f *testing.F) {
	f.Add([]byte(
		`{"new":[{"type":"ban","scope":"Ip","value":"192.0.2.15","duration":"1h"}],"deleted":[]}`,
	))
	f.Add([]byte(
		`{"new":[{"type":"ban","scope":"range","value":"2001:db8::/32","duration":"90s"},` +
			`{"type":"captcha","scope":"ip","value":"198.51.100.4","duration":"5m"}],"deleted":[{}]}`,
	))
	f.Add([]byte(
		`{"new":[{"type":"ban","scope":"range","value":"::ffff:192.0.2.0/120","duration":"1m"}],"deleted":[]}`,
	))
	f.Add([]byte(`{"new":[],"deleted":[]}`))
	f.Add([]byte(`not-json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer rejectPanic(t)
		start := time.Unix(1_700_000_000, 0).UTC()
		first, err := decode(bytes.NewReader(data), start)
		if err != nil {
			if first != nil {
				t.Fatal("decode error returned decisions")
			}
			return
		}
		second, err := decode(bytes.NewReader(data), start)
		if err != nil || !reflect.DeepEqual(first, second) {
			t.Fatal("decode is not stable")
		}
		var latest time.Time
		for prefix, expires := range first.bans {
			if !prefix.IsValid() || expires.IsZero() {
				t.Fatalf("invalid ban %s at %s", prefix, expires)
			}
			if expires.After(latest) {
				latest = expires
			}
		}
		for _, expires := range first.expiry {
			if expires.After(latest) {
				latest = expires
			}
		}
		bouncer := &Bouncer{
			started: start,
			now:     func() time.Time { return latest.Add(time.Second) },
		}
		bouncer.active.Store(first)
		for prefix := range first.bans {
			if bouncer.Banned(prefix.Addr()) {
				t.Fatalf("expired ban %s still active", prefix)
			}
		}
	})
}

func rejectPanic(t *testing.T) {
	t.Helper()
	if recovered := recover(); recovered != nil {
		t.Fatalf("panic: %v\n%s", recovered, debug.Stack())
	}
}
