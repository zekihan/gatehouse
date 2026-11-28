package crowdsec

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFullSnapshotsAcrossReplicas(t *testing.T) {
	var mu sync.Mutex
	var calls int
	status, body := http.StatusOK, `{"new":[
		{"type":"ban","scope":"Ip","value":"192.0.2.1","duration":"5s"},
		{"type":"ban","scope":"IP","value":"::ffff:192.0.2.1","duration":"20s"},
		{"type":"ban","scope":"Range","value":"2001:db8::5/48","duration":"1m"},
		{"type":"ban","scope":"range","value":"198.51.100.0/24","duration":"40s"},
		{"type":"captcha","scope":"Ip","value":"192.0.2.2","duration":"1m"}
	],"deleted":null}`
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if req.Method != http.MethodGet || req.URL.Path != "/v1/decisions/stream" ||
			req.URL.RawQuery != "startup=true" || req.Header.Get("X-Api-Key") != "fixture" {
			t.Errorf("unexpected LAPI request")
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(lapi.Close)
	before := time.Unix(120, 0)
	first, second := testBouncer(
		t,
		lapi.URL,
		before,
	), testBouncer(
		t,
		lapi.URL,
		before.Add(time.Second),
	)
	poll := func(b *Bouncer, fail bool) {
		t.Helper()
		if err := b.poll(t.Context()); (err != nil) != fail {
			t.Fatalf("poll error = %v, expected failure = %t", err, fail)
		}
	}
	if first.Ready() || first.Banned(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("a cold bouncer must fail open and be unready")
	}
	poll(first, false)
	if second.Ready() {
		t.Fatal("another replica's first poll activated this replica")
	}
	poll(second, false)
	expectBan(t, first, true, "192.0.2.1", "::ffff:192.0.2.1", "2001:db8::e", "198.51.100.2")
	expectBan(t, first, false, "192.0.2.2", "2001:db9::1")
	expectBan(t, second, true, "192.0.2.1", "2001:db8::e")

	first.now = func() time.Time { return before.Add(10 * time.Second) }
	expectBan(t, first, true, "192.0.2.1")
	mu.Lock()
	body = `{"new":[{"type":"ban","scope":"Ip","value":"192.0.2.2","duration":"23s"}],"deleted":`
	mu.Unlock()
	poll(first, true)
	expectBan(t, first, false, "192.0.2.2")
	expectBan(t, first, true, "192.0.2.1", "2001:db8::e")
	first.now = func() time.Time { return before.Add(30 * time.Second) }
	expectBan(t, first, false, "192.0.2.1")
	expectBan(t, first, true, "2001:db8::e", "198.51.100.2")
	if metric := first.Metrics(); metric.Decisions != 2 || metric.Staleness != 30*time.Second {
		t.Fatalf("unexpected stale metrics: %+v", metric)
	}

	mu.Lock()
	status = http.StatusServiceUnavailable
	mu.Unlock()
	poll(first, true)
	if !first.Ready() {
		t.Fatal("a failed poll removed readiness")
	}
	mu.Lock()
	status = http.StatusOK
	body = `{"new":[{"type":"ban","scope":"Ip","value":"192.0.2.2","duration":"23s"}],"deleted":[]}`
	mu.Unlock()
	poll(first, false)
	expectBan(t, first, false, "198.51.100.2", "2001:db8::e")
	expectBan(t, first, true, "192.0.2.2")
	expectBan(t, second, true, "198.51.100.2", "2001:db8::e")
	poll(second, false)
	expectBan(t, second, false, "198.51.100.2", "2001:db8::e")
	expectBan(t, second, true, "192.0.2.2")
	mu.Lock()
	defer mu.Unlock()
	if calls != 6 {
		t.Fatalf("got %d full snapshot calls, want 6", calls)
	}
}

func testBouncer(t *testing.T, address string, start time.Time) *Bouncer {
	t.Helper()
	bouncer, err := New(address, func() (string, error) { return "fixture", nil })
	if err != nil {
		t.Fatal(err)
	}
	bouncer.now = func() time.Time { return start }
	return bouncer
}

func expectBan(t *testing.T, b *Bouncer, want bool, ips ...string) {
	t.Helper()
	for _, ip := range ips {
		if b.Banned(netip.MustParseAddr(ip)) != want {
			t.Errorf("%s ban = %t, want %t", ip, !want, want)
		}
	}
}

func TestInvalidFullSnapshot(t *testing.T) {
	inputs := []string{
		`null`,
		`{"new":[]}`,
		`{"new":{},"deleted":[]}`,
		`{"new":[],"deleted":[]} {}`,
		`{"new":[null],"deleted":[]}`,
		`{"new":[{"type":"ban","scope":"Ip","value":"oops","duration":"1h"}],"deleted":[]}`,
		`{"new":[{"type":"ban","scope":"Range","value":"192.0.2.0/99","duration":"1h"}],"deleted":[]}`,
		`{"new":[{"type":"ban","scope":"Ip","value":"192.0.2.1","duration":"oops"}],"deleted":[]}`,
	}
	for _, input := range inputs {
		if _, err := decode(strings.NewReader(input), time.Now()); err == nil {
			t.Errorf("accepted invalid input %s", input)
		}
	}
	if _, err := decode(strings.NewReader(`{"new":null,"deleted":null}`), time.Now()); err != nil {
		t.Fatal("valid empty snapshot rejected:", err)
	}
}
