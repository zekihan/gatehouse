package limiter

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
)

const (
	route = "apps/storage"
	host  = "storage.example"
	start = 1000
)

var clientIP = netip.MustParseAddr("192.0.2.1")

func limits(minute, second, client, host int) config.Limits {
	return config.Limits{
		PerRouteClient: config.ClientLimits{
			PerMinute:     minute,
			PerSecondSlot: second,
			InFlight:      client,
		},
		PerRouteHost: config.HostLimits{InFlight: host},
	}
}

func testNode(name string, epoch int64, pending bool, clock *int64) *Limiter {
	node := newLimiter(origin{Name: name, Epoch: epoch}, pending)
	node.now = func() time.Time { return time.Unix(*clock, 0) }
	return node
}

func see(receiver, other *Limiter) {
	receiver.observe(other.local, receiver.now())
	receiver.peers[other.local] = receiver.now()
}

func transfer(sender, receiver *Limiter, full bool) {
	data, _ := sender.export(full)
	receiver.merge(data, full)
}

func send(l *Limiter, ip netip.Addr, attempts int, cfg config.Limits, release bool) int {
	for i := range attempts {
		done, ok := l.Admit(route, ip, host, cfg)
		if !ok {
			return i
		}
		if release {
			done()
		}
	}
	return attempts
}

func expect(t *testing.T, l *Limiter, attempts, want int, cfg config.Limits) {
	t.Helper()
	if n := send(l, clientIP, attempts, cfg, true); n != want {
		t.Fatalf("at slot %d, %s admitted %d, want %d", l.now().Unix(), l.local.Name, n, want)
	}
}

func TestAlignedWindow(t *testing.T) {
	slot := int64(start)
	node := testNode("node", 1, false, &slot)
	cfg := limits(5, 3, 10, 10)
	expect(t, node, 4, 3, cfg)
	slot++
	expect(t, node, 4, 2, cfg)
	slot = start + window - 1
	expect(t, node, 1, 0, cfg)
	slot++
	expect(t, node, 4, 3, cfg)
}

func TestSnapshotsRepairLossAndHoldGauges(t *testing.T) {
	slot := int64(start)
	a, b := testNode("a", 1, false, &slot), testNode("b", 1, false, &slot)
	see(b, a)
	flight := limits(500, 500, 1, 1)
	release, ok := a.Admit(route, clientIP, host, flight)
	if !ok {
		t.Fatal("first request refused")
	}
	lost, _ := a.export(false)
	// The delta was lost. The next full exchange must reconcile the active gauge.
	expect(t, b, 1, 1, flight)
	transfer(a, b, true)
	expect(t, b, 1, 0, flight)
	// Repeated refreshes keep the active gauge pinned throughout an upload.
	for slot < start+1800 {
		slot += gaugeRefresh
		transfer(a, b, false)
	}
	expect(t, b, 1, 0, flight)
	delayed, _ := a.export(true)
	release()
	release()
	transfer(a, b, false)
	b.merge(delayed, true)
	b.merge(lost, false)
	expect(t, b, 1, 1, flight)
	slot += window
	b.merge(delayed, true)
	expect(t, b, 1, 1, flight)
}

func TestIncarnationFencingAndResync(t *testing.T) {
	slot := int64(start)
	old, survivor := testNode("a", 1, false, &slot), testNode("b", 1, false, &slot)
	see(survivor, old)
	cfg := limits(10, 3, 3, 3)
	if send(old, clientIP, 2, cfg, false) != 2 {
		t.Fatal("initial requests refused")
	}
	transfer(old, survivor, false)
	expect(t, old, 1, 1, cfg)
	delayed, _ := old.export(false)

	restarted := testNode("a", 2, true, &slot)
	see(restarted, survivor)
	see(survivor, restarted)
	survivor.merge(delayed, false)
	delete(survivor.peers, old.local)
	if restarted.Ready() {
		t.Fatal("ready before resync")
	}
	expect(t, restarted, 1, 1, cfg)
	transfer(survivor, restarted, true)
	if !restarted.Ready() {
		t.Fatal("still pending after full peer state")
	}
	expect(t, restarted, 1, 0, cfg)
	transfer(restarted, survivor, false)
	expect(t, survivor, 1, 0, cfg)
	slot++
	expect(t, survivor, 3, 3, cfg)
}

const slotCap, minuteCap = 3000, 30000

func TestConnectedRateBounds(t *testing.T) {
	cfg := limits(minuteCap, slotCap, 3000, 6000)
	cases := []struct {
		name     string
		visible  int
		crosses  bool
		expected int
	}{
		{name: "previous slots delivered before next slot", visible: 27000, expected: 36000},
		{name: "one second delay crosses boundary", visible: 24000, crosses: true, expected: 42000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slot := int64(start)
			nodes := threeNodes(&slot)
			for visible := 0; visible < tc.visible; visible += slotCap {
				expect(t, nodes[0], slotCap, slotCap, cfg)
				transfer(nodes[0], nodes[1], true)
				transfer(nodes[0], nodes[2], true)
				slot++
			}
			total := tc.visible
			for _, node := range nodes {
				total += send(node, clientIP, slotCap+1, cfg, true)
			}
			if tc.crosses {
				slot++
				for _, node := range nodes {
					total += send(node, clientIP, slotCap+1, cfg, true)
				}
			}
			if total != tc.expected {
				t.Fatalf("admitted %d in window, want %d", total, tc.expected)
			}
			t.Logf("measured %d admissions in window", total)
			synchronize(nodes)
			for _, node := range nodes {
				expect(t, node, 1, 0, cfg)
			}
		})
	}
}

func TestIsolatedBounds(t *testing.T) {
	cfg := limits(minuteCap, slotCap, 3000, 6000)
	slot := int64(start)
	nodes := threeNodes(&slot)
	for _, node := range nodes {
		clear(node.peers)
	}
	total := 0
	for ; slot < start+window; slot++ {
		burst := 0
		for _, node := range nodes {
			burst += send(node, clientIP, slotCap+1, cfg, true)
		}
		if burst > 9000 || (slot == start && burst != 9000) {
			t.Fatalf("isolated slot admitted %d", burst)
		}
		total += burst
	}
	if total != 90000 {
		t.Fatalf("isolated minute admitted %d", total)
	}
	flight := 0
	for _, node := range nodes {
		flight += send(node, clientIP, slotCap+1, cfg, false)
		slot++
	}
	if flight != 9000 {
		t.Fatalf("isolated client in-flight admitted %d", flight)
	}
	for _, node := range nodes {
		flight += send(node, netip.MustParseAddr("192.0.2.2"), slotCap+1, cfg, false)
		expect(t, node, 1, 0, cfg)
	}
	if flight != 18000 {
		t.Fatalf("isolated host in-flight admitted %d", flight)
	}
	t.Log(
		"measured isolated bounds: 9000/slot, 90000/minute, 9000 client and 18000 host in flight",
	)
}

func TestConnectedInFlightBound(t *testing.T) {
	slot := int64(start)
	nodes := threeNodes(&slot)
	cfg := limits(minuteCap, slotCap, 3000, 6000)
	const visible, unshared = 2700, 300
	total := send(nodes[0], clientIP, visible, cfg, false)
	synchronize(nodes)
	for _, node := range nodes {
		n := send(node, clientIP, unshared+1, cfg, false)
		if n != unshared {
			t.Fatalf("replica %s admitted %d additional requests", node.local.Name, n)
		}
		total += n
	}
	if total != 3000+2*unshared {
		t.Fatalf("combined in-flight = %d", total)
	}
	synchronize(nodes)
	slot++
	for _, node := range nodes {
		expect(t, node, 1, 0, cfg)
	}
	t.Logf(
		"measured %d in flight at %d additional admissions per replica during the delay",
		total,
		unshared,
	)
}

func threeNodes(slot *int64) []*Limiter {
	nodes := []*Limiter{
		testNode("a", 1, false, slot), testNode("b", 1, false, slot), testNode("c", 1, false, slot),
	}
	for _, receiver := range nodes {
		for _, other := range nodes {
			if receiver != other {
				see(receiver, other)
			}
		}
	}
	return nodes
}

func synchronize(nodes []*Limiter) {
	for _, sender := range nodes {
		for _, receiver := range nodes {
			if sender != receiver {
				transfer(sender, receiver, true)
			}
		}
	}
}

func TestHighCardinalityKeepsTrackedAndOverflowState(t *testing.T) {
	slot := int64(start)
	node := testNode("node", 1, false, &slot)
	cfg := limits(1, 1, 1, sharedKeys+2)
	pinned, ok := node.Admit(route, clientIP, host, cfg)
	if !ok {
		t.Fatal("first request refused")
	}
	for i := range sharedKeys + overflowKeys {
		ip := addressFor(i)
		send(node, ip, 1, cfg, true)
	}
	if len(node.shared) != sharedKeys || node.overflowEvents == 0 {
		t.Fatalf("shared keys %d, overflow events %d", len(node.shared), node.overflowEvents)
	}
	slot += 1800
	expect(t, node, 1, 0, cfg)
	if len(node.shared) != 2 {
		t.Fatalf(
			"%d shared keys after inactivity; want just the pinned client and host",
			len(node.shared),
		)
	}
	pinned()
	expect(t, node, 2, 1, cfg)
	slot += window
	expect(t, node, 2, 1, cfg)
}

func addressFor(index int) netip.Addr {
	var ip [16]byte
	ip[0] = 0xfd
	binary.BigEndian.PutUint64(ip[8:], uint64(max(index, 0)))
	return netip.AddrFrom16(ip)
}
