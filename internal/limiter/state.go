// Package limiter enforces soft request limits across Gatehouse replicas.
package limiter

import (
	"crypto/sha256"
	"encoding/base64"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
)

const (
	window       = 60
	sharedKeys   = 8192
	overflowKeys = 1024
	peerFresh    = 3 * time.Second
)

type origin struct {
	Name  string `json:"name"`
	Epoch int64  `json:"epoch"`
}

type gauge struct {
	Seq   uint64 `json:"seq"`
	Value uint64 `json:"value"`
	At    int64  `json:"at"`
}

type counter struct {
	Slots map[int64]uint64
	Gauge gauge
}

type entry map[origin]*counter

type epochMark struct {
	epoch int64
	at    int64
}

type Limiter struct {
	mu             sync.Mutex
	local          origin
	now            func() time.Time
	shared         map[string]entry
	overflow       [overflowKeys]*counter
	peers          map[origin]time.Time
	latest         map[string]epochMark
	dirty          map[string]bool
	pressures      map[string]map[int64]float64
	resync         bool
	overflowEvents uint64
	lastSweep      int64
	sequence       uint64
	lastRefresh    int64
}

func NewLocal() *Limiter {
	return newLimiter(origin{Name: "local", Epoch: 1}, false)
}

func newLimiter(id origin, resync bool) *Limiter {
	return &Limiter{
		local:     id,
		now:       time.Now,
		shared:    make(map[string]entry),
		peers:     make(map[origin]time.Time),
		latest:    make(map[string]epochMark),
		dirty:     make(map[string]bool),
		pressures: make(map[string]map[int64]float64),
		resync:    resync,
	}
}

func (l *Limiter) Ready() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.resync
}

func (l *Limiter) Admit(
	route string,
	ip netip.Addr,
	host string,
	limits config.Limits,
) (func(), bool) {
	if limits.PerRouteClient.PerMinute <= 0 || limits.PerRouteClient.PerSecondSlot <= 0 ||
		limits.PerRouteClient.InFlight <= 0 || limits.PerRouteHost.InFlight <= 0 {
		return nil, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	slot := l.now().Unix()
	l.sweep(slot)
	clientKey, client, clientOverflow := l.lookup(route, "client", ip.WithZone("").Unmap().String())
	hostKey, hostCounter, hostOverflow := l.lookup(route, "host", host)
	clientCount := l.counts(clientKey, client, slot, clientOverflow)
	hostCount := l.counts(hostKey, hostCounter, slot, hostOverflow)
	caps := configCaps(limits)
	if !permitted(clientCount, hostCount, caps) {
		l.dropUnused(clientKey, client)
		l.dropUnused(hostKey, hostCounter)
		l.pressure(route, slot, clientCount, hostCount, caps)
		return nil, false
	}
	if client.Slots == nil {
		client.Slots = make(map[int64]uint64)
	}
	client.Slots[slot]++
	l.writeGauge(clientKey, client, clientOverflow, client.Gauge.Value+1, slot)
	l.writeGauge(hostKey, hostCounter, hostOverflow, hostCounter.Gauge.Value+1, slot)
	clientCount.minute++
	clientCount.slot++
	clientCount.flight++
	hostCount.flight++
	l.pressure(route, slot, clientCount, hostCount, caps)
	release := sync.OnceFunc(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		now := l.now().Unix()
		l.writeGauge(clientKey, client, clientOverflow, client.Gauge.Value-1, now)
		l.writeGauge(hostKey, hostCounter, hostOverflow, hostCounter.Gauge.Value-1, now)
	})
	return release, true
}

type usage struct {
	minute, slot, flight uint64
}

//nolint:gosec // Admit has already checked that each limit is positive.
func configCaps(cfg config.Limits) [4]uint64 {
	return [4]uint64{
		uint64(cfg.PerRouteClient.PerMinute),
		uint64(cfg.PerRouteClient.PerSecondSlot),
		uint64(cfg.PerRouteClient.InFlight),
		uint64(cfg.PerRouteHost.InFlight),
	}
}

func permitted(client, host usage, caps [4]uint64) bool {
	return client.minute < caps[0] && client.slot < caps[1] &&
		client.flight < caps[2] && host.flight < caps[3]
}

func (l *Limiter) lookup(route, kind, value string) (string, *counter, bool) {
	digest := sha256.Sum256([]byte(route + "\x00" + kind + "\x00" + value))
	key := base64.RawURLEncoding.EncodeToString(digest[:])
	index := (int(digest[0])<<8 | int(digest[1])) % (overflowKeys / 2)
	if kind == "host" {
		index += overflowKeys / 2
	}
	// Keep an overflow bucket's usage until its window has aged out. Collisions
	// conservatively share the same local allowance.
	if bucket := l.overflow[index]; bucket != nil && l.shared[key] == nil {
		l.overflowEvents++
		return "", bucket, true
	}
	group := l.shared[key]
	if group == nil && len(l.shared) >= sharedKeys {
		bucket := new(counter)
		l.overflow[index] = bucket
		l.overflowEvents++
		return "", bucket, true
	}
	if group == nil {
		group = make(entry)
		l.shared[key] = group
	}
	if group[l.local] == nil {
		group[l.local] = new(counter)
	}
	return key, group[l.local], false
}

func (l *Limiter) dropUnused(key string, item *counter) {
	if key == "" || item.Gauge.Seq != 0 {
		return
	}
	group := l.shared[key]
	delete(group, l.local)
	if len(group) == 0 {
		delete(l.shared, key)
	}
}

func (l *Limiter) counts(key string, self *counter, slot int64, overflow bool) usage {
	value := usage{flight: self.Gauge.Value}
	value.addSlots(self.Slots, slot)
	if overflow || l.resync {
		return value
	}
	for node, data := range l.shared[key] {
		if node != l.local {
			value.addSlots(data.Slots, slot)
			if _, live := l.peers[node]; live && l.latest[node.Name].epoch == node.Epoch &&
				data.Gauge.At > slot-window {
				value.flight = saturatingAdd(value.flight, data.Gauge.Value)
			}
		}
	}
	return value
}

func (u *usage) addSlots(slots map[int64]uint64, now int64) {
	for slot, n := range slots {
		if slot <= now && slot > now-window {
			u.minute = saturatingAdd(u.minute, n)
			if slot == now {
				u.slot = saturatingAdd(u.slot, n)
			}
		}
	}
}

func saturatingAdd(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

func (l *Limiter) writeGauge(key string, c *counter, overflow bool, value uint64, slot int64) {
	l.sequence++
	c.Gauge = gauge{Seq: l.sequence, Value: value, At: slot}
	if !overflow {
		l.dirty[key] = true
	}
}

func (l *Limiter) sweep(slot int64) {
	if slot == l.lastSweep {
		return
	}
	l.lastSweep = slot
	for key, group := range l.shared {
		for id, c := range group {
			if id != l.local && c.Gauge.At <= slot-window {
				c.Gauge = gauge{}
			}
			if !keep(c, slot) {
				delete(group, id)
			}
		}
		if len(group) == 0 {
			delete(l.shared, key)
			delete(l.dirty, key)
		}
	}
	for i, c := range l.overflow {
		if c != nil && !keep(c, slot) {
			l.overflow[i] = nil
		}
	}
	l.sweepMetadata(slot)
}

func (l *Limiter) sweepMetadata(slot int64) {
	for name, mark := range l.latest {
		if _, live := l.peers[origin{Name: name, Epoch: mark.epoch}]; !live &&
			mark.at <= slot-window {
			delete(l.latest, name)
		}
	}
	for route, values := range l.pressures {
		for at := range values {
			if at <= slot-window {
				delete(values, at)
			}
		}
		if len(values) == 0 {
			delete(l.pressures, route)
		}
	}
}

func keep(c *counter, slot int64) bool {
	for at := range c.Slots {
		if at <= slot-window {
			delete(c.Slots, at)
		}
	}
	return c.Gauge.Value != 0 || (c.Gauge.Seq != 0 && c.Gauge.At > slot-window) || len(c.Slots) != 0
}

func (l *Limiter) pressure(route string, slot int64, client, host usage, caps [4]uint64) {
	high := max(float64(client.minute)/float64(caps[0]), float64(client.slot)/float64(caps[1]),
		float64(client.flight)/float64(caps[2]), float64(host.flight)/float64(caps[3]))
	values := l.pressures[route]
	if values == nil {
		values = make(map[int64]float64)
		l.pressures[route] = values
	}
	values[slot] = max(high, values[slot])
}
