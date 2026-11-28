package limiter

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"time"
)

const (
	wireVersion  = 1
	maxFrame     = 20 << 20 // memberlist's user state and user message limits.
	maxDecoded   = 96 << 20
	gaugeRefresh = 10
)

type change struct {
	Key   string           `json:"key"`
	Node  origin           `json:"node"`
	Slots map[int64]uint64 `json:"slots,omitempty"`
	Gauge gauge            `json:"gauge"`
}

type frame struct {
	Version int      `json:"version"`
	From    origin   `json:"from"`
	At      int64    `json:"at"`
	Full    bool     `json:"full"`
	Changes []change `json:"changes,omitempty"`
}

func (l *Limiter) export(full bool) ([]byte, []string) {
	l.mu.Lock()
	slot := l.now().Unix()
	l.sweep(slot)
	message := frame{Version: wireVersion, From: l.local, At: slot, Full: full}
	var keys []string
	if full {
		message.Changes = l.fullState(slot)
	} else {
		message.Changes, keys = l.changedState(slot)
	}
	l.mu.Unlock()

	data, err := encodeFrame(message)
	if err != nil || len(data) > maxFrame {
		l.retry(keys)
		return nil, nil
	}
	return data, keys
}

func (l *Limiter) fullState(slot int64) []change {
	var updates []change
	for key, group := range l.shared {
		for id, item := range group {
			updates = append(updates, makeChange(key, id, item, l.local, slot))
		}
	}
	return updates
}

func (l *Limiter) changedState(slot int64) ([]change, []string) {
	if slot >= l.lastRefresh+gaugeRefresh {
		for key, group := range l.shared {
			if value := group[l.local]; value != nil && value.Gauge.Value != 0 {
				l.dirty[key] = true
			}
		}
		l.lastRefresh = slot
	}
	var updates []change
	var keys []string
	for key := range l.dirty {
		if item := l.shared[key][l.local]; item != nil {
			updates = append(updates, makeChange(key, l.local, item, l.local, slot))
			keys = append(keys, key)
		}
	}
	clear(l.dirty)
	return updates, keys
}

func encodeFrame(message frame) ([]byte, error) {
	raw, err := json.Marshal(message)
	if err != nil || len(raw) <= 32<<10 {
		return raw, err
	}
	var data bytes.Buffer
	data.WriteByte(0)
	writer, err := flate.NewWriter(&data, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(raw); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

func decodeFrame(data []byte) (frame, bool) {
	var message frame
	if len(data) == 0 || len(data) > maxFrame {
		return message, false
	}
	if data[0] != 0 {
		err := json.Unmarshal(data, &message)
		return message, err == nil
	}
	reader := flate.NewReader(bytes.NewReader(data[1:]))
	defer func() { _ = reader.Close() }()
	length := &io.LimitedReader{R: reader, N: maxDecoded + 1}
	decoder := json.NewDecoder(length)
	var trailing json.RawMessage
	if decoder.Decode(&message) != nil || decoder.Decode(&trailing) != io.EOF || length.N == 0 {
		return frame{}, false
	}
	return message, true
}

func makeChange(key string, node origin, item *counter, local origin, slot int64) change {
	value := item.Gauge
	if node == local && value.Value > 0 {
		value.At = slot
	}
	return change{Key: key, Node: node, Slots: maps.Clone(item.Slots), Gauge: value}
}

func (l *Limiter) retry(keys []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		l.dirty[key] = true
	}
}

func (l *Limiter) merge(data []byte, full bool) {
	message, ok := decodeFrame(data)
	if !ok ||
		message.Version != wireVersion || message.Full != full || message.From == l.local ||
		!validOrigin(message.From) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	slot := now.Unix()
	if message.At <= slot-window || message.At > slot+1 ||
		!l.observe(message.From, now) {
		return
	}
	l.sweep(slot)
	for _, update := range message.Changes {
		l.mergeChange(update, message.From, slot, full)
	}
	if full {
		l.resync = false
	}
}

func (l *Limiter) mergeChange(update change, sender origin, slot int64, full bool) {
	id := update.Node
	if !l.validChange(update, sender, full) {
		return
	}
	latest := l.latest[id.Name].epoch
	fenced := id.Epoch < latest || id.Name == l.local.Name
	// Full state relays retained slots to new replicas. Once fenced, an
	// older sender's own packets cannot change its contributions.
	if fenced && (id == sender || !full) {
		return
	}
	if !fenced {
		l.latest[id.Name] = epochMark{epoch: id.Epoch, at: slot}
	}
	group := l.remoteGroup(update.Key)
	if group == nil {
		return
	}
	item := group[id]
	if item == nil {
		item = new(counter)
		group[id] = item
	}
	item.mergeSlots(update.Slots, slot)
	if !fenced && update.Gauge.newer(item.Gauge, slot) {
		item.Gauge = update.Gauge
	}
	if !keep(item, slot) {
		delete(group, id)
		if len(group) == 0 {
			delete(l.shared, update.Key)
		}
	}
}

func (l *Limiter) validChange(update change, sender origin, full bool) bool {
	return update.Node != l.local && validOrigin(update.Node) &&
		len(update.Key) == 43 && (full || update.Node == sender)
}

func (l *Limiter) remoteGroup(key string) entry {
	group := l.shared[key]
	if group != nil {
		return group
	}
	if len(l.shared) >= sharedKeys {
		l.overflowEvents++
		return nil
	}
	group = make(entry)
	l.shared[key] = group
	return group
}

func (c *counter) mergeSlots(slots map[int64]uint64, now int64) {
	for at, count := range slots {
		if at > now-window && at <= now+1 && count > c.Slots[at] {
			if c.Slots == nil {
				c.Slots = make(map[int64]uint64)
			}
			c.Slots[at] = count
		}
	}
}

func (g gauge) newer(previous gauge, now int64) bool {
	return g.At > now-window && g.At <= now+1 &&
		(g.Seq > previous.Seq || g.Seq == previous.Seq && g.At > previous.At)
}

func (l *Limiter) observe(id origin, now time.Time) bool {
	if id.Name == l.local.Name || id.Epoch < l.latest[id.Name].epoch {
		return false
	}
	l.latest[id.Name] = epochMark{epoch: id.Epoch, at: now.Unix()}
	if _, member := l.peers[id]; member {
		l.peers[id] = now
	}
	return true
}

func (l *Limiter) Metrics(out io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now.Unix())
	peers := 0
	for id, last := range l.peers {
		if id.Epoch != l.latest[id.Name].epoch {
			continue
		}
		if now.Sub(last) <= peerFresh {
			peers++
		}
		fmt.Fprintf(
			out,
			"gatehouse_gossip_peer_staleness_seconds{peer=%q} %g\n",
			id.Name,
			max(0, now.Sub(last).Seconds()),
		)
	}
	fmt.Fprintf(out, "gatehouse_gossip_peers %d\n", peers)
	fmt.Fprintf(out, "gatehouse_limiter_isolated %d\n", flag(l.resync || peers == 0))
	fmt.Fprintf(out, "gatehouse_limiter_resync_pending %d\n", flag(l.resync))
	fmt.Fprintf(out, "gatehouse_limiter_capacity_overflow_total %d\n", l.overflowEvents)
	for route, values := range l.pressures {
		high := 0.0
		for _, value := range values {
			high = max(high, value)
		}
		fmt.Fprintf(out, "gatehouse_limiter_pressure{route=%q} %g\n", route, high)
	}
}

func flag(value bool) int {
	if value {
		return 1
	}
	return 0
}
