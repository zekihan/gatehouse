// Package crowdsec installs complete CrowdSec LAPI snapshots.
package crowdsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zekihan/gatehouse/internal/observability"
)

const maxResponse = 64 << 20

type Bouncer struct {
	started  time.Time
	endpoint string
	key      func() (string, error)
	client   *http.Client
	active   atomic.Pointer[decisions]
	now      func() time.Time
}

type decisions struct {
	updated time.Time
	bans    map[netip.Prefix]time.Time
	lengths [2][]int
	expiry  []time.Time
}

type decision struct {
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
}

func New(address string, key func() (string, error)) (*Bouncer, error) {
	u, err := url.Parse(address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid CrowdSec LAPI base URL")
	}
	if key == nil {
		return nil, errors.New("CrowdSec LAPI key source is required")
	}
	u = u.JoinPath("v1/decisions/stream")
	u.RawQuery = "startup=true"
	client := &http.Client{
		Timeout: 25 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Bouncer{
		started:  time.Now(),
		endpoint: u.String(),
		key:      key,
		client:   client,
		now:      time.Now,
	}, nil
}

func (b *Bouncer) Run(ctx context.Context, report func(error)) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if err := b.poll(ctx); err != nil && ctx.Err() == nil && report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (b *Bouncer) Banned(ip netip.Addr) bool {
	current := b.active.Load()
	if current == nil || !ip.IsValid() {
		return false
	}
	ip = ip.WithZone("").Unmap()
	now := b.now()
	for _, bits := range current.lengths[family(ip)] {
		if current.bans[netip.PrefixFrom(ip, bits).Masked()].After(now) {
			return true
		}
	}
	return false
}

func (b *Bouncer) Ready() bool { return b.active.Load() != nil }

func (b *Bouncer) Metrics() observability.CrowdSecMetrics {
	now := b.now()
	metrics := observability.CrowdSecMetrics{Staleness: max(0, now.Sub(b.started))}
	if current := b.active.Load(); current != nil {
		for _, expires := range current.expiry {
			if expires.After(now) {
				metrics.Decisions++
			}
		}
		metrics.Staleness = max(0, now.Sub(current.updated))
	}
	return metrics
}

func (b *Bouncer) poll(ctx context.Context) error {
	key, err := b.key()
	if err != nil || strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\r\n") {
		return errors.New("CrowdSec LAPI key is unavailable or invalid")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.endpoint, nil)
	if err != nil {
		return errors.New("could not construct CrowdSec request")
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("Accept", "application/json")
	start := b.now()
	resp, err := b.client.Do(req)
	if err != nil {
		return errors.New("CrowdSec LAPI request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CrowdSec LAPI returned HTTP %d", resp.StatusCode)
	}
	next, err := decode(resp.Body, start)
	if err != nil {
		return err
	}
	next.updated = b.now()
	b.active.Store(next)
	return nil
}

func decode(body io.Reader, start time.Time) (*decisions, error) {
	limited := &io.LimitedReader{R: body, N: maxResponse + 1}
	parser := json.NewDecoder(limited)
	var response struct {
		New     json.RawMessage `json:"new"`
		Deleted json.RawMessage `json:"deleted"`
	}
	var extra json.RawMessage
	if parser.Decode(&response) != nil || parser.Decode(&extra) != io.EOF || limited.N == 0 {
		return nil, errors.New("invalid or incomplete CrowdSec snapshot")
	}
	var active []decision
	var deleted []json.RawMessage
	if json.Unmarshal(response.New, &active) != nil ||
		json.Unmarshal(response.Deleted, &deleted) != nil {
		return nil, errors.New("invalid CrowdSec decision arrays")
	}
	return compile(active, start)
}

func compile(active []decision, start time.Time) (*decisions, error) {
	next := &decisions{bans: make(map[netip.Prefix]time.Time)}
	var lengths [2][129]bool
	for _, entry := range active {
		if entry.Type == "" || entry.Scope == "" {
			return nil, errors.New("CrowdSec decision is missing a type or scope")
		}
		if !strings.EqualFold(entry.Type, "ban") {
			continue
		}
		prefix, err := entry.prefix()
		if err != nil {
			return nil, err
		}
		if !prefix.IsValid() {
			continue
		}
		duration, err := time.ParseDuration(entry.Duration)
		if err != nil {
			return nil, errors.New("invalid CrowdSec decision duration")
		}
		if duration <= 0 {
			continue
		}
		expires := start.Add(duration)
		next.expiry = append(next.expiry, expires)
		if expires.After(next.bans[prefix]) {
			next.bans[prefix] = expires
		}
		lengths[family(prefix.Addr())][prefix.Bits()] = true
	}
	for f, bits := range lengths {
		for size, used := range bits {
			if used {
				next.lengths[f] = append(next.lengths[f], size)
			}
		}
	}
	return next, nil
}

func (d decision) prefix() (netip.Prefix, error) {
	switch strings.ToLower(d.Scope) {
	case "ip":
		ip, err := netip.ParseAddr(d.Value)
		if err != nil || ip.Zone() != "" {
			return netip.Prefix{}, errors.New("invalid CrowdSec IP decision")
		}
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	case "range":
		prefix, err := netip.ParsePrefix(d.Value)
		if err != nil {
			return netip.Prefix{}, errors.New("invalid CrowdSec range decision")
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		return prefix.Masked(), nil
	default:
		return netip.Prefix{}, nil
	}
}

func family(ip netip.Addr) int {
	if ip.Is4() {
		return 0
	}
	return 1
}
