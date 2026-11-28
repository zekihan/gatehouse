package dataplane

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zekihan/gatehouse/internal/observability"
)

type metricKey struct {
	port                   uint16
	code                   int
	route, backend, method string
}

type histogram struct {
	buckets [8]uint64
	sum     float64
	count   uint64
}

type series struct {
	bytesIn, bytesOut uint64
	latency, upstream histogram
}

type metrics struct {
	mu          sync.Mutex
	ids         atomicCounter
	logErrors   atomicCounter
	requests    map[metricKey]series
	handshakes  map[string]uint64
	denies      map[string]uint64
	connections map[uint16]*atomic.Int64
}

var latencyBounds = [...]time.Duration{
	500 * time.Microsecond, time.Millisecond, 5 * time.Millisecond, 25 * time.Millisecond,
	100 * time.Millisecond, 500 * time.Millisecond, time.Second, 10 * time.Second,
}

func (h *histogram) observe(elapsed time.Duration) {
	h.count++
	h.sum += elapsed.Seconds()
	for i, limit := range latencyBounds {
		if elapsed <= limit {
			h.buckets[i]++
		}
	}
}

func (m *metrics) request(
	entry requestRecord,
	status int,
	method string,
	elapsed time.Duration,
	in, out uint64,
) {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE":
	default:
		method = "OTHER"
	}
	key := metricKey{
		port:    entry.listener,
		code:    status,
		route:   entry.route,
		backend: entry.backend,
		method:  method,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.requests == nil {
		m.requests = make(map[metricKey]series)
		m.denies = make(map[string]uint64)
	}
	s := m.requests[key]
	s.bytesIn += in
	s.bytesOut += out
	s.latency.observe(elapsed)
	if entry.upstream > 0 {
		s.upstream.observe(entry.upstream)
	}
	m.requests[key] = s
	if entry.deny != "" {
		m.denies[entry.deny]++
	}
}

func (m *metrics) handshake(result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.handshakes == nil {
		m.handshakes = make(map[string]uint64)
	}
	m.handshakes[result]++
}

func (m *metrics) connectionsFor(port uint16) *atomic.Int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connections == nil {
		m.connections = make(map[uint16]*atomic.Int64)
	}
	counter := m.connections[port]
	if counter == nil {
		counter = new(atomic.Int64)
		m.connections[port] = counter
	}
	return counter
}

func (m *metrics) openConnections(port uint16) int64 {
	m.mu.Lock()
	counter := m.connections[port]
	m.mu.Unlock()
	if counter == nil {
		return 0
	}
	return counter.Load()
}

func (p *Plane) Metrics() http.Handler {
	return observability.MetricsHandler(p.WriteMetrics)
}

func (p *Plane) WriteMetrics(out io.Writer) {
	p.metrics.render(out)
	fmt.Fprintf(
		out,
		"# TYPE gatehouse_access_log_errors_total counter\ngatehouse_access_log_errors_total %d\n",
		p.metrics.logErrors.Load(),
	)
	p.writeSnapshotMetrics(out)
	p.writePolicyMetrics(out)
}

func (p *Plane) writeSnapshotMetrics(out io.Writer) {
	s := p.state.Load()
	if s == nil {
		fmt.Fprint(
			out,
			"# TYPE gatehouse_device_tls_exceptions gauge\ngatehouse_device_tls_exceptions 0\n",
		)
		return
	}
	fmt.Fprintf(
		out,
		"# TYPE gatehouse_snapshot_digest_info gauge\ngatehouse_snapshot_digest_info{digest=%s} 1\n",
		observability.Label(s.digest),
	)
	fmt.Fprintf(
		out,
		"# TYPE gatehouse_device_tls_exceptions gauge\ngatehouse_device_tls_exceptions %d\n",
		s.deviceTLSExceptions,
	)

	ports := slices.Sorted(maps.Keys(s.ports))
	fmt.Fprintln(out, "# TYPE gatehouse_open_connections gauge")
	for _, number := range ports {
		fmt.Fprintf(out, "gatehouse_open_connections{listener=%s} %d\n",
			observability.Label(listenerName(number)), p.metrics.openConnections(number))
	}
	const expiry = "gatehouse_certificate_expiry_timestamp_seconds"
	fmt.Fprintln(out, "# TYPE "+expiry+" gauge")
	for _, number := range ports {
		port := s.ports[number]
		for _, name := range slices.Sorted(maps.Keys(port.hosts)) {
			host := port.hosts[name]
			if host.tls != nil {
				fmt.Fprintf(out, "%s{listener=%s,host=%s} %d\n", expiry,
					observability.Label(listenerName(number)), observability.Label(name),
					host.tls.Certificates[0].Leaf.NotAfter.Unix())
			}
		}
	}
}

func (p *Plane) writePolicyMetrics(out io.Writer) {
	var crowdSec observability.CrowdSecMetrics
	if p.opts.CrowdSecMetrics != nil {
		crowdSec = p.opts.CrowdSecMetrics()
	}
	fmt.Fprintf(out, "# TYPE gatehouse_crowdsec_decisions gauge\ngatehouse_crowdsec_decisions %d\n",
		crowdSec.Decisions)
	fmt.Fprintf(
		out,
		"# TYPE gatehouse_crowdsec_staleness_seconds gauge\ngatehouse_crowdsec_staleness_seconds %g\n",
		crowdSec.Staleness.Seconds(),
	)
	var limiter observability.LimiterMetrics
	if p.opts.LimiterMetrics != nil {
		limiter = p.opts.LimiterMetrics()
	}
	fmt.Fprintf(
		out,
		"# TYPE gatehouse_gossip_peers gauge\ngatehouse_gossip_peers %d\n",
		limiter.GossipPeers,
	)
	fmt.Fprintln(out, "# TYPE gatehouse_gossip_peer_staleness_seconds gauge")
	for _, peer := range slices.Sorted(maps.Keys(limiter.PeerStaleness)) {
		fmt.Fprintf(out, "gatehouse_gossip_peer_staleness_seconds{peer=%s} %g\n",
			observability.Label(peer), limiter.PeerStaleness[peer].Seconds())
	}
	fmt.Fprintf(out, "# TYPE gatehouse_limiter_isolated gauge\ngatehouse_limiter_isolated %d\n",
		observability.BoolMetric(limiter.Isolated))
	fmt.Fprintf(
		out,
		"# TYPE gatehouse_limiter_capacity_overflow_total counter\ngatehouse_limiter_capacity_overflow_total %d\n",
		limiter.CapacityOverflow,
	)
	fmt.Fprintf(
		out,
		"# TYPE gatehouse_limiter_resync_pending gauge\ngatehouse_limiter_resync_pending %d\n",
		observability.BoolMetric(limiter.ResyncPending),
	)
	fmt.Fprintln(out, "# TYPE gatehouse_limiter_pressure gauge")
	for _, route := range slices.Sorted(maps.Keys(limiter.RoutePressure)) {
		fmt.Fprintf(out, "gatehouse_limiter_pressure{route=%s} %g\n",
			observability.Label(route), limiter.RoutePressure[route])
	}
}

type labeledSeries struct {
	series

	labels string
}

func (m *metrics) render(out io.Writer) {
	m.mu.Lock()
	requests, handshakes, denies := maps.Clone(
		m.requests,
	), maps.Clone(
		m.handshakes,
	), maps.Clone(
		m.denies,
	)
	m.mu.Unlock()

	keys := make([]labeledSeries, 0, len(requests))
	for key, values := range requests {
		labels := fmt.Sprintf("route=%s,listener=%s,backend=%s,code=%s,method=%s",
			observability.Label(key.route), observability.Label(listenerName(key.port)),
			observability.Label(key.backend), observability.Label(strconv.Itoa(key.code)),
			observability.Label(key.method))
		keys = append(keys, labeledSeries{series: values, labels: labels})
	}
	slices.SortFunc(keys, func(a, b labeledSeries) int { return cmp.Compare(a.labels, b.labels) })
	renderRequestMetrics(out, keys)

	const tls = "gatehouse_tls_handshakes_total"
	fmt.Fprintln(out, "# TYPE "+tls+" counter")
	for _, result := range []string{"alert_write_failed", "failed", "malformed", "ok", "passthrough", "passthrough_error", "unrecognized_name"} {
		fmt.Fprintf(out, "%s{result=%s} %d\n", tls, observability.Label(result), handshakes[result])
	}
	const deny = "gatehouse_denies_total"
	fmt.Fprintln(out, "# TYPE "+deny+" counter")
	for _, reason := range slices.Sorted(maps.Keys(denies)) {
		fmt.Fprintf(out, "%s{reason=%s} %d\n", deny, observability.Label(reason), denies[reason])
	}
}

func renderRequestMetrics(out io.Writer, keys []labeledSeries) {
	for _, metric := range []struct {
		name  string
		value func(series) uint64
	}{
		{"gatehouse_requests_total", func(s series) uint64 { return s.latency.count }},
		{"gatehouse_request_bytes_total", func(s series) uint64 { return s.bytesIn }},
		{"gatehouse_response_bytes_total", func(s series) uint64 { return s.bytesOut }},
	} {
		fmt.Fprintln(out, "# TYPE "+metric.name+" counter")
		for _, entry := range keys {
			fmt.Fprintf(out, "%s{%s} %d\n", metric.name, entry.labels, metric.value(entry.series))
		}
	}

	const latency = "gatehouse_request_duration_seconds"
	fmt.Fprintln(out, "# TYPE "+latency+" histogram")
	for _, entry := range keys {
		entry.latency.write(out, latency, entry.labels)
	}

	const upstream = "gatehouse_upstream_duration_seconds"
	fmt.Fprintln(out, "# TYPE "+upstream+" histogram")
	for _, entry := range keys {
		if entry.upstream.count != 0 {
			entry.upstream.write(out, upstream, entry.labels)
		}
	}
}

func (h *histogram) write(out io.Writer, name, labels string) {
	for i, n := range h.buckets {
		fmt.Fprintf(
			out,
			"%s_bucket{%s,le=\"%g\"} %d\n",
			name,
			labels,
			latencyBounds[i].Seconds(),
			n,
		)
	}
	fmt.Fprintf(out, "%s_bucket{%s,le=\"+Inf\"} %d\n%s_sum{%s} %g\n%s_count{%s} %d\n",
		name, labels, h.count, name, labels, h.sum, name, labels, h.count)
}
