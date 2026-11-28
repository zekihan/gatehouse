// Package observability defines the telemetry shared across Gatehouse components.
package observability

import "time"

// CrowdSecMetrics describes the snapshot currently used for enforcement.
type CrowdSecMetrics struct {
	Decisions int
	Staleness time.Duration
}

// LimiterMetrics describes one replica's shared limiter. Map keys are replica
// identities and configured route identities. Providers take a read-only
// snapshot so scrapes can safely run concurrently with policy updates.
type LimiterMetrics struct {
	GossipPeers      int
	PeerStaleness    map[string]time.Duration
	Isolated         bool
	CapacityOverflow uint64
	ResyncPending    bool
	RoutePressure    map[string]float64
}

func RouteID(namespace, name string) string {
	if namespace == "" || name == "" {
		return name
	}
	return namespace + "/" + name
}
