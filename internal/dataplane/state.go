package dataplane

import (
	"maps"
	"slices"

	"github.com/zekihan/gatehouse/internal/observability"
)

func (p *Plane) State() observability.State {
	out := observability.State{
		Ready: p.serving.Load() && p.Ready(), Listeners: []observability.ListenerState{},
	}
	if current := p.state.Load(); current != nil {
		out.SnapshotDigest = current.digest
		out.DeviceTLSExceptions = current.deviceTLSExceptions
		out.Listeners = make([]observability.ListenerState, 0, len(current.ports))
		for _, number := range slices.Sorted(maps.Keys(current.ports)) {
			out.Listeners = append(out.Listeners, observability.ListenerState{
				Port: number, Mode: current.ports[number].mode,
				OpenConnections: p.metrics.openConnections(number),
			})
		}
	}
	return out
}
