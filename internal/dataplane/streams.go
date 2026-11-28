package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

// A host fence closes streams when their attachment or policy inputs change.
// Publish the replacement before revoking the old fence so new requests see
// the current policy. Unchanged hosts keep their established streams.
type hostFence struct {
	key     [32]byte
	mu      sync.Mutex
	revoked bool
	next    uint64
	streams map[uint64]context.CancelFunc
}

func newFence(
	cfg *config.Config, port uint16, registry config.Host, host snapshot.Host,
) *hostFence {
	input := struct {
		Host     snapshot.Host                       `json:"host"`
		Registry config.Host                         `json:"registry"`
		Port     config.Port                         `json:"port"`
		Profiles map[string]config.ClientCertProfile `json:"profiles"`
		Trust    config.DeviceTrust                  `json:"trust"`
		LAN      []config.LANBackend                 `json:"lan"`
	}{host, registry, cfg.Ports[port], cfg.ClientCertProfiles, cfg.DeviceTrust, cfg.LANBackends}
	data, err := json.Marshal(input)
	if err != nil {
		// A malformed file or controller input must never keep an old fence
		// alive accidentally. Such a host cannot establish new streams.
		return &hostFence{revoked: true}
	}
	return &hostFence{key: sha256.Sum256(data)}
}

func (f *hostFence) track(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked {
		cancel()
		return ctx, cancel
	}
	if f.streams == nil {
		f.streams = make(map[uint64]context.CancelFunc)
	}
	id := f.next
	f.next++
	f.streams[id] = cancel
	return ctx, func() {
		f.mu.Lock()
		delete(f.streams, id)
		f.mu.Unlock()
		cancel()
	}
}

func (f *hostFence) revoke() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = true
	for _, cancel := range f.streams {
		cancel()
	}
	f.streams = nil
}
