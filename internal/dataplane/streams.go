package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

// A host fence owns the streams for one port and hostname. Routing and
// attachment changes retire the fence. A trust-only change rechecks the
// authenticated streams and lets those still authorized continue.
type hostFence struct {
	key           [32]byte
	mu            sync.Mutex
	revoked       bool
	next          uint64
	streams       map[uint64]context.CancelFunc
	authKey       [32]byte
	authenticated map[streamIdentity]map[*authenticatedStream]struct{}
}

type streamIdentity struct {
	name   string
	anchor [32]byte
}

type authenticatedStream struct {
	identity streamIdentity
	route    int
	request  *http.Request
	cancel   context.CancelFunc
}

func newFence(
	cfg *config.Config, number uint16, port *edgePort, registry config.Host, host snapshot.Host,
) *hostFence {
	var authKey [32]byte
	if isMTLS(registry.Protection) {
		var err error
		authKey, err = authenticationKey(cfg, registry, host)
		if err != nil {
			return &hostFence{revoked: true}
		}
		host.ClientCA = nil
		host.Routes = slices.Clone(host.Routes)
		for i := range host.Routes {
			host.Routes[i].MTLS = nil
		}
		registry.Identities, registry.IdentityConstraints = nil, nil
	}
	input := struct {
		Host        snapshot.Host                      `json:"host"`
		Registry    config.Host                        `json:"registry"`
		Port        config.Port                        `json:"port"`
		EdgeSecrets [][32]byte                         `json:"edgeSecrets"`
		ForwardAuth map[string]config.ForwardAuthClass `json:"forwardAuth"`
		Trust       config.DeviceTrust                 `json:"trust"`
		LAN         []config.LANBackend                `json:"lan"`
	}{host, registry, cfg.Ports[number], port.hashes, cfg.ForwardAuthClasses, cfg.DeviceTrust, cfg.LANBackends}
	data, err := json.Marshal(input)
	if err != nil {
		// A malformed file or controller input must never keep an old fence
		// alive accidentally. Such a host cannot establish new streams.
		return &hostFence{revoked: true}
	}
	return &hostFence{key: sha256.Sum256(data), authKey: authKey}
}

func authenticationKey(
	cfg *config.Config,
	registry config.Host,
	host snapshot.Host,
) ([32]byte, error) {
	policies := make([]*snapshot.MTLSPolicy, len(host.Routes))
	for i, route := range host.Routes {
		policies[i] = route.MTLS
	}
	profile := cfg.ClientCertProfiles[strings.TrimPrefix(registry.Protection, "mtls:")]
	data, err := json.Marshal(struct {
		CA          []byte                               `json:"ca"`
		Profile     config.ClientCertProfile             `json:"profile"`
		Identities  []string                             `json:"identities"`
		Constraints map[string]config.IdentityConstraint `json:"constraints"`
		Policies    []*snapshot.MTLSPolicy               `json:"policies"`
	}{host.ClientCA, profile, registry.Identities, registry.IdentityConstraints, policies})
	return sha256.Sum256(data), err
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
	for _, streams := range f.authenticated {
		for stream := range streams {
			stream.cancel()
		}
	}
	f.streams = nil
	f.authenticated = nil
}

func (h *edgeHost) trackRequest(
	ctx context.Context, r *http.Request, route *route, identity streamIdentity,
) (context.Context, func()) {
	if identity.name == "" {
		return h.fence.track(ctx)
	}
	return h.fence.trackMTLS(ctx, r, h.authKey, route.position, identity)
}

func (f *hostFence) trackMTLS(
	ctx context.Context, r *http.Request, authKey [32]byte, position int, identity streamIdentity,
) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked || f.authKey != authKey {
		cancel()
		return ctx, cancel
	}
	// The route index is stable for the lifetime of the fence. The plugin only
	// needs the method, raw path, and peer TLS state to recheck authorization.
	probe := &http.Request{
		Host: r.Host, Method: r.Method, TLS: r.TLS,
		URL: &url.URL{Path: r.URL.Path, RawPath: r.URL.RawPath},
	}
	stream := &authenticatedStream{
		identity: identity, route: position, request: probe.WithContext(ctx), cancel: cancel,
	}
	f.index(stream)
	return ctx, func() {
		f.mu.Lock()
		group := f.authenticated[stream.identity]
		delete(group, stream)
		if len(group) == 0 {
			delete(f.authenticated, stream.identity)
		}
		f.mu.Unlock()
		cancel()
	}
}

func (f *hostFence) index(stream *authenticatedStream) {
	if f.authenticated == nil {
		f.authenticated = make(map[streamIdentity]map[*authenticatedStream]struct{})
	}
	group := f.authenticated[stream.identity]
	if group == nil {
		group = make(map[*authenticatedStream]struct{})
		f.authenticated[stream.identity] = group
	}
	group[stream] = struct{}{}
}

func (f *hostFence) refreshAuthentication(host *edgeHost) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.authKey == host.authKey {
		return
	}
	f.authKey = host.authKey
	previous := f.authenticated
	f.authenticated = nil
	for _, group := range previous {
		for stream := range group {
			if host.tls == nil || stream.route >= len(host.routes) {
				stream.cancel()
				continue
			}
			probe := stream.request.WithContext(stream.request.Context())
			probe.Header = make(http.Header)
			decision := &discardPolicyResponse{make(http.Header)}
			if identity, allowed := authorizeMTLS(
				decision,
				probe,
				host.routes[stream.route].mtls,
				host,
			); allowed {
				stream.identity = identity
				f.index(stream)
			} else {
				stream.cancel()
			}
		}
	}
}

type discardPolicyResponse struct{ header http.Header }

func (w *discardPolicyResponse) Header() http.Header       { return w.header }
func (*discardPolicyResponse) WriteHeader(int)             {}
func (*discardPolicyResponse) Write(p []byte) (int, error) { return len(p), nil }
