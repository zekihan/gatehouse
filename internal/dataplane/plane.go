// Package dataplane serves immutable Gatehouse snapshots.
package dataplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

const (
	defaultDeadline = 300 * time.Second
	redirectMode    = "redirect"
)

var groups = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP384, tls.CurveP521}

type RequestInfo struct {
	Listener   uint16
	Host       string
	Protection string
	Path       string
	ClientIP   netip.Addr
	Route      *snapshot.Route
}

// Options connects independently managed request policies to the data plane.
// Policies return false after writing a refusal. A nil OIDC hook fails closed.
type Options struct {
	OnListening func()
	AccessLog   io.Writer
	CrowdSec    func(http.ResponseWriter, *http.Request, RequestInfo) bool
	Limits      func(http.ResponseWriter, *http.Request, RequestInfo) (release func(), allowed bool)
	OIDC        func(http.ResponseWriter, *http.Request, RequestInfo) bool
}

type Plane struct {
	opts     Options
	state    atomic.Pointer[compiled]
	updateMu sync.Mutex
	metrics  metrics
	logMu    sync.Mutex
}

type compiled struct {
	digest      string
	ports       map[uint16]*edgePort
	registry    map[string]config.Host
	edgeHeaders map[string]bool
	forwardAuth map[string]config.ForwardAuthClass
	compression config.Compression
	transports  []*http.Transport
}

type edgePort struct {
	mode     string
	identity string
	trusted  []netip.Prefix
	secret   string
	hashes   [][32]byte
	resolver http.Handler
	hosts    map[string]*edgeHost
}

func (p *edgePort) trusts(ip netip.Addr) bool {
	return slices.ContainsFunc(p.trusted, func(prefix netip.Prefix) bool {
		return prefix.Contains(ip)
	})
}

type edgeHost struct {
	fence          *hostFence
	authKey        [32]byte
	snapshotDigest string
	tls            *tls.Config
	passthrough    *backend
	routes         []*route
}

func New(opts Options) *Plane {
	return &Plane{opts: opts}
}

// Update compiles and activates a snapshot. Invalid app objects are denied at
// their existing match, so they cannot expose a broader route.
func (p *Plane) Update(input *snapshot.Snapshot) error {
	if input == nil || input.Config == nil || input.DataPlane == nil {
		return errors.New("operator configuration and data plane are required")
	}
	p.updateMu.Lock()
	defer p.updateMu.Unlock()
	old := p.state.Load()
	if old != nil && input.Digest != "" && old.digest == input.Digest {
		return nil
	}
	next := &compiled{
		digest: input.Digest, ports: make(map[uint16]*edgePort), registry: input.Config.Hosts,
		edgeHeaders: make(map[string]bool), forwardAuth: input.Config.ForwardAuthClasses,
		compression: input.Config.Defaults.Compression,
	}
	for number, options := range input.Config.Ports {
		port, err := newPort(options, input.DataPlane.EdgeSecrets)
		if err != nil {
			return fmt.Errorf("listener %d: %w", number, err)
		}
		if port.secret != "" {
			next.edgeHeaders[config.FoldHeader(port.secret)] = true
		}
		next.ports[number] = port
	}
	next.compileHosts(input, old)
	p.state.Store(next)
	if old != nil {
		old.revokeChanged(next)
		for _, transport := range old.transports {
			transport.CloseIdleConnections()
		}
	}
	return nil
}

func (s *compiled) compileHosts(input *snapshot.Snapshot, old *compiled) {
	for number, port := range s.ports {
		if port.mode == redirectMode {
			continue
		}
		hosts := input.DataPlane.Hosts
		if input.DataPlane.Ports != nil {
			hosts = input.DataPlane.Ports[number]
		}
		for name, host := range hosts {
			registry, ok := s.registry[name]
			if !ok || registry.Protection == "deny" || !slices.Contains(registry.Ports, number) {
				continue
			}
			compiled := s.compileHost(input.Config, name, registry, host)
			compiled.fence = newFence(input.Config, number, port, registry, host)
			compiled.authKey = compiled.fence.authKey
			compiled.snapshotDigest = s.digest
			previous := old.host(number, name)
			if previous != nil && previous.fence.key == compiled.fence.key &&
				!compiled.fence.revoked {
				compiled.fence = previous.fence
			}
			port.hosts[name] = compiled
		}
	}
}

func (s *compiled) host(port uint16, name string) *edgeHost {
	if s != nil && s.ports[port] != nil {
		return s.ports[port].hosts[name]
	}
	return nil
}

func (s *compiled) revokeChanged(next *compiled) {
	for number, port := range s.ports {
		for name, host := range port.hosts {
			current := next.host(number, name)
			if current == nil || current.fence != host.fence {
				host.fence.revoke()
			} else if host.authKey != current.authKey {
				host.fence.refreshAuthentication(current)
			}
		}
	}
}

func (s *compiled) compileHost(
	cfg *config.Config,
	name string,
	registry config.Host,
	input snapshot.Host,
) *edgeHost {
	h := new(edgeHost)
	if input.Passthrough != nil {
		if registry.Protection == "public" && registry.Deny == nil &&
			len(registry.Exceptions) == 0 &&
			len(registry.Delegate) == 0 &&
			input.Certificate == nil {
			h.passthrough = newBackend(cfg, input.Passthrough, snapshot.Deadlines{}, true)
		}
		return h
	}

	if input.Certificate != nil {
		h.tls = makeTLS(cfg, name, registry, input)
	}
	if h.tls == nil {
		return h
	}
	for _, rule := range input.Routes {
		r := s.compileRoute(cfg, registry, rule)
		h.routes = append(h.routes, r)
	}
	sortRoutes(h.routes)
	for i, route := range h.routes {
		route.position = i
	}
	return h
}

func makeTLS(
	cfg *config.Config,
	name string,
	registry config.Host,
	host snapshot.Host,
) *tls.Config {
	cert, err := tls.X509KeyPair(host.Certificate.CertPEM, host.Certificate.KeyPEM)
	if err != nil {
		return nil
	}
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil
		}
	}
	public, ok := cert.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() || cert.Leaf.VerifyHostname(name) != nil {
		return nil
	}
	out := &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		CurvePreferences: groups, NextProtos: []string{"h2", "http/1.1"},
	}
	if profileName, ok := strings.CutPrefix(registry.Protection, "mtls:"); ok {
		profile, ok := cfg.ClientCertProfiles[profileName]
		if !ok {
			return nil
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(host.ClientCA) {
			return nil
		}
		out.ClientCAs = pool
		out.ClientAuth = tls.RequireAndVerifyClientCert
		out.SessionTicketsDisabled = !profile.SessionTickets
		if profile.MinVersion == "1.3" {
			out.MinVersion = tls.VersionTLS13
		}
	}
	return out
}

func (h *edgeHost) tlsAvailable(now time.Time) bool {
	if h == nil || h.tls == nil {
		return false
	}
	leaf := h.tls.Certificates[0].Leaf
	return !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}

// Serve binds the operator's configured ports and serves until canceled.
// The controller can update request policy and trust through Update.
func (p *Plane) Serve(ctx context.Context, bindIP string) error {
	state := p.state.Load()
	if state == nil || len(state.ports) == 0 {
		return errors.New("no snapshot listeners")
	}
	listeners := make(map[uint16]net.Listener, len(state.ports))
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for number := range state.ports {
		addr := net.JoinHostPort(bindIP, strconv.Itoa(int(number)))
		var cfg net.ListenConfig
		listener, err := cfg.Listen(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("bind %s: %w", addr, err)
		}
		listeners[number] = listener
	}

	if p.opts.OnListening != nil {
		p.opts.OnListening()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(listeners))
	var workers sync.WaitGroup
	defer workers.Wait()
	for number, listener := range listeners {
		mode := state.ports[number].mode
		workers.Go(func() { results <- p.serve(ctx, number, mode, listener) })
	}
	err := <-results
	cancel()
	return err
}

func (p *Plane) serve(
	ctx context.Context,
	number uint16,
	mode string,
	listener net.Listener,
) error {
	l := wrapListener(ctx, listener, p, number, mode)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.serveRequest(number, mode, w, r)
		}),
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            handshakeTimeout,
		IdleTimeout:                  defaultDeadline,
		ErrorLog:                     log.New(io.Discard, "", 0),
		ConnContext:                  connContext,
		BaseContext:                  func(net.Listener) context.Context { return ctx },
	}
	if mode != redirectMode {
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}
	}
	stop := context.AfterFunc(ctx, func() {
		_ = l.Close()
		_ = server.Close()
	})
	defer stop()
	err := server.Serve(l)
	if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type connKey struct{}

func connContext(ctx context.Context, c net.Conn) context.Context {
	if secure, ok := c.(*tls.Conn); ok {
		c = secure.NetConn()
	}
	if source, ok := c.(*sourceConn); ok {
		return context.WithValue(ctx, connKey{}, source)
	}
	return ctx
}
