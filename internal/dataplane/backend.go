package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

type atomicCounter = atomic.Uint64

type weighted struct {
	end   uint64
	value *backend
}

type endpoint struct {
	addr netip.AddrPort
	id   string
}

type backend struct {
	name    string
	port    uint16
	targets []endpoint
	index   atomicCounter
	cookie  string
	proxyV2 bool
	tls     *tls.Config
	expires time.Time
	time    snapshot.Deadlines
	proxy   *httputil.ReverseProxy
}

func (r *route) addBackend(
	state *compiled,
	cfg *config.Config,
	input *snapshot.Backend,
	weight uint32,
) {
	if weight == 0 {
		return
	}
	value := newBackend(cfg, input, r.rule.Deadlines, false)
	r.total += uint64(weight)
	r.backends = append(r.backends, weighted{end: r.total, value: value})
	if value != nil {
		pooled := value.transport(false)
		fresh := value.transport(true)
		state.transports = append(state.transports, pooled, fresh)
		value.proxy = value.reverseProxy(pooled, fresh, r.rule.ResponseHeaders)
	}
}

func (r *route) choose() *backend {
	if len(r.backends) == 1 {
		return r.backends[0].value
	}
	if r.total != 0 {
		point := (r.index.Add(1) - 1) % r.total
		i, _ := slices.BinarySearchFunc(r.backends, point, func(item weighted, point uint64) int {
			if item.end <= point {
				return -1
			}
			return 1
		})
		return r.backends[i].value
	}
	return nil
}

func newBackend(
	cfg *config.Config,
	input *snapshot.Backend,
	deadlines snapshot.Deadlines,
	stream bool,
) *backend {
	if input == nil || input.Port == 0 || stream && (input.TLSRequired || input.TLS != nil) ||
		!stream && input.ProxyV2 {
		return nil
	}
	b := &backend{
		name: input.Service, port: input.Port, cookie: input.StickyCookie,
		time: phaseDefaults(deadlines), proxyV2: input.ProxyV2,
	}
	if !b.initTLS(cfg.DeviceTrust, input) {
		return nil
	}
	if !b.initEndpoints(cfg.LANBackends, input) {
		return nil
	}
	return b
}

func (b *backend) initEndpoints(allows []config.LANBackend, input *snapshot.Backend) bool {
	addresses := input.Endpoints
	if input.ClusterIP != "" {
		addresses = []string{input.ClusterIP}
	}
	seen := make(map[netip.AddrPort]bool)
	for _, value := range addresses {
		addr, err := netip.ParseAddrPort(value)
		if err != nil || addr.Port() == 0 || addr.Addr().Zone() != "" ||
			addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() {
			return false
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		if input.LAN && !allowedLAN(allows, addr) {
			return false
		}
		if !seen[addr] {
			seen[addr] = true
			hash := sha256.Sum256([]byte(addr.String()))
			b.targets = append(b.targets, endpoint{addr: addr, id: hex.EncodeToString(hash[:8])})
		}
	}
	return len(b.targets) != 0
}

func (b *backend) initTLS(trust config.DeviceTrust, input *snapshot.Backend) bool {
	var exception *config.DeviceException
	for i := range trust.Exceptions {
		candidate := &trust.Exceptions[i]
		if candidate.Service == input.Service && candidate.Port == input.Port {
			if exception != nil {
				return false
			}
			exception = candidate
		}
	}
	if !input.TLSRequired {
		return input.TLS == nil && exception == nil
	}
	if (input.TLS == nil) == (exception == nil) {
		return false
	}
	b.tls = &tls.Config{MinVersion: tls.VersionTLS12}
	if exception != nil {
		expires, err := time.Parse(time.DateOnly, exception.Expires)
		if err != nil {
			return false
		}
		b.expires = expires
		b.tls.InsecureSkipVerify = true // operator-owned, expiring device exception
		return true
	}
	pool := x509.NewCertPool()
	if input.TLS.ServerName == "" || !pool.AppendCertsFromPEM(input.TLS.CAPEM) {
		return false
	}
	b.tls.RootCAs, b.tls.ServerName = pool, input.TLS.ServerName
	return true
}

func allowedLAN(allows []config.LANBackend, addr netip.AddrPort) bool {
	for _, allow := range allows {
		prefix, err := netip.ParsePrefix(allow.CIDR)
		if err == nil && prefix.Contains(addr.Addr()) && slices.Contains(allow.Ports, addr.Port()) {
			return true
		}
	}
	return false
}

func (b *backend) available() bool {
	return b != nil && (b.expires.IsZero() || time.Now().Before(b.expires))
}

func phaseDefaults(d snapshot.Deadlines) snapshot.Deadlines {
	for _, v := range []*time.Duration{&d.Dial, &d.TLS, &d.RequestBody, &d.ResponseHeader, &d.ResponseBody, &d.UpgradeIdle} {
		if *v <= 0 {
			*v = defaultDeadline
		}
	}
	return d
}

func (b *backend) selectEndpoint(r *http.Request) endpoint {
	if b.cookie != "" {
		if cookie, err := r.Cookie(b.cookie); err == nil {
			for _, target := range b.targets {
				if target.id == cookie.Value {
					return target
				}
			}
		}
	}
	return b.nextEndpoint()
}

func (b *backend) nextEndpoint() endpoint {
	if len(b.targets) == 1 {
		return b.targets[0]
	}
	return b.targets[(b.index.Add(1)-1)%uint64(len(b.targets))]
}

func (b *backend) dialStream(ctx context.Context, source, dest netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, b.time.Dial)
	defer cancel()
	d := net.Dialer{KeepAlive: 30 * time.Second}
	var err error
	for range len(b.targets) {
		target := b.nextEndpoint()
		var conn net.Conn
		conn, err = d.DialContext(ctx, "tcp", target.addr.String())
		if err == nil {
			if b.proxyV2 {
				if err := sendProxyV2(conn, source, dest, b.time.Dial); err != nil {
					_ = conn.Close()
					return nil, err
				}
			}
			return conn, nil
		}
	}
	return nil, err
}

func sendProxyV2(conn net.Conn, source, dest netip.AddrPort, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := writeProxyV2(conn, source, dest); err != nil {
		return err
	}
	return conn.SetWriteDeadline(time.Time{})
}

func (b *backend) transport(fresh bool) *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: b.time.Dial, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       b.tls,
		TLSHandshakeTimeout:   b.time.TLS,
		ResponseHeaderTimeout: b.time.ResponseHeader,
		DisableCompression:    true,
		DisableKeepAlives:     fresh,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
	}
}

type backendRequest struct {
	target      endpoint
	writer      *responseWriter
	noRetry     bool
	upstream    time.Duration
	compression config.Compression
	coding      string
}

type backendKey struct{}

var buffers = new(proxyBuffers)

type proxyBuffers struct{ pool sync.Pool }

const bufferSize = 32 << 10

func (p *proxyBuffers) Get() []byte {
	if b, ok := p.pool.Get().(*[bufferSize]byte); ok {
		return b[:]
	}
	return make([]byte, bufferSize)
}

func (p *proxyBuffers) Put(b []byte) {
	if cap(b) >= bufferSize {
		p.pool.Put((*[bufferSize]byte)(b[:bufferSize]))
	}
}

func (b *backend) reverseProxy(
	pooled, fresh *http.Transport,
	headers snapshot.HeaderFilter,
) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		BufferPool: buffers,
		Rewrite: func(pr *httputil.ProxyRequest) {
			state := requestBackend(pr.In)
			pr.Out.URL.Scheme = "http"
			if b.tls != nil {
				pr.Out.URL.Scheme = "https"
			}
			pr.Out.URL.Host = state.target.addr.String()
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			for header, values := range pr.In.Header {
				if stringsHasOwnedPrefix(header) {
					pr.Out.Header[header] = values
				}
			}
		},
		Transport: roundTripper{backend: b, pooled: pooled, fresh: fresh},
		ModifyResponse: func(resp *http.Response) error {
			applyFilter(resp.Header, headers, nil)
			if b.cookie != "" && resp.StatusCode >= 200 && resp.StatusCode < 400 {
				state := requestBackend(resp.Request)
				resp.Header.Add("Set-Cookie", (&http.Cookie{
					Name: b.cookie, Value: state.target.id, Path: "/", Secure: true, HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				}).String())
			}
			state := requestBackend(resp.Request)
			if resp.StatusCode == http.StatusSwitchingProtocols {
				upstream, ok := resp.Body.(io.ReadWriteCloser)
				if !ok {
					return errors.New("missing bidirectional upgrade body")
				}
				securityHeaders(resp.Header)
				stream := newIdleStream(upstream, b.time.UpgradeIdle)
				state.writer.upgrade = stream
				resp.Body = stream
				return nil
			}
			return compressResponse(resp, state.compression, state.coding)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var timeout net.Error
			status := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) ||
				(errors.As(err, &timeout) && timeout.Timeout()) {
				status = http.StatusGatewayTimeout
			}
			http.Error(w, http.StatusText(status), status)
		},
		ErrorLog: discardedLogs,
	}
}

func requestBackend(r *http.Request) *backendRequest {
	state, ok := r.Context().Value(backendKey{}).(*backendRequest)
	if !ok {
		panic("data plane request missing backend state")
	}
	return state
}

func listenerName(port uint16) string { return strconv.Itoa(int(port)) }

// roundTripper advances to another endpoint only when no connection could be
// made. Once connected, the standard transport owns stale-connection retries.
type roundTripper struct {
	backend       *backend
	pooled, fresh *http.Transport
}

func (t roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	state := requestBackend(r)
	transport := t.pooled
	if state.noRetry {
		transport = t.fresh
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer func() { state.upstream = time.Since(start) }()
	r = r.WithContext(ctx)
	if r.Body != nil {
		// ReverseProxy owns the original body. A failed dial must not close
		// it before the next endpoint can try to send it.
		r.Body = io.NopCloser(r.Body)
	}
	first := state.target
	var err error
	for attempt := range len(t.backend.targets) {
		if attempt != 0 {
			index := slices.Index(t.backend.targets, first)
			state.target = t.backend.targets[(index+attempt)%len(t.backend.targets)]
			r.URL.Host = state.target.addr.String()
		}
		var resp *http.Response
		resp, err = transport.RoundTrip(r)
		if err == nil {
			if resp.StatusCode == http.StatusSwitchingProtocols {
				if body, ok := resp.Body.(io.ReadWriteCloser); ok {
					resp.Body = &upgradeBody{ReadWriteCloser: body, cancel: cancel}
					return resp, nil
				}
			}
			timer := time.AfterFunc(t.backend.time.ResponseBody, cancel)
			resp.Body = &phaseBody{ReadCloser: resp.Body, cancel: cancel, timer: timer}
			return resp, nil
		}
		var op *net.OpError
		if !errors.As(err, &op) || op.Op != "dial" || ctx.Err() != nil {
			break
		}
	}
	cancel()
	return nil, err
}

type phaseBody struct {
	io.ReadCloser

	timer  *time.Timer
	cancel context.CancelFunc
}

func (b *phaseBody) Close() error {
	b.timer.Stop()
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

type upgradeBody struct {
	io.ReadWriteCloser

	cancel context.CancelFunc
}

func (b *upgradeBody) Close() error {
	b.cancel()
	return b.ReadWriteCloser.Close()
}

type idleStream struct {
	io.ReadWriteCloser

	mu         sync.Mutex
	timer      *time.Timer
	idle       time.Duration
	once       sync.Once
	downstream net.Conn
}

func newIdleStream(stream io.ReadWriteCloser, idle time.Duration) *idleStream {
	s := &idleStream{ReadWriteCloser: stream, idle: idle}
	s.mu.Lock()
	s.timer = time.AfterFunc(idle, func() { _ = s.Close() })
	s.mu.Unlock()
	return s
}

func (s *idleStream) Read(p []byte) (int, error) {
	n, err := s.ReadWriteCloser.Read(p)
	s.touch(n)
	return n, err
}

func (s *idleStream) Write(p []byte) (int, error) {
	n, err := s.ReadWriteCloser.Write(p)
	s.touch(n)
	return n, err
}

func (s *idleStream) Close() error {
	var err error
	s.once.Do(func() {
		s.mu.Lock()
		s.timer.Stop()
		s.timer = nil
		if s.downstream != nil {
			_ = s.downstream.Close()
		}
		s.mu.Unlock()
		err = s.ReadWriteCloser.Close()
	})
	return err
}

func (s *idleStream) attach(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer == nil {
		_ = conn.Close()
		return
	}
	s.downstream = conn
}

func (s *idleStream) touch(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil && n > 0 {
		s.timer.Reset(s.idle)
	}
}
