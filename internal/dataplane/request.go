package dataplane

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/oidclogin"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

var discardedLogs = log.New(io.Discard, "", 0)

func (p *Plane) serveRequest(
	number uint16,
	mode string,
	out http.ResponseWriter,
	req *http.Request,
) {
	start := time.Now()
	w := &responseWriter{ResponseWriter: out}
	record := requestRecord{listener: number, requestBytes: new(atomicCounter)}
	defer func() { p.observe(w, req, record, start) }()
	state := p.state.Load()
	if state == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	port := state.ports[number]
	if port == nil || port.mode != mode {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	record.client = requestIP(w, req, port)
	if !record.client.IsValid() {
		record.deny = "client_identity"
		if w.status == 0 {
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}
		return
	}
	if mode == redirectMode {
		redirect(w, req)
		return
	}
	p.serveTLSRequest(state, port, w, req, &record)
}

func (p *Plane) serveTLSRequest(
	state *compiled,
	port *edgePort,
	w *responseWriter,
	req *http.Request,
	record *requestRecord,
) {
	state.stripHeaders(req.Header)
	state.stripHeaders(req.Trailer)
	setForwarded(req, record.client)
	hostName := hostname(req.Host)
	registry, host := selectHost(state, port, w, req, record, hostName)
	if host == nil {
		return
	}
	path, valid := normalizedPath(req)
	if !valid {
		reject(w, record, "ambiguous_path", http.StatusBadRequest)
		return
	}
	if denied(registry.Deny, path) {
		reject(w, record, "registry_path", http.StatusForbidden)
		return
	}
	route := matchRoute(host.routes, req, path)
	if route == nil {
		route = nativeAuthRoute(registry, len(host.routes), path)
	}
	if route == nil {
		if isMTLS(registry.Protection) && len(host.routes) == 0 {
			reject(w, record, "mtls_policy", http.StatusForbidden)
		} else if strings.HasPrefix(registry.Protection, "oidc:") && len(host.routes) == 0 {
			reject(w, record, "auth_policy", http.StatusServiceUnavailable)
		} else {
			http.NotFound(w, req)
		}
		return
	}
	p.applyPolicies(state, registry, host, route, w, req, record, hostName, path)
}

func selectHost(
	state *compiled,
	port *edgePort,
	w http.ResponseWriter,
	req *http.Request,
	record *requestRecord,
	hostName string,
) (config.Host, *edgeHost) {
	registry, known := state.registry[hostName]
	sni := ""
	if req.TLS != nil {
		sni = hostname(req.TLS.ServerName)
	}
	if sni != hostName && (isMTLS(registry.Protection) || isMTLS(state.registry[sni].Protection)) {
		reject(w, record, "sni_host_mismatch", http.StatusMisdirectedRequest)
		return registry, nil
	}
	host := port.hosts[hostName]
	if !known || host == nil || host.tls == nil ||
		!slices.Contains(registry.Ports, record.listener) {
		if known && registry.Protection == "deny" {
			reject(w, record, "registry_host", http.StatusForbidden)
		} else {
			reject(w, record, "listener_host", http.StatusMisdirectedRequest)
		}
		return registry, nil
	}
	return registry, host
}

func (p *Plane) applyPolicies(
	state *compiled,
	registry config.Host,
	host *edgeHost,
	route *route,
	w *responseWriter,
	req *http.Request,
	record *requestRecord,
	hostName, path string,
) {
	record.route, record.logOff = route.rule.Name, route.rule.AccessLogOff
	if denied(route.rule.Deny, path) {
		reject(w, record, "route_path", http.StatusForbidden)
		return
	}
	if route.rule.InvalidPolicy {
		status := http.StatusServiceUnavailable
		if isMTLS(registry.Protection) {
			status = http.StatusForbidden
		}
		reject(w, record, "invalid_policy", status)
		return
	}
	if isMTLS(registry.Protection) {
		if !authorizeMTLS(w, req, route.mtls, host) {
			record.deny = "mtls_policy"
			return
		}
		record.identity = req.Header.Get(identityHeader)
		authorizeForwardedMTLS(req.Header, route.rule.MTLS)
	}
	info := RequestInfo{
		Listener:   record.listener,
		Host:       hostName,
		Protection: registry.Protection,
		Path:       path,
		ClientIP:   record.client,
		Route:      &route.rule,
	}
	crowdSecExempt := route.rule.CrowdSecExempt &&
		slices.Contains(registry.CrowdSecExemptPaths, path)
	if p.opts.CrowdSec != nil && !crowdSecExempt && !p.opts.CrowdSec(w, req, info) {
		record.deny = "crowdsec"
		return
	}
	if p.opts.Limits != nil {
		release, allowed := p.opts.Limits(w, req, info)
		if !allowed {
			record.deny = "limits"
			return
		}
		if release != nil {
			defer release()
		}
	}
	delegated, allows := state.authorizeRequest(w, req, registry, info, record)
	if !allows {
		return
	}

	p.proxyAuthorized(
		state,
		host,
		route,
		w,
		req,
		record,
		path,
		delegated,
		isMTLS(registry.Protection),
	)
}

func (p *Plane) proxyAuthorized(state *compiled, host *edgeHost, route *route, w *responseWriter,
	req *http.Request, record *requestRecord, path, delegated string, protectStream bool,
) {
	if protectStream || req.Header.Get("Upgrade") != "" {
		ctx, finish := host.fence.track(req.Context())
		defer finish()
		if ctx.Err() != nil {
			reject(w, record, "snapshot_replaced", http.StatusServiceUnavailable)
			return
		}
		req = req.WithContext(ctx)
	}
	p.proxyRequest(state, route, w, req, record, path, delegated)
}

func authorizeForwardedMTLS(header http.Header, policy *snapshot.MTLSPolicy) {
	values := map[string]string{
		identityHeader: header.Get(identityHeader),
		leafHeader:     header.Get(leafHeader),
		expiryHeader:   header.Get(expiryHeader),
	}
	for name := range values {
		header.Del(name)
	}
	if policy == nil {
		return
	}
	for _, name := range policy.ForwardHeaders {
		if value := values[snapshot.MTLSHeaderSource(name)]; value != "" {
			header.Set(name, value)
		}
	}
}

func (p *Plane) proxyRequest(
	state *compiled,
	route *route,
	w *responseWriter,
	req *http.Request,
	record *requestRecord,
	path, delegated string,
) {
	target := route.choose()
	if !target.available() {
		reject(w, record, "invalid_backend", http.StatusInternalServerError)
		return
	}
	record.backend = target.name
	// Keep the inbound request immutable for logging and authorization.
	r := req.Clone(req.Context())
	applyRewrite(r, route, path, delegated)
	if rewrite := route.rule.Rewrite; rewrite != nil && rewrite.Host != "" {
		r.Host = rewrite.Host
	}
	applyFilter(r.Header, route.rule.RequestHeaders, state.reserved)
	oidclogin.StripCookies(r.Header)
	setForwarded(r, record.client)
	r.Header.Set("X-Forwarded-Host", req.Host)
	compression := state.compression
	if route.rule.Compression != nil {
		compression = *route.rule.Compression
	}
	call := &backendRequest{
		writer:      w,
		target:      target.selectEndpoint(r),
		noRetry:     !idempotent(r.Method),
		compression: compression,
		coding:      negotiate(r.Header.Values("Accept-Encoding"), compression.Encodings),
	}
	defer func() { record.upstream = call.upstream }()
	if r.Body != nil && r.Body != http.NoBody {
		controller := http.NewResponseController(w)
		if err := controller.SetReadDeadline(time.Now().Add(target.time.RequestBody)); err == nil {
			defer resetReadDeadline(controller)
		}
		r.Body = &countedBody{ReadCloser: r.Body, size: record.requestBytes}
	}
	w.bodyDeadline = target.time.ResponseBody
	ctx := context.WithValue(req.Context(), backendKey{}, call)
	if !target.expires.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, target.expires)
		defer cancel()
	}
	target.proxy.ServeHTTP(w, r.WithContext(ctx))
}

func applyRewrite(r *http.Request, route *route, path, delegated string) {
	switch {
	case path == "/metrics" || path == "/metrics/":
		rewritePath(r, "/")
	case delegated != "":
		rewritePath(r, delegated)
	case route.rule.Rewrite != nil && route.rule.Rewrite.Path != "":
		rewrite := route.rule.Rewrite
		next := rewrite.Path
		if rewrite.Prefix {
			if suffix := strings.TrimPrefix(path, route.rule.Path); suffix != "" {
				next = strings.TrimRight(next, "/") + "/" + strings.TrimLeft(suffix, "/")
			}
		}
		rewritePath(r, next)
	}
}

func resetReadDeadline(controller *http.ResponseController) {
	//nolint:errcheck // the connection may already be closed.
	_ = controller.SetReadDeadline(time.Time{})
}

func isMTLS(protection string) bool { return strings.HasPrefix(protection, "mtls:") }

func idempotent(method string) bool {
	switch method {
	case http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodTrace,
		http.MethodPut,
		http.MethodDelete:
		return true
	}
	return false
}

func reject(w http.ResponseWriter, record *requestRecord, reason string, code int) {
	record.deny = reason
	http.Error(w, http.StatusText(code), code)
}

func redirect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
		if ip, err := netip.ParseAddr(name); err == nil && ip.Is6() {
			host = "[" + name + "]"
		}
	}
	target := r.URL.RequestURI()
	if !strings.HasPrefix(target, "/") {
		target = "/"
	}
	w.Header().Set("Location", "https://"+host+target)
	w.WriteHeader(http.StatusMovedPermanently)
}

type countedBody struct {
	io.ReadCloser

	size *atomicCounter
}

func (b *countedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.size.Add(uint64(n))
	}
	return n, err
}
