package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	mtls "github.com/zekihan/traefik-mtls-authz"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/oidclogin"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

const (
	identityHeader = "X-Mtls-Identity"
	leafHeader     = "X-Mtls-Fingerprint"
	expiryHeader   = "X-Mtls-Not-After"
)

type mtlsPolicy struct {
	handler http.Handler
	anchors []string
}

func compileMTLS(host config.Host, route snapshot.Route) *mtlsPolicy {
	rule := route.MTLS
	if rule == nil {
		return nil
	}
	prefix := rule.IdentityPrefix
	want := "urn:noqer:mtls:" + strings.TrimPrefix(host.Protection, "mtls:") + ":"
	if prefix == "" {
		prefix = want
	}
	if prefix != want {
		return nil
	}
	identities, constraints := allowedIdentities(host, rule)
	blocked := make([]any, 0, len(rule.BlockedFingerprints))
	for _, fp := range rule.BlockedFingerprints {
		blocked = append(blocked, map[string]any{"fingerprint": fp})
	}
	policy := map[string]any{
		"schemaVersion":            1,
		"app":                      route.Namespace + "/" + route.Name,
		"identityPrefix":           prefix,
		"trustedIssuers":           rule.TrustedAnchors,
		"identities":               identities,
		"disabledIdentities":       append([]string{}, rule.DisabledIdentities...),
		"blockedFingerprints":      blocked,
		"constraints":              constraints,
		"forwardIdentityHeader":    identityHeader,
		"forwardFingerprintHeader": leafHeader,
		"forwardNotAfterHeader":    expiryHeader,
	}
	plugin := map[string]any{"policy": policy}
	handler, err := mtls.New(
		context.Background(),
		http.HandlerFunc(acceptMTLS),
		&plugin,
		route.Name,
	)
	if err != nil {
		return nil
	}
	return &mtlsPolicy{handler: handler, anchors: rule.TrustedAnchors}
}

func allowedIdentities(
	host config.Host,
	rule *snapshot.MTLSPolicy,
) ([]string, map[string]config.IdentityConstraint) {
	identities := make([]string, 0, len(rule.Identities))
	constraints := make(map[string]config.IdentityConstraint)
	for _, identity := range rule.Identities {
		if !slices.Contains(host.Identities, identity) {
			continue
		}
		registry, restricted := host.IdentityConstraints[identity]
		local, narrowed := rule.Constraints[identity]
		if restricted && narrowed {
			local.Methods = intersection(registry.Methods, local.Methods)
			local.Paths = intersection(registry.Paths, local.Paths)
		} else if restricted {
			local = registry
		}
		if restricted || narrowed {
			if len(local.Methods) == 0 || len(local.Paths) == 0 {
				continue
			}
			constraints[identity] = local
		}
		identities = append(identities, identity)
	}
	return identities, constraints
}

func intersection(a, b []string) []string {
	var out []string
	for _, item := range a {
		if slices.Contains(b, item) {
			out = append(out, item)
		}
	}
	return out
}

type mtlsKey struct{}

func acceptMTLS(_ http.ResponseWriter, r *http.Request) {
	if accepted, ok := r.Context().Value(mtlsKey{}).(*bool); ok {
		*accepted = true
	}
}

func authorizeMTLS(
	w http.ResponseWriter,
	r *http.Request,
	policy *mtlsPolicy,
	host *edgeHost,
) (streamIdentity, bool) {
	if policy == nil || host.tls == nil || r.TLS == nil || r.TLS.Version < host.tls.MinVersion ||
		len(r.TLS.VerifiedChains) == 0 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return streamIdentity{}, false
	}
	state := *r.TLS
	if original, ok := r.Context().Value(connKey{}).(*sourceConn); ok &&
		original.trustKey != host.authKey {
		state.VerifiedChains = original.verify(r, host)
	}
	var accepted bool
	probe := r.WithContext(context.WithValue(r.Context(), mtlsKey{}, &accepted))
	probe.TLS = &state
	now := time.Now()
	policy.handler.ServeHTTP(w, probe)
	if !accepted {
		return streamIdentity{}, false
	}
	return streamIdentity{
		name:   r.Header.Get(identityHeader),
		anchor: policy.acceptedAnchor(state.VerifiedChains, now),
	}, true
}

// The plugin forwards the leaf facts but does not expose its selected anchor.
// It chooses the first pinned chain valid within its 60-second clock skew.
func (p *mtlsPolicy) acceptedAnchor(chains [][]*x509.Certificate, now time.Time) [32]byte {
	for _, chain := range chains {
		fp := sha256.Sum256(chain[len(chain)-1].Raw)
		if slices.Contains(p.anchors, hex.EncodeToString(fp[:])) &&
			!slices.ContainsFunc(chain, func(cert *x509.Certificate) bool {
				return now.Before(cert.NotBefore.Add(-time.Minute)) ||
					now.After(cert.NotAfter.Add(time.Minute))
			}) {
			return fp
		}
	}
	return [32]byte{}
}

func (c *sourceConn) verify(r *http.Request, host *edgeHost) [][]*x509.Certificate {
	c.verifyMu.Lock()
	defer c.verifyMu.Unlock()
	if c.verifyDigest == host.snapshotDigest && c.verifyKey == host.authKey {
		return c.verified
	}
	peer := r.TLS.PeerCertificates
	roots := host.tls.ClientCAs
	var chains [][]*x509.Certificate
	if len(peer) != 0 && roots != nil {
		intermediates := x509.NewCertPool()
		for _, cert := range peer[1:] {
			intermediates.AddCert(cert)
		}
		var err error
		chains, err = peer[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			chains = nil
		}
	}
	c.verifyDigest, c.verifyKey, c.verified = host.snapshotDigest, host.authKey, chains
	return chains
}

var authTransport = &http.Transport{
	DisableCompression:    true,
	ResponseHeaderTimeout: defaultDeadline,
	TLSHandshakeTimeout:   defaultDeadline,
}

type authResult struct {
	delegation *config.Delegation
	strip      []string
}

func (a authResult) stripCredentials(h http.Header) {
	for _, name := range a.strip {
		deleteHeader(h, config.FoldHeader(name))
	}
}

func (s *compiled) forward(
	w http.ResponseWriter,
	r *http.Request,
	class string,
) (authResult, bool) {
	cfg, ok := s.forwardAuth[class]
	if !ok {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return authResult{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultDeadline)
	defer cancel()
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Address, nil)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return authResult{}, false
	}
	for _, name := range cfg.RequestHeaders {
		if !s.reserved(name) {
			for _, value := range r.Header.Values(name) {
				probe.Header.Add(name, value)
			}
		}
	}
	oidclogin.StripCookies(probe.Header)
	for _, name := range []string{"X-Real-Ip", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"} {
		probe.Header[name] = r.Header[name]
	}
	probe.Header.Set("X-Forwarded-Uri", r.RequestURI)
	probe.Header.Set("X-Forwarded-Method", r.Method)
	if !checkForwardResponse(w, probe, cfg.MaxResponseBytes) {
		return authResult{}, false
	}
	result := authResult{strip: cfg.StripAfter}
	result.stripCredentials(r.Header)
	result.stripCredentials(r.Trailer)
	return result, true
}

func checkForwardResponse(w http.ResponseWriter, probe *http.Request, maxBytes int) bool {
	resp, err := authTransport.RoundTrip(probe)
	if err == nil {
		defer resp.Body.Close()
		var n int64
		n, err = io.Copy(io.Discard, io.LimitReader(resp.Body, int64(maxBytes)+1))
		if n > int64(maxBytes) {
			err = errors.New("forward auth body exceeds limit")
		}
	}
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := resp.StatusCode
		if status != http.StatusUnauthorized && status != http.StatusForbidden {
			status = http.StatusServiceUnavailable
		}
		if challenge := resp.Header.Get(
			"WWW-Authenticate",
		); status == http.StatusUnauthorized &&
			challenge != "" {
			w.Header().Set("WWW-Authenticate", challenge)
		}
		http.Error(w, http.StatusText(status), status)
		return false
	}
	return true
}

func (s *compiled) authorize(
	w http.ResponseWriter, req *http.Request, registry config.Host, info RequestInfo,
) (authResult, bool) {
	kind, class, _ := strings.Cut(registry.Protection, ":")
	if kind == "oidcCallback" {
		s.oidc[class].Callback(w, req, info.Host, info.Path, time.Now())
		return authResult{}, false
	}
	if kind == "oidc" && isAuthPath(info.Path) {
		return authResult{}, s.oidc[class].Authorize(w, req, info.Host, info.Path, time.Now())
	}
	rule := info.Route
	grant, delegated := delegatedPath(registry, info.Path, req.Method)
	if grant != nil {
		return s.authorizeDelegation(w, req, grant, info)
	}
	if rule.Namespace != "" && rule.Namespace != registry.Namespace {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return authResult{}, false
	}
	if rule.ForwardAuth != "" {
		return s.authorizeException(w, req, registry, info)
	}
	if delegated {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return authResult{}, false
	}
	if kind == "oidc" {
		return authResult{}, s.oidc[class].Authorize(w, req, info.Host, info.Path, time.Now())
	}
	return authResult{}, true
}

func (s *compiled) authorizeRequest(
	w *responseWriter,
	req *http.Request,
	registry config.Host,
	info RequestInfo,
	record *requestRecord,
) (authResult, bool) {
	result, allowed := s.authorize(w, req, registry, info)
	if !allowed && (w.status == 0 || w.status >= http.StatusBadRequest) {
		record.deny = "auth"
	}
	if allowed && strings.HasPrefix(registry.Protection, "oidc:") {
		record.identity = req.Header.Get("X-Auth-Request-User")
	}
	return result, allowed
}

func isAuthPath(path string) bool {
	return path == oidclogin.SignInPath || path == oidclogin.SignOutPath
}

func nativeAuthRoute(registry config.Host, routes int, path string) *route {
	kind, _, _ := strings.Cut(registry.Protection, ":")
	if kind == "oidcCallback" || (kind == "oidc" && routes > 0 && isAuthPath(path)) {
		return &route{rule: snapshot.Route{
			Namespace: registry.Namespace, Name: "gatehouse-oidc", Path: path, Exact: true,
		}}
	}
	return nil
}

func delegatedPath(registry config.Host, path, method string) (*config.Delegation, bool) {
	reserved := false
	for i := range registry.Delegate {
		grant := &registry.Delegate[i]
		if !slices.Contains(grant.Paths, path) {
			continue
		}
		if slices.Contains(grant.Methods, method) {
			return grant, true
		}
		reserved = true
	}
	return nil, reserved
}

func (s *compiled) authorizeDelegation(
	w http.ResponseWriter,
	req *http.Request,
	grant *config.Delegation,
	info RequestInfo,
) (authResult, bool) {
	if grant.Namespace == info.Route.Namespace && exactGrantMatch(req, info) &&
		grant.ForwardAuth == info.Route.ForwardAuth {
		result, allowed := s.forward(w, req, grant.ForwardAuth)
		result.delegation = grant
		return result, allowed
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
	return authResult{}, false
}

func (s *compiled) authorizeException(
	w http.ResponseWriter,
	req *http.Request,
	registry config.Host,
	info RequestInfo,
) (authResult, bool) {
	if info.Route.Namespace != registry.Namespace {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return authResult{}, false
	}
	for _, ex := range registry.Exceptions {
		if ex.ForwardAuth == info.Route.ForwardAuth && ex.Path == info.Path &&
			exactGrantMatch(req, info) && slices.Contains(ex.Methods, req.Method) {
			return s.forward(w, req, info.Route.ForwardAuth)
		}
	}
	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	return authResult{}, false
}

func exactGrantMatch(req *http.Request, info RequestInfo) bool {
	return info.Route.Exact && info.Route.Path == info.Path &&
		info.Route.Method == req.Method && req.URL.EscapedPath() == info.Path
}

func applyFilter(h http.Header, filter snapshot.HeaderFilter, reserved func(string) bool) {
	valid := func(name string) bool {
		if reserved != nil && reserved(name) {
			return false
		}
		switch config.FoldHeader(name) {
		case "connection",
			"keep-alive",
			"proxy-connection",
			"te",
			"trailer",
			"transfer-encoding",
			"upgrade",
			"host",
			"content-length":
			return false
		}
		return true
	}
	for _, name := range filter.Remove {
		if valid(name) {
			h.Del(name)
		}
	}
	for name, value := range filter.Set {
		if valid(name) {
			h.Set(name, value)
		}
	}
	for name, value := range filter.Add {
		if valid(name) {
			h.Add(name, value)
		}
	}
}

func stringsHasOwnedPrefix(header string) bool {
	switch header {
	case "X-Real-Ip", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Groups":
		return true
	}
	return snapshot.MTLSHeaderSource(header) != ""
}
