package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	realip "github.com/zekihan/traefik-real-ip"

	"github.com/zekihan/gatehouse/internal/config"
)

func newPort(cfg config.Port, secrets map[string]map[string]string) (*edgePort, error) {
	p := &edgePort{mode: cfg.Mode, identity: cfg.Identity, hosts: make(map[string]*edgeHost)}
	for _, value := range cfg.TrustedCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, errors.New("invalid trusted CIDR")
		}
		p.trusted = append(p.trusted, prefix)
	}
	if cfg.Identity == "cloudflare" && cfg.EdgeSecret != nil {
		p.secret = cfg.EdgeSecret.Header
		for _, key := range cfg.EdgeSecret.Keys {
			if secret := strings.TrimSpace(
				secrets[cfg.EdgeSecret.Secret][key],
			); len(secret) >= 16 &&
				!strings.ContainsAny(secret, "\r\n") {
				p.hashes = append(p.hashes, sha256.Sum256([]byte(secret)))
			}
		}
		plugin := &realip.Config{
			ScopedTrust: true, DenyUntrusted: true, CloudflareTrustedIPs: cfg.TrustedCIDRs,
			XForwardedForMode: realip.XForwardedForModeReplace,
			PanicPolicy:       realip.PanicPolicyPropagate,
			LogLevel:          "error",
		}
		resolver, err := realip.New(
			context.Background(),
			http.HandlerFunc(saveCloudflareIP),
			plugin,
			"gatehouse",
		)
		if err != nil {
			return nil, err
		}
		p.resolver = resolver
	}
	return p, nil
}

type edgeIPKey struct{}

func saveCloudflareIP(_ http.ResponseWriter, r *http.Request) {
	out, ok := r.Context().Value(edgeIPKey{}).(*netip.Addr)
	resolved, err := netip.ParseAddr(r.Header.Get(realip.XRealIP))
	if ok && err == nil {
		*out = resolved
	}
}

func requestIP(w http.ResponseWriter, r *http.Request, port *edgePort) netip.Addr {
	addr, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := addr.Addr().WithZone("").Unmap()
	source, hasSource := r.Context().Value(connKey{}).(*sourceConn)
	if hasSource && source.identity != port.identity {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return netip.Addr{}
	}
	switch port.identity {
	case "direct":
		return ip
	case "proxyProtocol":
		if hasSource && port.trusts(source.socket) {
			return ip
		}
	case "cloudflare":
		return port.cloudflareIP(w, r, ip)
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
	return netip.Addr{}
}

func (p *edgePort) cloudflareIP(
	w http.ResponseWriter,
	r *http.Request,
	peer netip.Addr,
) netip.Addr {
	if !p.trusts(peer) || p.resolver == nil ||
		nominated(r.Header, p.secret) || nominated(r.Header, realip.CfConnectingIP) ||
		!p.validSecret(
			r.Header.Values(p.secret),
		) || len(r.Header.Values(realip.CfConnectingIP)) == 0 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return netip.Addr{}
	}
	var ip netip.Addr
	p.resolver.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), edgeIPKey{}, &ip)))
	return ip
}

func (p *edgePort) validSecret(values []string) bool {
	if len(values) != 1 {
		return false
	}
	hash := sha256.Sum256([]byte(values[0]))
	ok := 0
	for _, secret := range p.hashes {
		ok |= subtle.ConstantTimeCompare(hash[:], secret[:])
	}
	return ok == 1
}

func foldHeader(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

func (s *compiled) reserved(name string) bool {
	folded := foldHeader(name)
	switch folded {
	case "x-real-ip", "remote-user", "remote-email", "remote-groups", "remote-name",
		"forwarded", "cf-connecting-ip", "cf-connecting-ipv6", "cf-pseudo-ipv4",
		"eo-connecting-ip", "true-client-ip", "x-client-ip", "x-cluster-client-ip",
		"x-original-forwarded-for", "fastly-client-ip", "x-is-trusted",
		"x-noqer-edge-auth":
		return true
	}
	return s.edgeHeaders[folded] || strings.HasPrefix(folded, "x-forwarded-") ||
		strings.HasPrefix(folded, "x-auth-request-") || strings.HasPrefix(folded, "x-authentik-") ||
		strings.HasPrefix(folded, "x-mtls-")
}

func nominated(headers http.Header, name string) bool {
	key := foldHeader(name)
	for _, line := range headers.Values("Connection") {
		for option := range strings.SplitSeq(line, ",") {
			if foldHeader(strings.TrimSpace(option)) == key {
				return true
			}
		}
	}
	return false
}

func (s *compiled) stripHeaders(h http.Header) {
	// Keep the protocol's upgrade negotiation, while removing any arbitrary
	// headers that the client nominates as connection-specific.
	for _, line := range h.Values("Connection") {
		for option := range strings.SplitSeq(line, ",") {
			name := foldHeader(strings.TrimSpace(option))
			if name != "connection" && name != "upgrade" {
				for candidate := range h {
					if foldHeader(candidate) == name {
						delete(h, candidate)
					}
				}
			}
		}
	}
	for name := range h {
		if s.reserved(name) {
			delete(h, name)
		}
	}
}

func setForwarded(r *http.Request, ip netip.Addr) {
	value := ip.String()
	r.Header[http.CanonicalHeaderKey(realip.XRealIP)] = []string{value}
	r.Header.Set("X-Forwarded-For", value)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", r.Host)
}
