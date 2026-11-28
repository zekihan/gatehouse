package controller

import (
	"encoding/hex"
	"maps"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	gateway "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zekihan/gatehouse/internal/config"
	policy "github.com/zekihan/gatehouse/internal/policy/v1alpha1"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

type routePolicyIndex map[target][]binding[policy.RoutePolicySpec]

func newRoutePolicyIndex(objects Objects) routePolicyIndex {
	index := make(routePolicyIndex)
	for _, obj := range objects.list(routePolicies, "") {
		p, ok := decode[policy.RoutePolicy](obj)
		if !ok {
			continue
		}
		for _, ref := range p.Spec.TargetRefs {
			if ref.Group == gatewayGroup && ref.Kind == httpRoutes.kind {
				id := target{p.Namespace, ref.Name, ref.SectionName}
				index[id] = append(index[id], binding[policy.RoutePolicySpec]{obj, p.Spec})
			}
		}
	}
	return index
}

func (index routePolicyIndex) selectPolicies(
	id key,
	section string,
) []binding[policy.RoutePolicySpec] {
	whole := index[target{namespace: id.namespace, name: id.name}]
	if section == "" {
		return whole
	}
	rule := index[target{id.namespace, id.name, section}]
	combined := append(slices.Clone(whole), rule...)
	slices.SortFunc(
		combined,
		func(a, b binding[policy.RoutePolicySpec]) int { return compareObjectAge(a.obj, b.obj) },
	)
	return slices.CompactFunc(
		combined,
		func(a, b binding[policy.RoutePolicySpec]) bool { return a.obj == b.obj },
	)
}

func (c *compiler) applyRoutePolicies(
	route *snapshot.Route,
	ctx ruleContext,
	matches []binding[policy.RoutePolicySpec],
) string {
	host := ctx.registry
	mtls := classOf(host.Protection, "mtls:")
	if len(matches) == 0 {
		if mtls != "" {
			return "PolicyRequired"
		}
		return ""
	}
	for _, match := range matches[1:] {
		c.markPolicy(routePolicies, match.obj, ctx.parent, outcome{rejected: conflicted})
	}
	winner := matches[0]
	failure := c.mergePolicy(route, host, winner.spec, mtls)
	c.markPolicy(routePolicies, winner.obj, ctx.parent, outcome{rejected: failure})
	if len(matches) > 1 && (host.Protection != "public" || route.ForwardAuth != "") {
		return conflicted
	}
	return failure
}

func (c *compiler) mergePolicy(
	route *snapshot.Route,
	host config.Host,
	spec policy.RoutePolicySpec,
	mtls string,
) string {
	if !applyAuth(route, host, spec.Auth) {
		return "AuthNotPermitted"
	}
	if !applyMTLS(route, host, spec.MTLS, mtls) {
		return "InvalidMTLS"
	}
	if !applyDeny(route, spec.Deny) {
		return "InvalidDeny"
	}
	if !c.applyResponseHeaders(route, spec.ResponseHeaders) {
		return "InvalidResponseHeaders"
	}
	return applyOverrides(route, host, spec)
}

func applyAuth(route *snapshot.Route, host config.Host, auth *policy.Auth) bool {
	if auth == nil {
		return true
	}
	if auth.OIDC != "" && auth.ForwardAuth == "" {
		return auth.OIDC == classOf(host.Protection, "oidc:") && route.ForwardAuth == ""
	}
	if auth.OIDC != "" || auth.ForwardAuth == "" {
		return false
	}
	if route.ForwardAuth != "" {
		return route.ForwardAuth == auth.ForwardAuth
	}
	for _, exception := range host.Exceptions {
		if exception.ForwardAuth == auth.ForwardAuth &&
			matchesExact(route, []string{exception.Path}, exception.Methods) {
			route.ForwardAuth = auth.ForwardAuth
			return true
		}
	}
	return false
}

func applyMTLS(route *snapshot.Route, host config.Host, p *policy.MTLS, profile string) bool {
	if p == nil {
		return profile == ""
	}
	if profile == "" || len(p.TrustedAnchors) == 0 || len(p.Identities) == 0 {
		return false
	}
	prefix := "urn:noqer:mtls:" + profile + ":"
	if p.IdentityPrefix != "" && p.IdentityPrefix != prefix {
		return false
	}
	for _, identity := range p.Identities {
		if !strings.HasPrefix(identity, prefix) || !slices.Contains(host.Identities, identity) {
			return false
		}
	}
	if !validFingerprints(p.TrustedAnchors) || !validFingerprints(p.BlockedFingerprints) ||
		!validMTLSHeaders(p.ForwardHeaders) {
		return false
	}
	constraints, ok := identityConstraints(p.Identities, p.Constraints)
	if !ok {
		return false
	}
	route.MTLS = &snapshot.MTLSPolicy{
		IdentityPrefix: prefix, Identities: p.Identities, Constraints: constraints,
		BlockedFingerprints: p.BlockedFingerprints, DisabledIdentities: p.DisabledIdentities,
		TrustedAnchors: p.TrustedAnchors, ForwardHeaders: p.ForwardHeaders,
	}
	return true
}

func validFingerprints(values []string) bool {
	for _, fingerprint := range values {
		decoded, err := hex.DecodeString(fingerprint)
		if err != nil || len(decoded) != 32 || strings.ToLower(fingerprint) != fingerprint {
			return false
		}
	}
	return true
}

func validMTLSHeaders(headers []string) bool {
	for _, header := range headers {
		if snapshot.MTLSHeaderSource(header) == "" {
			return false
		}
	}
	return true
}

func identityConstraints(
	identities []string,
	constraints map[string]policy.Constraint,
) (map[string]config.IdentityConstraint, bool) {
	result := make(map[string]config.IdentityConstraint, len(constraints))
	for identity, constraint := range constraints {
		if !slices.Contains(identities, identity) || len(constraint.Methods) == 0 ||
			len(constraint.Paths) == 0 {
			return nil, false
		}
		for _, method := range constraint.Methods {
			if !validToken(method) || strings.ToUpper(method) != method {
				return nil, false
			}
		}
		for _, entry := range constraint.Paths {
			if !absolutePath(entry) {
				return nil, false
			}
		}
		result[identity] = config.IdentityConstraint{
			Methods: constraint.Methods,
			Paths:   constraint.Paths,
		}
	}
	return result, true
}

func absolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "%?#\\\t\r\n ") &&
		(path.Clean(value) == value || path.Clean(value)+"/" == value)
}

func applyDeny(route *snapshot.Route, deny *policy.Deny) bool {
	if deny == nil {
		return true
	}
	for _, entries := range [][]string{deny.Prefixes, deny.Exact} {
		for _, entry := range entries {
			if !absolutePath(entry) {
				return false
			}
		}
	}
	route.Deny = &config.Deny{Prefixes: deny.Prefixes, Exact: deny.Exact}
	return true
}

func (c *compiler) applyResponseHeaders(route *snapshot.Route, headers map[string]string) bool {
	if len(headers) == 0 {
		return true
	}
	additions := maps.Clone(route.ResponseHeaders.Add)
	if additions == nil {
		additions = make(map[string]string, len(headers))
	}
	for name, value := range headers {
		if !c.validHeader(name, value) {
			return false
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, exists := additions[canonical]; exists {
			return false
		}
		additions[canonical] = value
	}
	route.ResponseHeaders.Add = additions
	return true
}

func applyOverrides(route *snapshot.Route, host config.Host, spec policy.RoutePolicySpec) string {
	if !applyCompression(route, spec.Compression) || !applyLimits(route, spec.Limits) {
		return "InvalidDefaults"
	}
	if !applyDeadlines(&route.Deadlines, spec.Deadlines) {
		return "InvalidDeadlines"
	}
	switch spec.AccessLog {
	case "":
	case "on", "off":
		route.AccessLogOff = spec.AccessLog == "off"
	default:
		return "InvalidAccessLog"
	}
	if spec.CrowdSec != "" {
		if spec.CrowdSec != "exempt" || !route.Exact ||
			!slices.Contains(host.CrowdSecExemptPaths, route.Path) {
			return "CrowdSecExemptionNotPermitted"
		}
		route.CrowdSecExempt = true
	}
	return ""
}

func applyCompression(route *snapshot.Route, p *policy.Compression) bool {
	if p == nil {
		return true
	}
	if p.MinBytes < 0 || p.Encodings == nil {
		return false
	}
	for _, encoding := range p.Encodings {
		switch encoding {
		case "zstd", "br", "gzip":
		default:
			return false
		}
	}
	route.Compression = &config.Compression{Encodings: p.Encodings, MinBytes: p.MinBytes}
	return true
}

func applyLimits(route *snapshot.Route, p *policy.Limits) bool {
	if p == nil {
		return true
	}
	client, host := p.PerRouteClient, p.PerRouteHost
	if client.InFlight <= 0 || client.PerMinute <= 0 || client.PerSecondSlot <= 0 ||
		client.PerMinute < client.PerSecondSlot || host.InFlight <= 0 {
		return false
	}
	route.Limits = &config.Limits{
		PerRouteClient: config.ClientLimits{
			PerMinute:     client.PerMinute,
			PerSecondSlot: client.PerSecondSlot,
			InFlight:      client.InFlight,
		},
		PerRouteHost: config.HostLimits{InFlight: host.InFlight},
	}
	return true
}

func applyDeadlines(result *snapshot.Deadlines, spec *policy.Deadlines) bool {
	if spec == nil {
		return true
	}
	fields := []struct {
		value string
		apply *time.Duration
	}{
		{spec.Dial, &result.Dial},
		{spec.TLS, &result.TLS},
		{spec.RequestBody, &result.RequestBody},
		{spec.ResponseHeader, &result.ResponseHeader},
		{spec.ResponseBody, &result.ResponseBody},
		{spec.UpgradeIdle, &result.UpgradeIdle},
	}
	for _, entry := range fields {
		if entry.value == "" {
			continue
		}
		duration, err := time.ParseDuration(entry.value)
		if err != nil || duration <= 0 {
			return false
		}
		*entry.apply = duration
	}
	return true
}

func (c *compiler) markPolicy(
	res resource,
	obj *unstructured.Unstructured,
	ancestor gateway.ParentReference,
	state outcome,
) {
	s := c.status(res, obj)
	for i, parent := range s.parents {
		if sameRef(ancestor, parent.ref) {
			if parent.valid() || state.rejected != "" {
				s.parents[i].outcome = state
			}
			return
		}
	}
	s.parents = append(s.parents, parentStatus{ref: ancestor, outcome: state})
}

func (c *compiler) recordPolicyStatuses() {
	if c.statuses[c.gatewayID()] == nil {
		return
	}
	for _, res := range []resource{routePolicies, backendPolicies, tlsPolicies} {
		for _, obj := range c.objects.list(res, "") {
			id := key{res, obj.GetNamespace(), obj.GetName()}
			if c.statuses[id] == nil && c.namespaceRelevant(id.namespace) {
				c.markPolicy(
					res,
					obj,
					referenceFor(c.gatewayID(), ""),
					outcome{rejected: "NoMatchingTarget"},
				)
			}
		}
	}
}

func (c *compiler) namespaceRelevant(namespace string) bool {
	for _, host := range c.cfg.Hosts {
		if host.Namespace == namespace ||
			slices.ContainsFunc(host.Delegate, func(item config.Delegation) bool {
				return item.Namespace == namespace
			}) {
			return true
		}
	}
	return false
}
