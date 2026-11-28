package controller

import (
	"regexp"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	gateway "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

type routeRules struct {
	http       []gateway.HTTPRouteRule
	tls        []gateway.TLSRouteRule
	policies   routePolicyIndex
	tlsWinners map[socketHost]tlsWinner
}

func (c *compiler) compileRoutes() {
	policies := newRoutePolicyIndex(c.objects)
	for _, obj := range c.objects.list(httpRoutes, "") {
		r, ok := decode[gateway.HTTPRoute](obj)
		if ok {
			c.compileRoute(
				httpRoutes,
				obj,
				r.Spec.ParentRefs,
				r.Spec.Hostnames,
				routeRules{http: r.Spec.Rules, policies: policies},
			)
		}
	}
	tls := c.objects.list(tlsRoutes, "")
	winners := c.selectTLSRoutes(tls)
	for _, obj := range tls {
		r, ok := decode[gateway.TLSRoute](obj)
		if ok {
			c.compileRoute(
				tlsRoutes,
				obj,
				r.Spec.ParentRefs,
				r.Spec.Hostnames,
				routeRules{tls: r.Spec.Rules, tlsWinners: winners},
			)
		}
	}
}

type tlsWinner struct {
	route       *unstructured.Unstructured
	specificity int
}

func (c *compiler) selectTLSRoutes(objects []*unstructured.Unstructured) map[socketHost]tlsWinner {
	winners := make(map[socketHost]tlsWinner)
	for _, obj := range objects {
		route, ok := decode[gateway.TLSRoute](obj)
		if !ok {
			continue
		}
		for _, ref := range route.Spec.ParentRefs {
			for _, a := range c.listeners[parentKey(ref, route.Namespace)] {
				c.considerTLSRoute(winners, a, ref, route, obj)
			}
		}
	}
	return winners
}

func (c *compiler) considerTLSRoute(
	winners map[socketHost]tlsWinner,
	a attachment,
	ref gateway.ParentReference,
	route *gateway.TLSRoute,
	obj *unstructured.Unstructured,
) {
	if !a.status.valid() || a.status.protocol != gateway.TLSProtocolType ||
		c.cfg.Hosts[a.host].Namespace != route.Namespace || !selectsAttachment(ref, a) ||
		!c.routeNamespaceAllowed(route.Namespace, a) {
		return
	}
	specificity := hostnameSpecificity(route.Spec.Hostnames, a.host)
	socket := socketHost{port: a.status.port, host: a.host}
	previous, exists := winners[socket]
	if specificity >= 0 && (!exists || specificity > previous.specificity) {
		winners[socket] = tlsWinner{route: obj, specificity: specificity}
	}
}

func (c *compiler) compileRoute(
	res resource,
	obj *unstructured.Unstructured,
	refs []gateway.ParentReference,
	hosts []gateway.Hostname,
	rules routeRules,
) {
	if hasOwnedParent(obj, "parents") {
		c.statusOnly(res, obj)
	}
	seen := make(map[*listenerStatus]outcome)
	for _, ref := range refs {
		id := parentKey(ref, obj.GetNamespace())
		parent := c.statuses[id]
		if parent == nil {
			continue
		}
		s := c.status(res, obj)
		state := outcome{rejected: "NoMatchingListenerHostname"}
		for _, a := range c.listeners[id] {
			specificity := hostnameSpecificity(hosts, a.host)
			if specificity < 0 || !selectsAttachment(ref, a) ||
				protocolRouteKind(a.status.protocol) != res.kind {
				continue
			}
			if !c.routeNamespaceAllowed(s.id.namespace, a) {
				if state.rejected != "" {
					state.rejected = "NotAllowedByListeners"
				}
				continue
			}
			item, exists := seen[a.status]
			if !exists {
				item = c.bindRoute(obj, a, s.id, rules, specificity)
				seen[a.status] = item
				if item.rejected == "" {
					a.status.attached++
				}
			}
			state = combineParent(state, item)
		}
		s.parents = append(s.parents, parentStatus{ref: ref, outcome: state})
	}
}

func selectsAttachment(ref gateway.ParentReference, a attachment) bool {
	return (ref.SectionName == nil || string(*ref.SectionName) == a.status.name) &&
		(ref.Port == nil || *ref.Port == int32(a.status.port))
}

func hostnameSpecificity(names []gateway.Hostname, host string) int {
	if len(names) == 0 {
		return 0
	}
	score := -1
	for _, name := range names {
		if string(name) == host {
			return len(host) + 1
		}
		if strings.HasPrefix(string(name), "*.") && strings.HasSuffix(host, string(name[1:])) {
			score = max(score, len(name)-1)
		}
	}
	return score
}

func (c *compiler) routeNamespaceAllowed(namespace string, a attachment) bool {
	if a.allowed == nil || a.allowed.Namespaces == nil {
		return namespace == a.set.namespace
	}
	ref := a.allowed.Namespaces
	return c.namespaceAllowed(namespace, a.set.namespace, ref.From, ref.Selector)
}

func combineParent(a, b outcome) outcome {
	if a.rejected != "" {
		return b
	}
	if b.rejected == "" && b.unresolved != "" {
		a.unresolved = b.unresolved
	}
	return a
}

func (c *compiler) bindRoute(
	obj *unstructured.Unstructured,
	a attachment,
	key key,
	rules routeRules,
	specificity int,
) outcome {
	if !a.status.valid() {
		return outcome{rejected: "NoMatchingParent"}
	}
	parent := referenceFor(a.set, a.status.name)
	if key.resource == tlsRoutes {
		winner := rules.tlsWinners[socketHost{port: a.status.port, host: a.host}]
		if winner.route != obj {
			return outcome{rejected: conflicted}
		}
		return c.bindTLS(key, a, rules.tls, parent)
	}
	return c.bindHTTP(obj, key, a, rules, parent, specificity)
}

func (o outcome) valid() bool { return o.rejected == "" && o.unresolved == "" }

func (c *compiler) bindTLS(
	id key,
	a attachment,
	rules []gateway.TLSRouteRule,
	parent gateway.ParentReference,
) outcome {
	if c.cfg.Hosts[a.host].Namespace != id.namespace {
		return outcome{rejected: hostNotPermitted}
	}
	host := c.data.Ports[a.status.port][a.host]
	if len(rules) != 1 || len(rules[0].BackendRefs) != 1 {
		return outcome{unresolved: "UnsupportedTLSRule"}
	}
	backend := c.backendRef(id, rules[0].BackendRefs[0].BackendObjectReference, parent, false)
	if backend.failure != "" {
		return outcome{unresolved: backend.failure}
	}
	if backend.backend.TLSRequired {
		return outcome{unresolved: "InvalidTLS"}
	}
	host.Passthrough = backend.backend
	c.putHost(a.status.port, a.host, host)
	return outcome{}
}

func (c *compiler) bindHTTP(
	obj *unstructured.Unstructured,
	id key,
	a attachment,
	rules routeRules,
	parent gateway.ParentReference,
	specificity int,
) outcome {
	registry := c.cfg.Hosts[a.host]
	if registry.Namespace != id.namespace &&
		!slices.ContainsFunc(registry.Delegate, func(d config.Delegation) bool {
			return d.Namespace == id.namespace
		}) {
		return outcome{rejected: hostNotPermitted}
	}
	published := c.data.Ports[a.status.port][a.host]
	var state outcome
	applied := false
	for _, spec := range rules.http {
		id := ruleContext{id, obj, registry, parent, specificity}
		routes, next := c.httpRule(id, spec, rules.policies)
		if len(routes) > 0 {
			published.Routes = append(published.Routes, routes...)
			applied = true
		}
		if next.unresolved != "" {
			state.unresolved = next.unresolved
		}
	}
	c.putHost(a.status.port, a.host, published)
	if !applied {
		state.rejected = hostNotPermitted
	}
	return state
}

type ruleContext struct {
	id          key
	object      *unstructured.Unstructured
	registry    config.Host
	parent      gateway.ParentReference
	specificity int
}

func (c *compiler) httpRule(
	ctx ruleContext,
	spec gateway.HTTPRouteRule,
	policies routePolicyIndex,
) ([]snapshot.Route, outcome) {
	base := snapshot.Route{
		Namespace:           ctx.id.namespace,
		Name:                ctx.id.name,
		Created:             ctx.object.GetCreationTimestamp().Time,
		HostnameSpecificity: ctx.specificity,
	}
	state := c.resolveHTTPBackends(&base, ctx, spec.BackendRefs)
	if !c.applyFilters(&base, spec.Filters) {
		base.InvalidPolicy = true
		state.unresolved = "UnsupportedFilter"
	}
	matches := spec.Matches
	if len(matches) == 0 {
		matches = []gateway.HTTPRouteMatch{{}}
	}
	candidates := policies.selectPolicies(ctx.id, string(value(spec.Name, "")))
	var routes []snapshot.Route
	for _, match := range matches {
		route := base
		if !applyMatch(&route, match) {
			route = base
			route.Path = "/"
			route.InvalidPolicy = true
			state.unresolved = "UnsupportedMatch"
		}
		if !applyDelegation(&route, ctx.registry) {
			continue
		}
		if failure := c.applyRoutePolicies(&route, ctx, candidates); failure != "" {
			route.InvalidPolicy = true
			state.unresolved = failure
		}
		routes = append(routes, route)
	}
	return routes, state
}

func (c *compiler) resolveHTTPBackends(
	route *snapshot.Route,
	ctx ruleContext,
	refs []gateway.HTTPBackendRef,
) outcome {
	var state outcome
	protected := ctx.registry.Protection != "public" || ctx.registry.Namespace != ctx.id.namespace
	for _, ref := range refs {
		weight := value(ref.Weight, 1)
		if weight == 0 {
			continue
		}
		if weight < 0 || len(ref.Filters) != 0 {
			state.unresolved = "UnsupportedFilter"
			route.InvalidPolicy = true
			continue
		}
		backend := c.backendRef(ctx.id, ref.BackendObjectReference, ctx.parent, protected)
		if backend.failure != "" {
			state.unresolved = backend.failure
		}
		route.Backends = append(
			route.Backends,
			snapshot.WeightedBackend{Weight: uint32(weight), Backend: backend.backend},
		)
		if backend.dial > 0 && (route.Deadlines.Dial == 0 || backend.dial < route.Deadlines.Dial) {
			route.Deadlines.Dial = backend.dial
		}
	}
	return state
}

func applyMatch(route *snapshot.Route, match gateway.HTTPRouteMatch) bool {
	route.Path = "/"
	if match.Path != nil {
		route.Path = value(match.Path.Value, "/")
		switch string(value(match.Path.Type, gateway.PathMatchPathPrefix)) {
		case string(gateway.PathMatchExact):
			route.Exact = true
		case string(gateway.PathMatchPathPrefix):
		default:
			return false
		}
	}
	route.Method = string(value(match.Method, ""))
	for _, header := range match.Headers {
		kind := value(header.Type, gateway.HeaderMatchExact)
		info := snapshot.Match{
			Name:  string(header.Name),
			Value: header.Value,
			Regex: kind == gateway.HeaderMatchRegularExpression,
		}
		if kind != gateway.HeaderMatchExact && !info.Regex || !validMatch(info) {
			return false
		}
		route.Headers = append(route.Headers, info)
	}
	for _, query := range match.QueryParams {
		kind := value(query.Type, gateway.QueryParamMatchExact)
		info := snapshot.Match{
			Name:  string(query.Name),
			Value: query.Value,
			Regex: kind == gateway.QueryParamMatchRegularExpression,
		}
		if kind != gateway.QueryParamMatchExact && !info.Regex || !validMatch(info) {
			return false
		}
		route.Query = append(route.Query, info)
	}
	return strings.HasPrefix(route.Path, "/")
}

func validMatch(match snapshot.Match) bool {
	if !match.Regex {
		return true
	}
	_, err := regexp.Compile(match.Value)
	return err == nil
}

func applyDelegation(route *snapshot.Route, host config.Host) bool {
	if host.Namespace == route.Namespace {
		return true
	}
	for _, delegation := range host.Delegate {
		if route.Namespace != delegation.Namespace ||
			!matchesExact(route, delegation.Paths, delegation.Methods) {
			continue
		}
		route.ForwardAuth = delegation.ForwardAuth
		// Delegate only the registry's explicit rewrite. Filters from the app
		// must not change the authority or convert this into a broader grant.
		route.Rewrite = nil
		if delegation.Rewrite != "" {
			route.Rewrite = &snapshot.Rewrite{Path: delegation.Rewrite}
		}
		return true
	}
	return false
}

func matchesExact(route *snapshot.Route, paths, methods []string) bool {
	return route.Exact && slices.Contains(paths, route.Path) &&
		slices.Contains(methods, route.Method)
}

func (c *compiler) applyFilters(route *snapshot.Route, filters []gateway.HTTPRouteFilter) bool {
	for _, filter := range filters {
		switch string(filter.Type) {
		case string(gateway.HTTPRouteFilterRequestHeaderModifier):
			if !c.applyHeaderFilter(&route.RequestHeaders, filter.RequestHeaderModifier) {
				return false
			}
		case string(gateway.HTTPRouteFilterResponseHeaderModifier):
			if !c.applyHeaderFilter(&route.ResponseHeaders, filter.ResponseHeaderModifier) {
				return false
			}
		case string(gateway.HTTPRouteFilterURLRewrite):
			if !applyRewrite(route, filter.URLRewrite) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func applyRewrite(route *snapshot.Route, rewrite *gateway.HTTPURLRewriteFilter) bool {
	if rewrite == nil || route.Rewrite != nil {
		return false
	}
	result := &snapshot.Rewrite{Host: string(value(rewrite.Hostname, ""))}
	if rewrite.Path != nil {
		switch rewrite.Path.Type {
		case gateway.FullPathHTTPPathModifier:
			result.Path = value(rewrite.Path.ReplaceFullPath, "")
		case gateway.PrefixMatchHTTPPathModifier:
			result.Path = value(rewrite.Path.ReplacePrefixMatch, "")
			result.Prefix = true
		default:
			return false
		}
	}
	route.Rewrite = result
	return true
}

func (c *compiler) applyHeaderFilter(
	out *snapshot.HeaderFilter,
	filter *gateway.HTTPHeaderFilter,
) bool {
	if filter == nil {
		return false
	}
	out.Set = make(map[string]string)
	out.Add = make(map[string]string)
	for _, h := range filter.Set {
		if !c.validHeader(string(h.Name), h.Value) {
			return false
		}
		out.Set[string(h.Name)] = h.Value
	}
	for _, h := range filter.Add {
		if !c.validHeader(string(h.Name), h.Value) {
			return false
		}
		out.Add[string(h.Name)] = h.Value
	}
	for _, name := range filter.Remove {
		if !c.validHeader(name, "") {
			return false
		}
		out.Remove = append(out.Remove, name)
	}
	return true
}

func (c *compiler) validHeader(name, value string) bool {
	if !validToken(name) || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	name = config.FoldHeader(name)
	if config.ReservedHeader(name) {
		return false
	}
	switch name {
	case "connection",
		"upgrade",
		"transfer-encoding",
		"host",
		"content-length",
		"strict-transport-security",
		"content-security-policy",
		"x-content-type-options",
		"x-frame-options",
		"referrer-policy",
		"permissions-policy":
		return false
	}
	for _, port := range c.cfg.Ports {
		if port.EdgeSecret != nil && name == config.FoldHeader(port.EdgeSecret.Header) {
			return false
		}
	}
	return true
}
