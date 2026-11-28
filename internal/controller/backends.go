package controller

import (
	"net/netip"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"

	policy "github.com/zekihan/gatehouse/internal/policy/v1alpha1"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

type target struct {
	namespace string
	name      string
	section   string
}

type binding[T any] struct {
	obj  *unstructured.Unstructured
	spec T
}

type backendIndex struct {
	service map[target][]binding[policy.BackendPolicySpec]
	tls     map[target][]binding[gateway.BackendTLSPolicySpec]
	slices  map[target][]*unstructured.Unstructured
}

func newBackendIndex(objects Objects) backendIndex {
	index := backendIndex{
		service: make(map[target][]binding[policy.BackendPolicySpec]),
		tls:     make(map[target][]binding[gateway.BackendTLSPolicySpec]),
		slices:  make(map[target][]*unstructured.Unstructured),
	}
	for _, obj := range objects.list(backendPolicies, "") {
		p, ok := decode[policy.BackendPolicy](obj)
		if !ok {
			continue
		}
		for _, ref := range p.Spec.TargetRefs {
			if ref.Group == "" && ref.Kind == services.kind && ref.SectionName != "" {
				id := target{p.Namespace, ref.Name, ref.SectionName}
				index.service[id] = append(
					index.service[id],
					binding[policy.BackendPolicySpec]{obj, p.Spec},
				)
			}
		}
	}
	for _, obj := range objects.list(tlsPolicies, "") {
		p, ok := decode[gateway.BackendTLSPolicy](obj)
		if !ok {
			continue
		}
		for _, ref := range p.Spec.TargetRefs {
			if ref.Group == "" && string(ref.Kind) == services.kind {
				id := target{p.Namespace, string(ref.Name), string(value(ref.SectionName, ""))}
				index.tls[id] = append(
					index.tls[id],
					binding[gateway.BackendTLSPolicySpec]{obj, p.Spec},
				)
			}
		}
	}
	for _, obj := range objects.list(endpointSlices, "") {
		if service := obj.GetLabels()[discovery.LabelServiceName]; service != "" {
			id := target{namespace: obj.GetNamespace(), name: service}
			index.slices[id] = append(index.slices[id], obj)
		}
	}
	return index
}

type backendPlan struct {
	backend *snapshot.Backend
	dial    time.Duration
	failure string
}

func (c *compiler) backendRef(
	source key,
	ref gateway.BackendObjectReference,
	gatewayRef gateway.ParentReference,
	protected bool,
) backendPlan {
	if value(ref.Group, "") != "" || value(ref.Kind, "Service") != "Service" || ref.Port == nil {
		return backendPlan{failure: "InvalidKind"}
	}
	id := key{
		services,
		string(value(ref.Namespace, gateway.Namespace(source.namespace))),
		string(ref.Name),
	}
	if !c.permitted(source, id) {
		return backendPlan{failure: "RefNotPermitted"}
	}
	obj := c.objects.get(services, id.namespace, id.name)
	service, ok := decode[corev1.Service](obj)
	if !ok {
		return backendPlan{failure: "BackendNotFound"}
	}
	c.useObject(services, obj)
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		return backendPlan{failure: "UnsupportedServiceType"}
	}
	for _, port := range service.Spec.Ports {
		if port.Port == *ref.Port &&
			(port.Protocol == corev1.ProtocolTCP || port.Protocol == "") {
			return c.servicePort(service, port, gatewayRef, protected)
		}
	}
	return backendPlan{failure: "PortNotFound"}
}

func (c *compiler) servicePort(
	svc *corev1.Service,
	port corev1.ServicePort,
	ancestor gateway.ParentReference,
	protected bool,
) backendPlan {
	id := target{svc.Namespace, svc.Name, port.Name}
	plan := &snapshot.Backend{
		Service: svc.Namespace + "/" + svc.Name,
		Port:    portNumber(port.Port),
		LAN:     len(svc.Spec.Selector) == 0,
	}
	var settings policy.BackendPolicySpec
	var dial time.Duration
	if matches := c.backend.service[id]; len(matches) != 0 {
		c.markBackendCandidates(matches, ancestor)
		if protected && len(matches) > 1 {
			return backendPlan{failure: conflicted}
		}
		settings = matches[0].spec
		var failure string
		dial, failure = useBackendPolicy(plan, settings)
		if failure != "" {
			c.markPolicy(backendPolicies, matches[0].obj, ancestor, outcome{rejected: failure})
			return backendPlan{failure: failure}
		}
	}

	if failure := c.backendTLS(plan, id, settings.SNI, ancestor); failure != "" {
		return backendPlan{failure: failure}
	}
	if settings.ClusterIP {
		plan.ClusterIP = c.clusterAddress(svc, plan, settings.AddressFamily)
		if plan.ClusterIP == "" {
			return backendPlan{failure: "InvalidClusterIP"}
		}
	} else {
		plan.Endpoints = c.endpoints(svc, port.Name, plan, settings.AddressFamily)
	}
	return backendPlan{backend: plan, dial: dial}
}

func (c *compiler) markBackendCandidates(
	matches []binding[policy.BackendPolicySpec],
	ancestor gateway.ParentReference,
) {
	for i, match := range matches {
		state := outcome{}
		if i != 0 {
			state.rejected = conflicted
		}
		c.markPolicy(backendPolicies, match.obj, ancestor, state)
	}
}

func useBackendPolicy(
	plan *snapshot.Backend,
	spec policy.BackendPolicySpec,
) (time.Duration, string) {
	var dial time.Duration
	if spec.DialTimeout != "" {
		var err error
		dial, err = time.ParseDuration(spec.DialTimeout)
		if err != nil || dial <= 0 {
			return 0, "InvalidDialTimeout"
		}
	}
	if spec.StickyCookie != "" && !validToken(spec.StickyCookie) {
		return 0, "InvalidStickyCookie"
	}
	if spec.TLS != "" && spec.TLS != "required" || spec.SNI != "" && spec.TLS != "required" {
		return 0, "InvalidTLS"
	}
	plan.TLSRequired = spec.TLS == "required"
	plan.ProxyV2 = spec.ProxyV2
	plan.StickyCookie = spec.StickyCookie
	return dial, ""
}

func (c *compiler) backendTLS(
	plan *snapshot.Backend,
	id target,
	sni string,
	ancestor gateway.ParentReference,
) string {
	matches := c.backendTLSCandidates(id)
	allowException := c.deviceException(plan)
	if len(matches) == 0 {
		if plan.TLSRequired && !allowException || allowException && !plan.TLSRequired {
			return "InvalidTLS"
		}
		return ""
	}
	for i, match := range matches {
		if i != 0 {
			c.markPolicy(tlsPolicies, match.obj, ancestor, outcome{rejected: conflicted})
		}
	}
	winner := matches[0]
	validation := winner.spec.Validation
	plan.TLS = c.resolveBackendCA(winner.obj.GetNamespace(), validation)
	switch {
	case !plan.TLSRequired || allowException || len(matches) > 1:
		c.markPolicy(tlsPolicies, winner.obj, ancestor, outcome{rejected: "TLSConflict"})
		return "TLSConflict"
	case plan.TLS == nil || sni != "" && sni != plan.TLS.ServerName:
		c.markPolicy(
			tlsPolicies,
			winner.obj,
			ancestor,
			outcome{unresolved: "InvalidCACertificateRef"},
		)
		return "InvalidCACertificateRef"
	default:
		c.markPolicy(tlsPolicies, winner.obj, ancestor, outcome{})
		return ""
	}
}

func (c *compiler) backendTLSCandidates(id target) []binding[gateway.BackendTLSPolicySpec] {
	allPorts := target{namespace: id.namespace, name: id.name}
	matches := slices.Clone(c.backend.tls[allPorts])
	if id != allPorts {
		matches = append(matches, c.backend.tls[id]...)
	}
	slices.SortFunc(matches, func(a, b binding[gateway.BackendTLSPolicySpec]) int {
		return compareObjectAge(a.obj, b.obj)
	})
	return slices.CompactFunc(
		matches,
		func(a, b binding[gateway.BackendTLSPolicySpec]) bool { return a.obj == b.obj },
	)
}

func (c *compiler) resolveBackendCA(
	namespace string,
	validation gateway.BackendTLSPolicyValidation,
) *snapshot.BackendTLS {
	if len(validation.CACertificateRefs) != 1 || len(validation.SubjectAltNames) != 0 ||
		validation.Hostname == "" {
		return nil
	}
	ref := validation.CACertificateRefs[0]
	if ref.Group != "" || ref.Kind != "ConfigMap" {
		return nil
	}
	id := key{configMaps, namespace, string(ref.Name)}
	c.caWatches[id] = true
	c.useNamed(id)
	cm, ok := decode[corev1.ConfigMap](c.objects.get(configMaps, id.namespace, id.name))
	if !ok {
		return nil
	}
	cert := []byte(cm.Data[caKey])
	if !validCA(cert, c.now) {
		return nil
	}
	return &snapshot.BackendTLS{ServerName: string(validation.Hostname), CAPEM: cert}
}

func (c *compiler) deviceException(plan *snapshot.Backend) bool {
	for _, exception := range c.cfg.DeviceTrust.Exceptions {
		expires, err := time.Parse(time.RFC3339, exception.Expires)
		if exception.Service == plan.Service && exception.Port == plan.Port && err == nil &&
			expires.After(c.now) {
			return true
		}
	}
	return false
}

func (c *compiler) clusterAddress(
	svc *corev1.Service,
	plan *snapshot.Backend,
	family string,
) string {
	addresses := svc.Spec.ClusterIPs
	if len(addresses) == 0 {
		addresses = []string{svc.Spec.ClusterIP}
	}
	for _, address := range addresses {
		ip, ok := parseAddress(address, family)
		if ok && (!plan.LAN || c.allowLAN(ip, plan.Port)) {
			return netip.AddrPortFrom(ip, plan.Port).String()
		}
	}
	return ""
}

func (c *compiler) endpoints(
	svc *corev1.Service,
	name string,
	plan *snapshot.Backend,
	family string,
) []string {
	id := target{namespace: svc.Namespace, name: svc.Name}
	var addresses []string
	for _, obj := range c.backend.slices[id] {
		c.useObject(endpointSlices, obj)
		slice, ok := decode[discovery.EndpointSlice](obj)
		if !ok || slice.AddressType != endpointFamily(family) ||
			!sliceBelongsToService(slice, svc, plan.LAN) {
			continue
		}
		port, ok := endpointPort(slice.Ports, name)
		if ok {
			addresses = c.appendEndpoints(addresses, slice.Endpoints, port, plan.LAN, family)
		}
	}
	slices.Sort(addresses)
	return slices.Compact(addresses)
}

func endpointFamily(family string) discovery.AddressType {
	if family == string(discovery.AddressTypeIPv6) {
		return discovery.AddressTypeIPv6
	}
	return discovery.AddressTypeIPv4
}

func sliceBelongsToService(
	slice *discovery.EndpointSlice,
	svc *corev1.Service,
	selectorless bool,
) bool {
	ownerFound := false
	for _, owner := range slice.OwnerReferences {
		if owner.Kind != "Service" {
			continue
		}
		if owner.Name != svc.Name || owner.UID != svc.UID {
			return false
		}
		ownerFound = true
	}
	return ownerFound || selectorless
}

func endpointPort(ports []discovery.EndpointPort, name string) (uint16, bool) {
	for _, field := range ports {
		if value(field.Name, "") == name &&
			value(field.Protocol, corev1.ProtocolTCP) == corev1.ProtocolTCP &&
			field.Port != nil {
			if port := portNumber(*field.Port); port != 0 {
				return port, true
			}
		}
	}
	return 0, false
}

func (c *compiler) appendEndpoints(
	out []string,
	endpoints []discovery.Endpoint,
	port uint16,
	lan bool,
	family string,
) []string {
	for _, endpoint := range endpoints {
		if !value(endpoint.Conditions.Ready, false) ||
			value(endpoint.Conditions.Terminating, false) {
			continue
		}
		for _, address := range endpoint.Addresses {
			ip, ok := parseAddress(address, family)
			if ok && (!lan || c.allowLAN(ip, port)) {
				out = append(out, netip.AddrPortFrom(ip, port).String())
			}
		}
	}
	return out
}

func parseAddress(address, family string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(address)
	return ip, err == nil && ip.Zone() == "" && !ip.Is4In6() &&
		ip.Is4() == (endpointFamily(family) == discovery.AddressTypeIPv4)
}

func (c *compiler) allowLAN(ip netip.Addr, port uint16) bool {
	for _, rule := range c.cfg.LANBackends {
		cidr, err := netip.ParsePrefix(rule.CIDR)
		if err == nil && cidr.Contains(ip) && slices.Contains(rule.Ports, port) {
			return true
		}
	}
	return false
}

func validToken(value string) bool {
	for _, r := range value {
		if r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return value != ""
}
