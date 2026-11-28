package controller

import (
	"slices"

	"k8s.io/apimachinery/pkg/labels"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

type attachment struct {
	status  *listenerStatus
	set     key
	host    string
	allowed *gateway.AllowedRoutes
}

type socketHost struct {
	port uint16
	host string
}

func value[T any](ptr *T, fallback T) T {
	if ptr == nil {
		return fallback
	}
	return *ptr
}

func parentKey(ref gateway.ParentReference, namespace string) key {
	if value(ref.Group, gateway.Group(gatewayGroup)) != gatewayGroup {
		return key{}
	}
	res := gateways
	switch value(ref.Kind, gateway.Kind("Gateway")) {
	case "Gateway":
	case "ListenerSet":
		res = listenerSets
	default:
		return key{}
	}
	return key{res, string(value(ref.Namespace, gateway.Namespace(namespace))), string(ref.Name)}
}

func (c *compiler) gatewayID() key {
	return key{gateways, c.op.namespace, c.gatewayName}
}

func (c *compiler) compileListeners() {
	id := c.gatewayID()
	obj := c.objects.get(id.resource, id.namespace, id.name)
	gw, ok := decode[gateway.Gateway](obj)
	if !ok {
		return
	}
	classObj := c.objects.get(classes, "", string(gw.Spec.GatewayClassName))
	class, ok := decode[gateway.GatewayClass](classObj)
	if !ok || class.Spec.ControllerName != controllerName {
		return
	}
	c.status(classes, classObj)
	gs := c.status(gateways, obj)
	for _, address := range gw.Spec.Addresses {
		gs.addresses = append(
			gs.addresses,
			gateway.GatewayStatusAddress(address),
		)
	}
	sockets := make(map[socketHost]*listenerStatus)
	for _, spec := range gw.Spec.Listeners {
		status := &listenerStatus{
			name:     string(spec.Name),
			port:     portNumber(spec.Port),
			protocol: spec.Protocol,
		}
		gs.listeners = append(gs.listeners, status)
		c.gatewayListener(
			spec,
			attachment{status, id, string(value(spec.Hostname, "")), spec.AllowedRoutes},
			sockets,
		)
	}
	c.compileListenerSets(gw, sockets)
}

func (c *compiler) gatewayListener(
	spec gateway.Listener,
	a attachment,
	sockets map[socketHost]*listenerStatus,
) {
	port, ok := c.cfg.Ports[a.status.port]
	switch {
	case !ok:
		a.status.rejected = "PortUnavailable"
	case spec.Protocol == gateway.HTTPProtocolType && port.Mode == "redirect" && a.host == "" && spec.TLS == nil:
		return
	case spec.Protocol == gateway.TLSProtocolType && port.Mode != "redirect" && spec.TLS != nil &&
		value(spec.TLS.Mode, gateway.TLSModeTerminate) == gateway.TLSModePassthrough:
		c.passthroughListener(a, sockets)
	default:
		a.status.rejected = "UnsupportedProtocol"
	}
}

func (c *compiler) passthroughListener(a attachment, sockets map[socketHost]*listenerStatus) {
	host, found := c.cfg.Hosts[a.host]
	if !found || !slices.Contains(host.Ports, a.status.port) || host.Protection != "public" ||
		host.Deny != nil || len(host.Exceptions) != 0 || len(host.Delegate) != 0 {
		a.status.rejected = hostNotPermitted
		return
	}
	c.attach(a, snapshot.Host{}, sockets)
}

func portNumber(port int32) uint16 {
	if port < 1 || port > 65535 {
		return 0
	}
	return uint16(port)
}

func (c *compiler) compileListenerSets(
	gw *gateway.Gateway,
	sockets map[socketHost]*listenerStatus,
) {
	for _, obj := range c.objects.list(listenerSets, "") {
		set, ok := decode[gateway.ListenerSet](obj)
		if !ok || !setTargets(set, c.gatewayID()) {
			continue
		}
		s := c.status(listenerSets, obj)
		if !c.listenerNamespaceAllowed(gw, set.Namespace) {
			s.rejected = "NotAllowed"
		}
		for _, spec := range set.Spec.Listeners {
			status := &listenerStatus{
				name:     string(spec.Name),
				port:     portNumber(spec.Port),
				protocol: spec.Protocol,
			}
			s.listeners = append(s.listeners, status)
			if s.rejected != "" {
				status.rejected = s.rejected
				continue
			}
			a := attachment{status, s.id, string(value(spec.Hostname, "")), spec.AllowedRoutes}
			c.setListener(spec, a, sockets)
		}
	}
}

func setTargets(set *gateway.ListenerSet, id key) bool {
	ref := set.Spec.ParentRef
	return value(ref.Group, gateway.Group(gatewayGroup)) == gatewayGroup &&
		value(ref.Kind, gateway.Kind("Gateway")) == "Gateway" &&
		string(value(ref.Namespace, gateway.Namespace(set.Namespace))) == id.namespace &&
		string(ref.Name) == id.name
}

func (c *compiler) listenerNamespaceAllowed(gw *gateway.Gateway, namespace string) bool {
	obj := c.objects.get(namespaces, "", namespace)
	if obj == nil {
		return false
	}
	c.useObject(namespaces, obj)
	if obj.GetLabels()[attachmentLabel] != "allowed" {
		return false
	}
	if gw.Spec.AllowedListeners == nil || gw.Spec.AllowedListeners.Namespaces == nil {
		return false
	}
	allowed := gw.Spec.AllowedListeners.Namespaces
	return allowed.From != nil &&
		c.namespaceAllowed(namespace, gw.Namespace, allowed.From, allowed.Selector)
}

func (c *compiler) namespaceAllowed(
	namespace, parent string,
	from *gateway.FromNamespaces,
	selector *metav1.LabelSelector,
) bool {
	switch value(from, gateway.NamespacesFromSame) {
	case gateway.NamespacesFromSame:
		return namespace == parent
	case gateway.NamespacesFromAll:
		return true
	case gateway.NamespacesFromNone:
		return false
	case gateway.NamespacesFromSelector:
		if selector == nil {
			return false
		}
		ns := c.objects.get(namespaces, "", namespace)
		if ns == nil {
			return false
		}
		c.useObject(namespaces, ns)
		match, err := metav1.LabelSelectorAsSelector(selector)
		return err == nil && match.Matches(labels.Set(ns.GetLabels()))
	default:
		return false
	}
}

func (c *compiler) setListener(
	spec gateway.ListenerEntry,
	a attachment,
	sockets map[socketHost]*listenerStatus,
) {
	host, found := c.cfg.Hosts[a.host]
	port, portFound := c.cfg.Ports[a.status.port]
	switch {
	case !found || host.Namespace != a.set.namespace || !slices.Contains(host.Ports, a.status.port):
		a.status.rejected = hostNotPermitted
	case !portFound || port.Mode == "redirect" || spec.Protocol != gateway.HTTPSProtocolType:
		a.status.rejected = "UnsupportedProtocol"
	case spec.TLS == nil || value(spec.TLS.Mode, gateway.TLSModeTerminate) != gateway.TLSModeTerminate ||
		len(spec.TLS.CertificateRefs) != 1 || len(spec.TLS.Options) != 0:
		a.status.unresolved = "InvalidCertificateRef"
	default:
		c.httpsListener(a, host, spec.TLS.CertificateRefs[0], sockets)
	}
}

func (c *compiler) httpsListener(
	a attachment,
	host config.Host,
	ref gateway.SecretObjectReference,
	sockets map[socketHost]*listenerStatus,
) {
	id := certificateID(ref, a.set.namespace)
	if id.resource != secrets || !c.permitted(a.set, id) {
		a.status.unresolved = "RefNotPermitted"
		return
	}
	c.useNamed(id)
	cert := keyPair(c.objects.get(secrets, id.namespace, id.name), a.host, c.now)
	if cert == nil {
		a.status.unresolved = "InvalidCertificateRef"
		return
	}
	clientCA := c.clientCA(host)
	if classOf(host.Protection, "mtls:") != "" && len(clientCA) == 0 {
		a.status.unresolved = "InvalidClientCA"
		return
	}
	c.attach(a, snapshot.Host{Certificate: cert, ClientCA: clientCA}, sockets)
}

func certificateID(ref gateway.SecretObjectReference, namespace string) key {
	if value(ref.Group, "") != "" || value(ref.Kind, "Secret") != "Secret" {
		return key{}
	}
	return key{
		secrets,
		string(value(ref.Namespace, gateway.Namespace(namespace))),
		string(ref.Name),
	}
}

func (c *compiler) attach(
	a attachment,
	host snapshot.Host,
	sockets map[socketHost]*listenerStatus,
) {
	if !validRouteKinds(a.allowed, a.status.protocol) {
		a.status.unresolved = "InvalidRouteKinds"
		return
	}
	socket := socketHost{port: a.status.port, host: a.host}
	if other := sockets[socket]; other != nil {
		other.rejected = conflicted
		a.status.rejected = conflicted
		delete(c.data.Ports[a.status.port], a.host)
		return
	}
	sockets[socket] = a.status
	c.putHost(a.status.port, a.host, host)
	c.listeners[a.set] = append(c.listeners[a.set], a)
}

func protocolRouteKind(protocol gateway.ProtocolType) string {
	if protocol == gateway.TLSProtocolType {
		return tlsRoutes.kind
	}
	if protocol == gateway.HTTPSProtocolType {
		return httpRoutes.kind
	}
	return ""
}

func validRouteKinds(allowed *gateway.AllowedRoutes, protocol gateway.ProtocolType) bool {
	if allowed == nil {
		return true
	}
	for _, ref := range allowed.Kinds {
		if value(ref.Group, gatewayGroup) != gatewayGroup ||
			string(ref.Kind) != protocolRouteKind(protocol) {
			return false
		}
	}
	return true
}

func (c *compiler) permitted(source, target key) bool {
	if source.namespace == target.namespace {
		return true
	}
	for _, obj := range c.objects.list(grants, target.namespace) {
		grant, ok := decode[gateway.ReferenceGrant](obj)
		if !ok || !slices.ContainsFunc(grant.Spec.From, func(from gateway.ReferenceGrantFrom) bool {
			return string(from.Group) == source.gvr.Group && string(from.Kind) == source.kind &&
				string(from.Namespace) == source.namespace
		}) {
			continue
		}
		c.useObject(grants, obj)
		if slices.ContainsFunc(grant.Spec.To, func(to gateway.ReferenceGrantTo) bool {
			return string(to.Group) == target.gvr.Group && string(to.Kind) == target.kind &&
				string(value(to.Name, gateway.ObjectName(target.name))) == target.name
		}) {
			return true
		}
	}
	return false
}
