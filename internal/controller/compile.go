package controller

import (
	"encoding/json"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	gateway "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

const (
	accepted         = "Accepted"
	resolved         = "ResolvedRefs"
	programmed       = "Programmed"
	pending          = "Pending"
	conflicted       = "Conflicted"
	hostNotPermitted = "HostNotPermitted"
)

type outcome struct {
	rejected   string
	unresolved string
}

type listenerStatus struct {
	outcome

	name     string
	port     uint16
	protocol gateway.ProtocolType
	attached int
}

type parentStatus struct {
	outcome

	ref gateway.ParentReference
}

type objectStatus struct {
	outcome

	id         key
	generation int64
	object     *unstructured.Unstructured
	listeners  []*listenerStatus
	parents    []parentStatus
	addresses  []gateway.GatewayStatusAddress
}

type result struct {
	snapshot  *snapshot.Snapshot
	statuses  map[key]*objectStatus
	caWatches map[key]bool
}

type compiler struct {
	objects     Objects
	cfg         *config.Config
	op          key
	gatewayName string
	now         time.Time
	data        *snapshot.DataPlane
	statuses    map[key]*objectStatus
	inputs      map[key]snapshot.Input
	listeners   map[key][]attachment
	backend     backendIndex
	caWatches   map[key]bool
}

func compile(
	objects Objects,
	cfg *config.Config,
	op key,
	gatewayName string,
	now time.Time,
) (result, error) {
	c := compiler{
		objects: objects, cfg: cfg, op: op, gatewayName: gatewayName, now: now,
		data: &snapshot.DataPlane{
			Ports:       make(map[uint16]map[string]snapshot.Host),
			EdgeSecrets: make(map[string]map[string]string),
		},
		statuses: make(map[key]*objectStatus), inputs: make(map[key]snapshot.Input),
		listeners: make(map[key][]attachment), caWatches: make(map[key]bool),
	}
	c.bootstrapInputs()
	c.compileListeners()
	c.backend = newBackendIndex(objects)
	c.compileRoutes()
	c.recordPolicyStatuses()
	return c.finish()
}

func (c *compiler) bootstrapInputs() {
	bootstrap := key{secrets, c.op.namespace, bootstrapSecret}
	c.useNamed(bootstrap)
	if values, ok := secretValues(
		c.objects.get(bootstrap.resource, bootstrap.namespace, bootstrap.name),
	); ok {
		c.data.OIDCSecrets = oidcSecrets(c.cfg.AuthClasses, values)
	}
	for _, profile := range c.cfg.ClientCertProfiles {
		c.useNamed(key{secrets, c.op.namespace, profile.CASecret})
	}
	for _, port := range c.cfg.Ports {
		if port.EdgeSecret == nil {
			continue
		}
		id := key{secrets, c.op.namespace, port.EdgeSecret.Secret}
		obj := c.objects.get(id.resource, id.namespace, id.name)
		c.useNamed(id)
		if values, ok := secretValues(obj); ok {
			c.data.EdgeSecrets[id.name] = make(map[string]string, len(port.EdgeSecret.Keys))
			for _, name := range port.EdgeSecret.Keys {
				if value := values[name]; len(value) != 0 {
					c.data.EdgeSecrets[id.name][name] = string(value)
				}
			}
		}
	}
}

func oidcSecrets(classes map[string]config.AuthClass, values map[string][]byte) map[string]string {
	out := make(map[string]string)
	for class := range classes {
		for _, name := range []string{
			"oidc-" + class + "-client-secret",
			"cookie-" + class + "-current",
			"cookie-" + class + "-previous",
		} {
			if value, found := values[name]; found {
				out[name] = string(value)
			}
		}
	}
	return out
}

func (c *compiler) finish() (result, error) {
	inputs := make([]snapshot.Input, 0, len(c.inputs)+1)
	for _, input := range c.inputs {
		inputs = append(inputs, input)
	}
	// The effective plan also captures transitions that need no API write,
	// such as a served certificate or a device exception expiring.
	plan, err := json.Marshal(c.data)
	if err != nil {
		return result{}, err
	}
	inputs = append(inputs, snapshot.Input{Group: controllerName, Kind: "DataPlane", Content: plan})
	digest, err := snapshot.Digest(c.cfg, inputs)
	if err != nil {
		return result{}, err
	}
	return result{
		snapshot: &snapshot.Snapshot{Digest: digest, Config: c.cfg, DataPlane: c.data},
		statuses: c.statuses, caWatches: c.caWatches,
	}, nil
}

func (c *compiler) status(res resource, obj *unstructured.Unstructured) *objectStatus {
	c.useObject(res, obj)
	return c.statusOnly(res, obj)
}

func (c *compiler) statusOnly(res resource, obj *unstructured.Unstructured) *objectStatus {
	id := key{res, obj.GetNamespace(), obj.GetName()}
	if existing, found := c.statuses[id]; found {
		return existing
	}
	s := &objectStatus{id: id, generation: obj.GetGeneration(), object: obj}
	c.statuses[id] = s
	return s
}

func (c *compiler) useObject(res resource, obj *unstructured.Unstructured) {
	content := map[string]any{"spec": obj.Object["spec"]}
	if res == namespaces {
		content = map[string]any{"labels": obj.GetLabels()}
	}
	if res == endpointSlices {
		content = map[string]any{
			"service":     obj.GetLabels()["kubernetes.io/service-name"],
			"addressType": obj.Object["addressType"], "endpoints": obj.Object["endpoints"],
			"ports": obj.Object["ports"], "owners": obj.GetOwnerReferences(),
		}
	}
	if res == routePolicies || res == backendPolicies || res == tlsPolicies ||
		res == listenerSets ||
		res == httpRoutes ||
		res == tlsRoutes {
		content["created"] = obj.GetCreationTimestamp()
	}
	if res == services {
		content["uid"] = obj.GetUID()
	}
	c.use(key{res, obj.GetNamespace(), obj.GetName()}, obj.GetGeneration(), content)
}

func (c *compiler) useNamed(id key) {
	var content any
	if obj := c.objects.get(id.resource, id.namespace, id.name); obj != nil {
		content = map[string]any{"data": obj.Object["data"], "binaryData": obj.Object["binaryData"]}
	}
	c.use(id, 0, content)
}

func (c *compiler) use(id key, generation int64, content any) {
	encoded, err := json.Marshal(content)
	if err != nil {
		// Digest rejects malformed inputs rather than publishing a partial identity.
		encoded = nil
	}
	c.inputs[id] = snapshot.Input{
		Group: id.gvr.Group, Kind: id.kind, Namespace: id.namespace, Name: id.name,
		Generation: generation, Content: encoded,
	}
}

func (c *compiler) putHost(port uint16, hostname string, value snapshot.Host) {
	if c.data.Ports[port] == nil {
		c.data.Ports[port] = make(map[string]snapshot.Host)
	}
	c.data.Ports[port][hostname] = value
}

func (c *compiler) clientCA(host config.Host) []byte {
	profile, ok := c.cfg.ClientCertProfiles[classOf(host.Protection, "mtls:")]
	if !ok {
		return nil
	}
	values, _ := secretValues(c.objects.get(secrets, c.op.namespace, profile.CASecret))
	if !validCA(values[caKey], c.now) {
		return nil
	}
	return values[caKey]
}
