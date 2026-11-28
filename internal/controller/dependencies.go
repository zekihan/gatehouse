package controller

import (
	"encoding/base64"
	"slices"
	"time"

	gateway "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

type requirement struct {
	required []string
	ca       bool
	keyset   bool
}

func requiredWatches(op key, cfg *config.Config) (map[key]requirement, map[key]bool) {
	bootstrapID := key{secrets, op.namespace, bootstrapSecret}
	required := map[key]requirement{
		bootstrapID: {required: []string{
			"oidc-admin-client-secret",
			"oidc-user-client-secret",
			"cookie-admin-current",
			"cookie-admin-previous",
			"cookie-user-current",
			"cookie-user-previous",
			"gossip-current",
			"gossip-previous",
			"crowdsec-lapi-key",
		}, keyset: true},
	}
	named := map[key]bool{
		bootstrapID: true,
		{configMaps, "external-ingress", cfg.DeviceTrust.CAConfigMap}: true,
	}
	for _, profile := range cfg.ClientCertProfiles {
		id := key{secrets, op.namespace, profile.CASecret}
		req := required[id]
		req.ca = true
		required[id] = req
	}
	for _, port := range cfg.Ports {
		if port.EdgeSecret != nil && len(port.EdgeSecret.Keys) != 0 {
			id := key{secrets, op.namespace, port.EdgeSecret.Secret}
			req := required[id]
			req.required = append(req.required, port.EdgeSecret.Keys[0])
			required[id] = req
		}
	}
	for id := range required {
		named[id] = true
	}
	return required, named
}

func bootstrapReady(objects Objects, requirements map[key]requirement, now time.Time) bool {
	for id, req := range requirements {
		data, ok := secretValues(objects.get(id.resource, id.namespace, id.name))
		if !ok || req.ca && !validCA(data[caKey], now) {
			return false
		}
		for _, field := range req.required {
			if len(data[field]) == 0 || req.keyset && !validBootstrapKey(field, data[field]) {
				return false
			}
		}
	}
	return true
}

func validBootstrapKey(name string, data []byte) bool {
	fields := []string{
		"cookie-admin-current",
		"cookie-admin-previous",
		"cookie-user-current",
		"cookie-user-previous",
		"gossip-current",
		"gossip-previous",
	}
	if !slices.Contains(fields, name) {
		return true
	}
	key, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil && len(key) == 32
}

func (c *compiler) certificateWatches(parent key, cfg *config.Config) map[key]bool {
	desired := make(map[key]bool)
	for _, obj := range c.objects.list(listenerSets, "") {
		set, ok := decode[gateway.ListenerSet](obj)
		if !ok || !setTargets(set, parent) {
			continue
		}
		ns := c.objects.get(namespaces, "", set.Namespace)
		if ns == nil || ns.GetLabels()[attachmentLabel] != "allowed" {
			continue
		}
		for _, listener := range set.Spec.Listeners {
			host, known := cfg.Hosts[string(value(listener.Hostname, ""))]
			if !known || host.Namespace != set.Namespace || listener.TLS == nil ||
				!slices.Contains(host.Ports, portNumber(listener.Port)) {
				continue
			}
			for _, ref := range listener.TLS.CertificateRefs {
				id := certificateID(ref, set.Namespace)
				if id.resource == secrets &&
					c.permittedWithoutRecording(key{listenerSets, set.Namespace, set.Name}, id) {
					desired[id] = true
				}
			}
		}
	}
	return desired
}

func (c *compiler) permittedWithoutRecording(source, target key) bool {
	if c.inputs == nil {
		c.inputs = make(map[key]snapshot.Input)
	}
	return c.permitted(source, target)
}
