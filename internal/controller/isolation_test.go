package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zekihan/gatehouse/internal/config"
)

// An owning HTTPRoute must not publish a URLRewrite that lands on a registry
// deny path. The inbound deny check runs before the rewrite is applied.
func TestOwningRewriteCannotReachRegistryDeny(t *testing.T) {
	t.Parallel()
	const (
		host      = "s3.example.test"
		namespace = "external-ingress"
	)
	certPEM, keyPEM := isolationCertificate(t, host)
	objects := Objects{items: map[key]*unstructured.Unstructured{}}
	isolationAdd(t, objects, classes, &gateway.GatewayClass{
		Name: "gatehouse",
		Spec: gateway.GatewayClassSpec{ControllerName: controllerName},
	})
	from := gateway.NamespacesFromSelector
	isolationAdd(t, objects, gateways, &gateway.Gateway{
		Namespace: "gatehouse", Name: "gatehouse",
		Spec: gateway.GatewaySpec{
			GatewayClassName: "gatehouse",
			AllowedListeners: &gateway.AllowedListeners{
				Namespaces: &gateway.ListenerNamespaces{
					From: &from,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{attachmentLabel: "allowed"},
					},
				},
			},
			Listeners: []gateway.Listener{{
				Name: "http", Port: 8000, Protocol: gateway.HTTPProtocolType,
			}},
		},
	})
	isolationAdd(t, objects, namespaces, &corev1.Namespace{
		Name:   namespace,
		Labels: map[string]string{attachmentLabel: "allowed"},
	})
	isolationAdd(t, objects, secrets, &corev1.Secret{
		Namespace: namespace, Name: "s3-tls",
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte(certPEM),
			corev1.TLSPrivateKeyKey: []byte(keyPEM),
		},
	})
	hostname := gateway.Hostname(host)
	mode := gateway.TLSModeTerminate
	parentNamespace := gateway.Namespace("gatehouse")
	isolationAdd(t, objects, listenerSets, &gateway.ListenerSet{
		Namespace: namespace, Name: "s3",
		Spec: gateway.ListenerSetSpec{
			ParentRef: gateway.ParentGatewayReference{
				Namespace: &parentNamespace, Name: "gatehouse",
			},
			Listeners: []gateway.ListenerEntry{{
				Name:     "https",
				Hostname: &hostname,
				Port:     8443,
				Protocol: gateway.HTTPSProtocolType,
				TLS: &gateway.ListenerTLSConfig{
					Mode: &mode,
					CertificateRefs: []gateway.SecretObjectReference{{
						Name: "s3-tls",
					}},
				},
			}},
		},
	})
	isolationAdd(t, objects, services, &corev1.Service{
		Namespace: namespace, Name: "s3", UID: "s3-uid",
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "s3"},
			Ports: []corev1.ServicePort{{
				Name: "http", Port: 9000, Protocol: corev1.ProtocolTCP,
			}},
		},
	})
	ready := true
	port := int32(9000)
	protocol := corev1.ProtocolTCP
	portName := "http"
	isolationAdd(t, objects, endpointSlices, &discovery.EndpointSlice{
		Namespace: namespace,
		Name:      "s3",
		Labels:    map[string]string{discovery.LabelServiceName: "s3"},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "v1", Kind: "Service", Name: "s3", UID: "s3-uid",
		}},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{{
			Addresses:  []string{"10.42.9.1"},
			Conditions: discovery.EndpointConditions{Ready: &ready},
		}},
		Ports: []discovery.EndpointPort{{
			Name: &portName, Protocol: &protocol, Port: &port,
		}},
	})
	full := &gateway.HTTPURLRewriteFilter{Path: &gateway.HTTPPathModifier{
		Type:            gateway.FullPathHTTPPathModifier,
		ReplaceFullPath: new("/minio/admin"),
	}}
	prefix := &gateway.HTTPURLRewriteFilter{Path: &gateway.HTTPPathModifier{
		Type:               gateway.PrefixMatchHTTPPathModifier,
		ReplacePrefixMatch: new("/minio/admin"),
	}}
	isolationAdd(t, objects, httpRoutes, isolationRoute(namespace, "web", host, "/", false, nil))
	isolationAdd(
		t, objects, httpRoutes, isolationRoute(namespace, "full", host, "/public", true, full),
	)
	isolationAdd(
		t, objects, httpRoutes, isolationRoute(namespace, "prefix", host, "/out", false, prefix),
	)

	cfg := &config.Config{
		Ports: map[uint16]config.Port{8443: {Identity: "direct"}},
		Hosts: map[string]config.Host{host: {
			Namespace:  namespace,
			Ports:      []uint16{8443},
			Protection: "public",
			Deny:       &config.Deny{Prefixes: []string{"/minio/admin"}},
		}},
	}
	got, err := compile(
		objects, cfg, key{configMaps, "gatehouse", "operator"}, "gatehouse", time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	routes := got.snapshot.DataPlane.Ports[8443][host].Routes
	var control bool
	for _, route := range routes {
		servable := !route.InvalidPolicy && len(route.Backends) == 1 &&
			route.Backends[0].Backend != nil && len(route.Backends[0].Backend.Endpoints) == 1
		if route.Name == "web" && servable {
			control = true
		}
		if !servable || route.Rewrite == nil ||
			!strings.HasPrefix(route.Rewrite.Path, "/minio/admin") {
			continue
		}
		t.Errorf(
			"%s publishes rewrite %q (prefix=%v) onto registry deny /minio/admin",
			route.Name, route.Rewrite.Path, route.Rewrite.Prefix,
		)
	}
	if !control {
		t.Fatal("fixture did not attach the owning route")
	}
}

func isolationRoute(
	namespace, name, host, path string, exact bool, rewrite *gateway.HTTPURLRewriteFilter,
) *gateway.HTTPRoute {
	pathType := gateway.PathMatchPathPrefix
	if exact {
		pathType = gateway.PathMatchExact
	}
	var filters []gateway.HTTPRouteFilter
	if rewrite != nil {
		filters = []gateway.HTTPRouteFilter{{
			Type: gateway.HTTPRouteFilterURLRewrite, URLRewrite: rewrite,
		}}
	}
	hostname := gateway.Hostname(host)
	kind := gateway.Kind("ListenerSet")
	section := gateway.SectionName("https")
	servicePort := gateway.PortNumber(9000)
	return &gateway.HTTPRoute{
		Namespace: namespace, Name: name,
		Spec: gateway.HTTPRouteSpec{
			Hostnames: []gateway.Hostname{hostname},
			ParentRefs: []gateway.ParentReference{{
				Kind: &kind, Name: "s3", SectionName: &section,
			}},
			Rules: []gateway.HTTPRouteRule{{
				Matches: []gateway.HTTPRouteMatch{{
					Path: &gateway.HTTPPathMatch{Type: &pathType, Value: &path},
				}},
				Filters: filters,
				BackendRefs: []gateway.HTTPBackendRef{{
					Name: "s3", Port: &servicePort,
				}},
			}},
		},
	}
}

func isolationAdd(t *testing.T, objects Objects, res resource, obj any) {
	t.Helper()
	data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		t.Fatal(err)
	}
	item := &unstructured.Unstructured{Object: data}
	namespace := item.GetNamespace()
	if res == namespaces || res == classes {
		namespace = ""
	}
	objects.items[key{res, namespace, item.GetName()}] = item
}

func isolationCertificate(t *testing.T, host string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})
	return string(cert), string(keyPEM)
}
