//go:build conformance

package controller

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"

	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coordination "k8s.io/client-go/kubernetes/typed/coordination/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"
	upstream "sigs.k8s.io/gateway-api/conformance"
	conformanceconfig "sigs.k8s.io/gateway-api/conformance/utils/config"

	"github.com/zekihan/gatehouse/internal/dataplane"
)

const conformanceOperator = `
ports:
  80: {identity: direct, mode: redirect}
hosts:
  fixture.test: {namespace: gateway-conformance-infra, ports: [80], dnsGroup: none, proxied: false, protection: public}
dnsGroups: {none: null}
clientCertProfiles: {}
forwardAuthClasses: {}
authClasses: {}
lanBackends: []
deviceTrust: {caConfigMap: device-ca, exceptions: []}
defaults:
  crowdsec: false
  limits:
    perRouteClient: {perMinute: 30000, perSecondSlot: 3000, inFlight: 3000}
    perRouteHost: {inFlight: 6000}
  compression: {encodings: [gzip], minBytes: 1024}
`

// The upstream status cases use port 80. Gatehouse gives the complete HTTP port
// to redirects, so remove the host match from the two redirect listeners only.
type redirectManifests struct{}

func (redirectManifests) Open(name string) (fs.File, error) {
	return upstream.Manifests.Open(name)
}

func (redirectManifests) ReadFile(name string) ([]byte, error) {
	data, err := upstream.Manifests.ReadFile(name)
	if err != nil {
		return nil, err
	}
	switch name {
	case "tests/listenerset-allowed-namespace-none.yaml",
		"tests/listenerset-default-not-allowed.yaml":
		const hostname = "    hostname: \"gateway-listener.com\"\n"
		if strings.Count(string(data), hostname) != 1 {
			return nil, errors.New("upstream redirect listener fixture changed")
		}
		return []byte(strings.Replace(string(data), hostname, "", 1)), nil
	default:
		return data, nil
	}
}

func TestGatewayAPIConformance(t *testing.T) {
	cluster := connectCluster(t)
	ns := suite.InfrastructureNamespace
	_, err := cluster.core.Namespaces().Create(t.Context(), &corev1.Namespace{
		Name: ns, Labels: map[string]string{attachmentLabel: "allowed"},
	}, metav1.CreateOptions{})
	check(t, err)
	_, err = cluster.core.ConfigMaps(ns).Create(t.Context(), &corev1.ConfigMap{
		Name: defaultConfigMap,
		Data: map[string]string{defaultConfigKey: conformanceOperator},
	}, metav1.CreateOptions{})
	check(t, err)
	cluster.secret(ns, bootstrapSecret, bootstrapValues())
	_, err = cluster.core.Services(ns).Create(t.Context(), &corev1.Service{
		Name: suite.InfraBackendServiceNameV1,
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8080}},
		},
	}, metav1.CreateOptions{})
	check(t, err)
	_, err = cluster.core.ServiceAccounts(ns).Create(t.Context(), &corev1.ServiceAccount{
		Name: testServiceAccount,
	}, metav1.CreateOptions{})
	check(t, err)
	pod := conformancePod(t, cluster)
	scheme := runtime.NewScheme()
	check(t, corev1.AddToScheme(scheme))
	check(t, gateway.Install(scheme))
	api, err := client.New(cluster.config, client.Options{Scheme: scheme})
	check(t, err)
	timeout := conformanceconfig.DefaultTimeoutConfig()
	applier := kubernetes.Applier{
		GatewayClass: defaultGateway,
		ManifestFS:   []fs.FS{redirectManifests{}},
	}
	conformance := &suite.ConformanceTestSuite{Client: api, TimeoutConfig: timeout}

	for _, group := range []struct {
		gateway string
		cases   []suite.ConformanceTest
	}{
		{"same-namespace", []suite.ConformanceTest{
			tests.HTTPRouteInvalidParentRefNotMatchingListenerPort,
			tests.HTTPRouteInvalidParentRefNotMatchingSectionName,
		}},
		{"gateway-with-one-not-matching-port-and-section-name-route", []suite.ConformanceTest{
			tests.HTTPRouteInvalidParentRefSectionNameNotMatchingPort,
		}},
		{"gateway-does-not-allow-listenerset", []suite.ConformanceTest{
			tests.ListenerSetAllowedNamespaceNone,
		}},
		{"gateway-default-does-not-allow-listenerset", []suite.ConformanceTest{
			tests.ListenerSetDefaultNotAllowed,
		}},
	} {
		t.Run(group.gateway, func(t *testing.T) {
			if group.gateway == "same-namespace" {
				check(t, api.Create(t.Context(), &gateway.Gateway{
					Name: group.gateway, Namespace: ns,
					Spec: gateway.GatewaySpec{
						GatewayClassName: defaultGateway,
						Listeners: []gateway.Listener{
							{Name: "http", Port: 80, Protocol: gateway.HTTPProtocolType},
						},
					},
				}))
				t.Cleanup(func() {
					check(t, api.Delete(context.WithoutCancel(t.Context()), &gateway.Gateway{
						Name: group.gateway, Namespace: ns,
					}))
				})
			}
			startConformanceController(t, cluster, group.gateway, pod)
			for _, entry := range group.cases {
				t.Run(entry.ShortName, func(t *testing.T) {
					for _, manifest := range entry.Manifests {
						applier.MustApplyWithCleanup(t, api, timeout, manifest, true)
					}
					entry.Test(t, conformance)
				})
			}
		})
	}
}

func conformancePod(t *testing.T, cluster *testCluster) *corev1.Pod {
	t.Helper()
	api := cluster.core.Pods(suite.InfrastructureNamespace)
	pod, err := api.Create(t.Context(), &corev1.Pod{
		Name:   "conformance-gatehouse",
		Labels: map[string]string{"app.kubernetes.io/name": "gatehouse"},
		Spec: corev1.PodSpec{
			SchedulerName:      "gatehouse-test-disabled",
			ServiceAccountName: testServiceAccount,
			Containers: []corev1.Container{
				{Name: "fixture", Image: "unused.invalid/placeholder"},
			},
		},
	}, metav1.CreateOptions{})
	check(t, err)
	pod.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionTrue},
	}
	pod, err = api.UpdateStatus(t.Context(), pod, metav1.UpdateOptions{})
	check(t, err)
	return pod
}

func startConformanceController(t *testing.T, cluster *testCluster, name string, pod *corev1.Pod) {
	t.Helper()
	controller, err := New(cluster.config, Options{
		Namespace: pod.Namespace,
		Gateway:   name,
		PodName:   pod.Name,
		PodUID:    string(pod.UID),
		Install:   dataplane.New(dataplane.Options{}).Update,
	})
	check(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- controller.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		check(t, <-stopped)
		coord, err := coordination.NewForConfig(cluster.config)
		check(t, err)
		if err := coord.Leases(pod.Namespace).Delete(
			context.WithoutCancel(t.Context()), leaderLease, metav1.DeleteOptions{},
		); !kerror.IsNotFound(err) {
			check(t, err)
		}
	})
}
