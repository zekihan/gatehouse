//go:build integration || conformance

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	auth "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/dataplane"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

const (
	testNamespace      = "bazarr"
	testServiceAccount = "gatehouse"
	testHost           = "bazarr.noqer.com"
)

type testCluster struct {
	t        *testing.T
	core     *coreclient.CoreV1Client
	dynamic  dynamic.Interface
	config   *rest.Config
	operator []byte
	ca       []byte
	anchor   string
}

func TestKubernetesController(t *testing.T) {
	cluster := connectCluster(t)
	cluster.bootstrap()

	first := cluster.start("gatehouse-alpha", nil)
	await(t, "first valid bootstrap and translated mTLS route", func() bool {
		host := servedHost(first)
		return first.Ready() && len(host.Routes) == 1 && !host.Routes[0].InvalidPolicy &&
			len(host.Routes[0].Backends) == 1 &&
			slices.Equal(host.Routes[0].Backends[0].Backend.Endpoints, []string{"10.42.9.1:8081"})
	})
	await(t, "translated TLSRoute with PROXY v2 and ClusterIP", func() bool {
		host := first.Snapshot().DataPlane.Ports[8445]["mesh-fixture.noqer.com"]
		return host.Passthrough != nil && host.Passthrough.ProxyV2 &&
			host.Passthrough.ClusterIP != ""
	})
	cluster.verifyRBAC()
	cluster.verifyPolicyAdmission()
	cluster.verifyGatewayHealth(first)
	cluster.verifyLabelRemoval(first)
	cluster.verifyPolicyConflict(first)
	cluster.verifyDependencyUpdates(first)
	cluster.verifyBackendTrust(first)
	cluster.verifyInvalidOperator(first)
	cluster.verifyOutage()
}

func connectCluster(t *testing.T) *testCluster {
	t.Helper()
	path := os.Getenv("GATEHOUSE_TEST_KUBECONFIG")
	if path == "" {
		t.Skip("run make test/controller to start the disposable k3s cluster")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	check(t, err)
	core, err := coreclient.NewForConfig(cfg)
	check(t, err)
	client, err := dynamic.NewForConfig(cfg)
	check(t, err)
	data, err := os.ReadFile("../../examples/operator.yaml")
	check(t, err)
	cfgDocument, err := config.Parse(data)
	check(t, err)
	cfgDocument.Hosts["mesh-fixture.noqer.com"] = config.Host{
		Namespace: testNamespace, Ports: []uint16{8445}, DNSGroup: "none", Protection: "public",
	}
	operator, err := json.Marshal(cfgDocument)
	check(t, err)
	return &testCluster{
		t:        t,
		core:     core,
		dynamic:  client,
		config:   cfg,
		operator: operator,
	}
}

func (c *testCluster) bootstrap() {
	c.t.Helper()
	c.label("allowed")
	c.operatorConfig(c.operator)
	c.ca, c.anchor = testCertificate(c.t, "", true)
	c.secret(defaultNamespace, "mtls-clients-v1-trust", map[string][]byte{caKey: c.ca})
	c.secret(
		defaultNamespace,
		"cloudflare-edge-auth",
		map[string][]byte{"current": []byte("disposable-edge")},
	)
	c.secret(defaultNamespace, bootstrapSecret, bootstrapValues())
	cert, privateKey := testCertificate(c.t, testHost, false)
	c.secret(testNamespace, "bazarr-tls", map[string][]byte{
		corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: []byte(privateKey),
	})
	c.endpoints("10.42.9.1", true)
	c.createPolicy("old-policy", "web")
}

func bootstrapValues() map[string][]byte {
	key := []byte(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	return map[string][]byte{
		"oidc-admin-client-secret": []byte(
			"disposable-admin",
		),
		"oidc-user-client-secret": []byte("disposable-user"),
		"cookie-admin-current":    key,
		"cookie-admin-previous":   key,
		"cookie-user-current":     key,
		"cookie-user-previous":    key,
		"gossip-current":          key,
		"gossip-previous":         key,
		"crowdsec-lapi-key":       []byte("disposable-bouncer"),
	}
}

func testCertificate(t *testing.T, host string, ca bool) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(
			1,
		),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if host != "" {
		template.DNSNames = []string{host}
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	check(t, err)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if ca {
		fingerprint := sha256.Sum256(cert)
		return pemCert, hex.EncodeToString(fingerprint[:])
	}
	privateKey, err := x509.MarshalECPrivateKey(key)
	check(t, err)
	return pemCert, string(
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKey}),
	)
}

func (c *testCluster) label(value string) {
	c.t.Helper()
	ns, err := c.core.Namespaces().Get(c.t.Context(), testNamespace, metav1.GetOptions{})
	check(c.t, err)
	if value == "" {
		delete(ns.Labels, attachmentLabel)
	} else {
		ns.Labels[attachmentLabel] = value
	}
	_, err = c.core.Namespaces().Update(c.t.Context(), ns, metav1.UpdateOptions{})
	check(c.t, err)
}

func (c *testCluster) operatorConfig(data []byte) {
	c.t.Helper()
	cfg := c.core.ConfigMaps(defaultNamespace)
	obj := &corev1.ConfigMap{
		Name: defaultConfigMap, Namespace: defaultNamespace,
		Data: map[string]string{defaultConfigKey: string(data)},
	}
	_, err := cfg.Create(c.t.Context(), obj, metav1.CreateOptions{})
	if !kerror.IsAlreadyExists(err) {
		check(c.t, err)
		return
	}
	current, err := cfg.Get(c.t.Context(), defaultConfigMap, metav1.GetOptions{})
	check(c.t, err)
	current.Data = obj.Data
	_, err = cfg.Update(c.t.Context(), current, metav1.UpdateOptions{})
	check(c.t, err)
}

func (c *testCluster) secret(namespace, name string, data map[string][]byte) {
	c.t.Helper()
	access := c.core.Secrets(namespace)
	obj, err := access.Get(c.t.Context(), name, metav1.GetOptions{})
	if kerror.IsNotFound(err) {
		_, err = access.Create(c.t.Context(), &corev1.Secret{
			Name: name, Namespace: namespace, Data: data,
		}, metav1.CreateOptions{})
	} else if err == nil {
		obj.Data = data
		_, err = access.Update(c.t.Context(), obj, metav1.UpdateOptions{})
	}
	if err != nil {
		c.t.Fatalf("writing disposable Secret %s/%s failed", namespace, name)
	}
}

func (c *testCluster) endpoints(address string, ready bool) {
	c.t.Helper()
	name := "bazarr-fixture"
	svc, err := c.core.Services(testNamespace).Get(c.t.Context(), "bazarr", metav1.GetOptions{})
	check(c.t, err)
	body := map[string]any{
		"apiVersion": "discovery.k8s.io/v1",
		"kind":       "EndpointSlice",
		"metadata": map[string]any{
			"name":      name,
			"namespace": testNamespace,
			"labels": map[string]any{
				"kubernetes.io/service-name":             svc.Name,
				"endpointslice.kubernetes.io/managed-by": "gatehouse-test",
			},
			"ownerReferences": []any{
				map[string]any{
					"apiVersion": "v1",
					"kind":       "Service",
					"name":       svc.Name,
					"uid":        string(svc.UID),
				},
			},
		},
		"addressType": "IPv4",
		"ports": []any{
			map[string]any{"name": "http", "protocol": "TCP", "port": int64(8081)},
		},
		"endpoints": []any{
			map[string]any{
				"addresses":  []any{address},
				"conditions": map[string]any{"ready": ready},
			},
		},
	}
	api := c.dynamic.Resource(endpointSlices.gvr).Namespace(testNamespace)
	old, err := api.Get(c.t.Context(), name, metav1.GetOptions{})
	obj := &unstructured.Unstructured{Object: body}
	if kerror.IsNotFound(err) {
		_, err = api.Create(c.t.Context(), obj, metav1.CreateOptions{})
	} else if err == nil {
		obj.SetResourceVersion(old.GetResourceVersion())
		_, err = api.Update(c.t.Context(), obj, metav1.UpdateOptions{})
	}
	check(c.t, err)
}

func (c *testCluster) createPolicy(name, section string) {
	c.t.Helper()
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gatehouse.noqer.com/v1alpha1", "kind": "RoutePolicy",
		"metadata": map[string]any{"name": name, "namespace": testNamespace},
		"spec": map[string]any{
			"targetRefs": []any{
				map[string]any{
					"group":       gatewayGroup,
					"kind":        "HTTPRoute",
					"name":        "bazarr",
					"sectionName": section,
				},
			},
			"mtls": map[string]any{
				"identities": []any{
					"urn:noqer:mtls:clients:z-arch",
				},
				"trustedAnchors": []any{c.anchor},
			},
		},
	}}
	api := c.dynamic.Resource(routePolicies.gvr).Namespace(testNamespace)
	_, err := api.Create(c.t.Context(), obj, metav1.CreateOptions{})
	check(c.t, err)
}

func (c *testCluster) credentials() *rest.Config {
	c.t.Helper()
	token, err := c.core.ServiceAccounts(defaultNamespace).
		CreateToken(c.t.Context(), testServiceAccount, &auth.TokenRequest{}, metav1.CreateOptions{})
	if err != nil {
		c.t.Fatal("creating disposable service account token failed")
	}
	cfg := rest.AnonymousClientConfig(c.config)
	cfg.BearerToken = token.Status.Token
	return cfg
}

func (c *testCluster) verifyRBAC() {
	c.t.Helper()
	client, err := dynamic.NewForConfig(c.credentials())
	check(c.t, err)
	_, err = client.Resource(secrets.gvr).
		Namespace(testNamespace).
		List(c.t.Context(), metav1.ListOptions{})
	if !kerror.IsForbidden(err) {
		c.t.Fatal("RBAC allowed unfiltered Secret list")
	}
	_, err = client.Resource(secrets.gvr).Namespace(testNamespace).
		List(c.t.Context(), metav1.ListOptions{FieldSelector: "metadata.name=bazarr-tls"})
	check(c.t, err)
	_, err = client.Resource(secrets.gvr).Namespace(testNamespace).
		List(c.t.Context(), metav1.ListOptions{FieldSelector: "metadata.name=other-secret"})
	if !kerror.IsForbidden(err) {
		c.t.Fatal("RBAC allowed a different Secret name")
	}
}

func (c *testCluster) verifyPolicyAdmission() {
	c.t.Helper()
	api := c.dynamic.Resource(backendPolicies.gvr).Namespace(testNamespace)
	wrongTarget := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gatehouse.noqer.com/v1alpha1", "kind": backendPolicies.kind,
		"metadata": map[string]any{"name": "invalid-target", "namespace": testNamespace},
		"spec": map[string]any{"targetRefs": []any{map[string]any{
			"group": "", "kind": services.kind, "name": "bazarr",
		}}},
	}}
	_, err := api.Create(
		c.t.Context(),
		wrongTarget,
		metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}},
	)
	if !kerror.IsInvalid(err) {
		c.t.Fatal("BackendPolicy CEL must reject a Service target without a port section")
	}
}

func (c *testCluster) start(name string, offline *atomic.Bool) *Controller {
	c.t.Helper()
	api := c.core.Pods(defaultNamespace)
	pod, err := api.Create(c.t.Context(), &corev1.Pod{
		Name:      name,
		Namespace: defaultNamespace,
		Labels:    map[string]string{"app.kubernetes.io/name": "gatehouse"},
		Spec: corev1.PodSpec{
			SchedulerName:      "gatehouse-test-disabled",
			ServiceAccountName: testServiceAccount,
			Containers: []corev1.Container{
				{Name: "fixture", Image: "unused.invalid/placeholder"},
			},
		},
	}, metav1.CreateOptions{})
	check(c.t, err)
	cfg := c.credentials()
	if offline != nil {
		cfg.Wrap(
			func(next http.RoundTripper) http.RoundTripper { return disconnected{next, offline} },
		)
	}
	proxy := dataplane.New(dataplane.Options{})
	controller, err := New(
		cfg,
		Options{
			PodName: name,
			PodUID:  string(pod.UID),
			Install: proxy.Update,
		},
	)
	check(c.t, err)
	ctx, cancel := context.WithCancel(c.t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- controller.Run(ctx) }()
	c.t.Cleanup(func() {
		cancel()
		check(c.t, <-stopped)
	})
	return controller
}

type disconnected struct {
	next    http.RoundTripper
	offline *atomic.Bool
}

func (d disconnected) RoundTrip(req *http.Request) (*http.Response, error) {
	if d.offline.Load() {
		return nil, errors.New("disposable Kubernetes API outage")
	}
	return d.next.RoundTrip(req)
}

func servedHost(c *Controller) snapshot.Host {
	if current := c.Snapshot(); current != nil {
		return current.DataPlane.Ports[8443][testHost]
	}
	return snapshot.Host{}
}

func await(t *testing.T, want string, condition func() bool) {
	t.Helper()
	timer := time.NewTimer(48 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-timer.C:
			t.Fatalf("timed out waiting for %s", want)
		case <-tick.C:
		}
	}
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (c *testCluster) verifyGatewayHealth(first *Controller) {
	c.t.Helper()
	// Neither an installed snapshot nor a Lease counts without a ready Pod.
	await(c.t, "Programmed=False with zero ready replicas", func() bool {
		return c.hasCondition(
			gateways,
			defaultNamespace,
			defaultGateway,
			programmed,
			"False",
			pending,
		)
	})
	c.setPodReady(first.options.PodName, true)
	await(c.t, "one ready and current replica", func() bool {
		return c.hasCondition(
			gateways,
			defaultNamespace,
			defaultGateway,
			programmed,
			"True",
			programmed,
		) &&
			c.hasCondition(httpRoutes, testNamespace, "bazarr", programmed, "True", programmed) &&
			c.hasCondition(tlsRoutes, testNamespace, "mesh", programmed, "True", programmed) &&
			c.hasCondition(
				tlsRoutes,
				testNamespace,
				"a-mesh-wildcard",
				accepted,
				"False",
				conflicted,
			)
	})
	var lagging atomic.Bool
	second := c.start("gatehouse-bravo", &lagging)
	await(c.t, "stable digest across replicas", func() bool {
		return second.Ready() && second.Snapshot().Digest == first.Snapshot().Digest
	})
	lagging.Store(true)
	c.setPodReady(second.options.PodName, true)
	await(
		c.t,
		"pending for a ready replica with an acknowledgement older than its readiness",
		func() bool {
			return c.hasCondition(
				gateways,
				defaultNamespace,
				defaultGateway,
				programmed,
				"False",
				pending,
			)
		},
	)
	lagging.Store(false)
	await(c.t, "both ready replicas acknowledged", func() bool {
		return c.hasCondition(
			gateways,
			defaultNamespace,
			defaultGateway,
			programmed,
			"True",
			programmed,
		)
	})
	c.setPodReady(second.options.PodName, false)
}

func (c *testCluster) setPodReady(name string, ready bool) {
	c.t.Helper()
	pods := c.core.Pods(defaultNamespace)
	pod, err := pods.Get(c.t.Context(), name, metav1.GetOptions{})
	check(c.t, err)
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	pod.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodReady, Status: status, LastTransitionTime: metav1.Now()},
	}
	_, err = pods.UpdateStatus(c.t.Context(), pod, metav1.UpdateOptions{})
	check(c.t, err)
}

func (c *testCluster) hasCondition(res resource, namespace, name, kind, state, reason string) bool {
	obj, err := c.dynamic.Resource(res.gvr).
		Namespace(namespace).
		Get(c.t.Context(), name, metav1.GetOptions{})
	if err != nil {
		return false
	}
	status, _, err := unstructured.NestedMap(obj.Object, "status")
	if err != nil {
		return false
	}
	path := []string{}
	switch res {
	case httpRoutes, tlsRoutes:
		path = []string{"parents"}
	case routePolicies, backendPolicies, tlsPolicies:
		path = []string{"ancestors"}
	}
	if len(path) == 0 {
		return conditionEquals(status, obj.GetGeneration(), kind, state, reason)
	}
	parents, _, _ := unstructured.NestedSlice(status, path...)
	for _, parent := range parents {
		if value, ok := parent.(map[string]any); ok &&
			conditionEquals(value, obj.GetGeneration(), kind, state, reason) {
			return true
		}
	}
	return false
}

func conditionEquals(status map[string]any, generation int64, kind, state, reason string) bool {
	conditions, err := getConditions(status)
	return err == nil && slices.ContainsFunc(conditions, func(c metav1.Condition) bool {
		return c.Type == kind && string(c.Status) == state && c.Reason == reason &&
			c.ObservedGeneration == generation
	})
}

func (c *testCluster) verifyLabelRemoval(controller *Controller) {
	c.t.Helper()
	old := controller.Snapshot().Digest
	c.label("")
	await(
		c.t,
		"immediate ListenerSet detachment with the registry protection retained",
		func() bool {
			current := controller.Snapshot()
			return current.Digest != old && servedHost(controller).Certificate == nil &&
				current.Config.Hosts[testHost].Protection == "mtls:clients"
		},
	)
	await(c.t, "rejected ListenerSet status", func() bool {
		return c.hasCondition(
			listenerSets,
			testNamespace,
			"bazarr",
			accepted,
			"False",
			"NotAllowed",
		)
	})
	c.label("allowed")
	await(
		c.t,
		"ListenerSet reattachment",
		func() bool { return servedHost(controller).Certificate != nil },
	)
}

func (c *testCluster) verifyPolicyConflict(controller *Controller) {
	c.t.Helper()
	c.createPolicy("z-conflict", "web")
	await(c.t, "terminal protected-route policy conflict", func() bool {
		host := servedHost(controller)
		return len(host.Routes) == 1 && host.Routes[0].InvalidPolicy
	})
	await(c.t, "new policy marked Conflicted", func() bool {
		return c.hasCondition(
			routePolicies,
			testNamespace,
			"z-conflict",
			accepted,
			"False",
			conflicted,
		) &&
			c.hasCondition(routePolicies, testNamespace, "old-policy", accepted, "True", accepted)
	})
	api := c.dynamic.Resource(routePolicies.gvr).Namespace(testNamespace)
	check(c.t, api.Delete(c.t.Context(), "z-conflict", metav1.DeleteOptions{}))
	await(c.t, "valid route after conflict removal", func() bool {
		host := servedHost(controller)
		return len(host.Routes) == 1 && !host.Routes[0].InvalidPolicy
	})
}

func (c *testCluster) verifyDependencyUpdates(controller *Controller) {
	c.t.Helper()
	old := controller.Snapshot().Digest
	c.endpoints("10.42.9.2", true)
	await(c.t, "endpoint-only snapshot change", func() bool {
		host := servedHost(controller)
		return controller.Snapshot().Digest != old && len(host.Routes) == 1 &&
			len(host.Routes[0].Backends) == 1 &&
			slices.Equal(host.Routes[0].Backends[0].Backend.Endpoints, []string{"10.42.9.2:8081"})
	})
	old = controller.Snapshot().Digest
	ca, _ := testCertificate(c.t, "", true)
	c.secret(defaultNamespace, "mtls-clients-v1-trust", map[string][]byte{caKey: ca})
	await(c.t, "rotated CA and dependency-only digest", func() bool {
		return controller.Snapshot().Digest != old &&
			slices.Equal(servedHost(controller).ClientCA, ca)
	})
	c.secret(
		defaultNamespace,
		"mtls-clients-v1-trust",
		map[string][]byte{caKey: []byte("not a CA")},
	)
	await(c.t, "invalid CA revocation", func() bool {
		return !controller.Ready() && servedHost(controller).Certificate == nil
	})
	c.secret(defaultNamespace, "mtls-clients-v1-trust", map[string][]byte{caKey: c.ca})
	await(
		c.t,
		"restored CA",
		func() bool { return controller.Ready() && servedHost(controller).Certificate != nil },
	)
}

func (c *testCluster) verifyInvalidOperator(controller *Controller) {
	c.t.Helper()
	old := controller.Snapshot().Digest
	c.operatorConfig([]byte("ports: unknown"))
	await(c.t, "invalid update rejected with prior config still serving", func() bool {
		status := controller.ObservabilityState()
		return status.ConfigErrors > 0 && status.OperatorConfigRejected &&
			status.OperatorConfigGeneration != "" && controller.Ready() &&
			controller.Snapshot().Digest == old &&
			c.hasCondition(
				gateways,
				defaultNamespace,
				defaultGateway,
				configAccepted,
				"False",
				"InvalidOperatorConfiguration",
			)
	})
	cold := c.start("gatehouse-cold", nil)
	await(
		c.t,
		"cold replica reports invalid configuration",
		func() bool { return cold.configErrors.Load() > 0 },
	)
	if cold.Ready() || cold.Snapshot() != nil {
		c.t.Fatal("cold replica installed a snapshot from invalid configuration")
	}
	c.operatorConfig(c.operator)
	await(c.t, "cold replica ready after operator repair", func() bool { return cold.Ready() })
}

func (c *testCluster) verifyOutage() {
	c.t.Helper()
	var offline atomic.Bool
	disconnected := c.start("gatehouse-disconnected", &offline)
	await(c.t, "replica bootstrap before outage", func() bool { return disconnected.Ready() })
	old := disconnected.Snapshot().Digest
	lastSync := disconnected.ObservabilityState().APILastSyncTimestamp
	if lastSync == 0 {
		c.t.Fatal("API sync timestamp was not populated after connecting")
	}
	offline.Store(true)
	select {
	case <-c.t.Context().Done():
		c.t.Fatal(c.t.Context().Err())
	case <-time.After(ackInterval + time.Second):
	}
	c.label("")
	select {
	case <-c.t.Context().Done():
		c.t.Fatal(c.t.Context().Err())
	case <-time.After(reconcileInterval + time.Second):
	}
	if !disconnected.Ready() || disconnected.Snapshot().Digest != old ||
		disconnected.ObservabilityState().APILastSyncTimestamp != lastSync {
		c.t.Fatal("API outage disturbed the running replica's snapshot")
	}
	offline.Store(false)
	await(c.t, "replica regains API and applies pending revocation", func() bool {
		return disconnected.Snapshot().Digest != old &&
			servedHost(disconnected).Certificate == nil &&
			disconnected.ObservabilityState().APILastSyncTimestamp > lastSync
	})
}

func (c *testCluster) verifyBackendTrust(controller *Controller) {
	c.t.Helper()
	policies := c.dynamic.Resource(backendPolicies.gvr).Namespace(testNamespace)
	p, err := policies.Get(c.t.Context(), "bazarr", metav1.GetOptions{})
	check(c.t, err)
	check(c.t, unstructured.SetNestedField(p.Object, "required", "spec", "tls"))
	_, err = policies.Update(c.t.Context(), p, metav1.UpdateOptions{})
	check(c.t, err)
	await(c.t, "TLS-required backend denied before trust policy", func() bool {
		host := servedHost(controller)
		return len(host.Routes) == 1 && len(host.Routes[0].Backends) == 1 &&
			host.Routes[0].Backends[0].Backend == nil
	})
	c.createBackendTrust()
	await(c.t, "TLS backend using named ConfigMap CA", func() bool {
		tls := servedBackendTLS(controller)
		return tls != nil && tls.ServerName == "bazarr.bazarr.svc" && slices.Equal(tls.CAPEM, c.ca)
	})
	await(c.t, "BackendTLSPolicy programmed status", func() bool {
		return c.hasCondition(tlsPolicies, testNamespace, "bazarr", programmed, "True", programmed)
	})

	cm := c.core.ConfigMaps(testNamespace)
	ca, _ := testCertificate(c.t, "", true)
	trust, err := cm.Get(c.t.Context(), "bazarr-upstream-ca", metav1.GetOptions{})
	check(c.t, err)
	trust.Data[caKey] = string(ca)
	old := controller.Snapshot().Digest
	_, err = cm.Update(c.t.Context(), trust, metav1.UpdateOptions{})
	check(c.t, err)
	await(c.t, "CA ConfigMap-only update changes digest and upstream roots", func() bool {
		tls := servedBackendTLS(controller)
		return controller.Snapshot().Digest != old && tls != nil && slices.Equal(tls.CAPEM, ca)
	})
}

func (c *testCluster) createBackendTrust() {
	c.t.Helper()
	_, err := c.core.ConfigMaps(testNamespace).Create(c.t.Context(), &corev1.ConfigMap{
		Name: "bazarr-upstream-ca", Namespace: testNamespace,
		Data: map[string]string{caKey: string(c.ca)},
	}, metav1.CreateOptions{})
	check(c.t, err)
	_, err = c.dynamic.Resource(tlsPolicies.gvr).
		Namespace(testNamespace).
		Create(c.t.Context(), &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": gatewayGroup + "/v1", "kind": tlsPolicies.kind,
				"metadata": map[string]any{"name": "bazarr", "namespace": testNamespace},
				"spec": map[string]any{
					"targetRefs": []any{map[string]any{
						"group": "", "kind": services.kind, "name": "bazarr", "sectionName": "http",
					}},
					"validation": map[string]any{
						"hostname": "bazarr.bazarr.svc",
						"caCertificateRefs": []any{map[string]any{
							"group": "", "kind": configMaps.kind, "name": "bazarr-upstream-ca",
						}},
					},
				},
			},
		}, metav1.CreateOptions{})
	check(c.t, err)
}

func servedBackendTLS(controller *Controller) *snapshot.BackendTLS {
	host := servedHost(controller)
	if len(host.Routes) != 1 || len(host.Routes[0].Backends) != 1 ||
		host.Routes[0].Backends[0].Backend == nil {
		return nil
	}
	return host.Routes[0].Backends[0].Backend.TLS
}
