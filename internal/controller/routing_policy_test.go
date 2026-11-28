package controller

import (
	"maps"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zekihan/gatehouse/internal/config"
	policy "github.com/zekihan/gatehouse/internal/policy/v1alpha1"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

func TestDuplicateTargetRefsDoNotChangeConflictDetection(t *testing.T) {
	t.Parallel()
	anchor := strings.Repeat("ab", 32)
	spec := map[string]any{
		"mtls": map[string]any{
			"identities":     []any{"urn:noqer:mtls:clients:admin"},
			"trustedAnchors": []any{anchor},
		},
	}
	t.Run("whole route", func(t *testing.T) {
		t.Parallel()
		whole := policyObjects(t, routePolicies, "", spec)
		matches := newRoutePolicyIndex(whole).selectPolicies(key{httpRoutes, "app", "route"}, "")
		route := snapshot.Route{
			Namespace: "app", Name: "route", Path: "/state", Exact: true, Method: "GET",
		}
		failure := policyCompiler().applyRoutePolicies(&route, mtlsContext(), matches)
		if len(matches) != 1 || failure != "" || route.MTLS == nil || route.InvalidPolicy {
			t.Fatalf(
				"one RoutePolicy with duplicate targetRefs: matches=%d failure=%q mtls=%t invalid=%t",
				len(matches),
				failure,
				route.MTLS != nil,
				route.InvalidPolicy,
			)
		}
	})
	t.Run("backend port", func(t *testing.T) {
		t.Parallel()
		ports := policyObjects(t, backendPolicies, "http", map[string]any{})
		backendMatches := newBackendIndex(ports).service[target{"app", "route", "http"}]
		if len(backendMatches) != 1 {
			t.Fatalf("BackendPolicy targetRefs indexed %d times", len(backendMatches))
		}
	})
}

func TestTwoPoliciesStillConflictWhenTargetRefsRepeat(t *testing.T) {
	t.Parallel()
	spec := map[string]any{"accessLog": "off"}
	objects := Objects{items: map[key]*unstructured.Unstructured{}}
	for i, name := range []string{"older", "newer"} {
		obj := policyObject(routePolicies, name, "", spec)
		obj.SetCreationTimestamp(metav1.NewTime(time.Unix(int64(i+1), 0).UTC()))
		objects.items[key{routePolicies, "app", name}] = obj
	}
	matches := newRoutePolicyIndex(objects).selectPolicies(key{httpRoutes, "app", "route"}, "")
	if len(matches) != 2 || matches[0].obj.GetName() != "older" ||
		matches[1].obj.GetName() != "newer" {
		names := make([]string, len(matches))
		for i, match := range matches {
			names[i] = match.obj.GetName()
		}
		t.Fatalf("bindings = %v, want one per policy in age order", names)
	}
}

func TestBackendPolicyRejectsReservedStickyCookie(t *testing.T) {
	t.Parallel()
	plan := &snapshot.Backend{}
	if _, reason := useBackendPolicy(
		plan,
		policy.BackendPolicySpec{StickyCookie: "app-sticky"},
	); reason != "" ||
		plan.StickyCookie != "app-sticky" {
		t.Fatalf("ordinary sticky cookie rejected: %q", reason)
	}
	_, reason := useBackendPolicy(plan, policy.BackendPolicySpec{
		StickyCookie: "__Secure-gatehouse-session-user",
	})
	if reason != "InvalidStickyCookie" || plan.StickyCookie == "__Secure-gatehouse-session-user" {
		t.Fatalf("reserved sticky cookie result %q cookie %q", reason, plan.StickyCookie)
	}
}

func TestExceptionGrantDropsAppRewrite(t *testing.T) {
	t.Parallel()
	route := snapshot.Route{
		Namespace: "jellyfin", Name: "health", Path: "/health", Exact: true, Method: "GET",
	}
	replacement := "/secret"
	if !applyRewrite(&route, &gateway.HTTPURLRewriteFilter{
		Path: &gateway.HTTPPathModifier{
			Type:            gateway.FullPathHTTPPathModifier,
			ReplaceFullPath: &replacement,
		},
	}) {
		t.Fatal("app rewrite was rejected before policy merge")
	}
	host := config.Host{
		Namespace: "jellyfin", Protection: "oidc:user",
		Exceptions: []config.Exception{{
			Path: "/health", Methods: []string{"GET"}, ForwardAuth: "gatus-bearer",
		}},
	}
	compiler := policyCompiler()
	obj := policyObject(routePolicies, "health", "", map[string]any{
		"auth": map[string]any{"forwardAuth": "gatus-bearer"},
	})
	failure := compiler.applyRoutePolicies(&route, ruleContext{
		id: key{httpRoutes, "jellyfin", "health"}, object: obj, registry: host,
	}, []binding[policy.RoutePolicySpec]{{
		obj: obj, spec: policy.RoutePolicySpec{Auth: &policy.Auth{ForwardAuth: "gatus-bearer"}},
	}})
	if failure != "" || route.ForwardAuth != "gatus-bearer" || route.Rewrite != nil {
		t.Fatalf(
			"exception grant failure=%q auth=%q rewrite=%+v",
			failure, route.ForwardAuth, route.Rewrite,
		)
	}
}

func policyCompiler() *compiler {
	return &compiler{
		cfg:      &config.Config{},
		statuses: map[key]*objectStatus{},
		inputs:   map[key]snapshot.Input{},
	}
}

func mtlsContext() ruleContext {
	obj := policyObject(routePolicies, "state", "", nil)
	return ruleContext{
		id: key{httpRoutes, "app", "route"}, object: obj,
		registry: config.Host{
			Namespace: "app", Protection: "mtls:clients",
			Identities: []string{"urn:noqer:mtls:clients:admin"},
		},
	}
}

func policyObjects(
	t *testing.T,
	res resource,
	section string,
	spec map[string]any,
) Objects {
	t.Helper()
	obj := policyObject(res, "only", section, spec)
	return Objects{items: map[key]*unstructured.Unstructured{
		{res, "app", "only"}: obj,
	}}
}

func policyObject(
	res resource,
	name, section string,
	spec map[string]any,
) *unstructured.Unstructured {
	ref := map[string]any{"group": gatewayGroup, "kind": resTargetKind(res), "name": "route"}
	if res == backendPolicies {
		ref["group"] = ""
		ref["kind"] = services.kind
	}
	if section != "" {
		ref["sectionName"] = section
	}
	body := map[string]any{"targetRefs": []any{ref, ref}}
	maps.Copy(body, spec)
	obj := &unstructured.Unstructured{Object: map[string]any{"spec": body}}
	obj.SetNamespace("app")
	obj.SetName(name)
	return obj
}

func resTargetKind(res resource) string {
	if res == backendPolicies {
		return services.kind
	}
	return httpRoutes.kind
}
