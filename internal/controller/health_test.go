package controller

import (
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
	coordination "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"
)

func TestArgoHealth(t *testing.T) {
	t.Parallel()
	for _, res := range []resource{gateways, listenerSets, httpRoutes, tlsRoutes, tlsPolicies} {
		t.Run(res.kind, func(t *testing.T) {
			t.Parallel()
			id := key{res, "demo", "demo"}
			ref := referenceFor(key{gateways, "demo", "edge"}, "")
			s := &objectStatus{
				id:         id,
				generation: 4,
				parents:    []parentStatus{{ref: ref}},
				listeners: []*listenerStatus{
					{name: "https", port: 8443, protocol: gateway.HTTPSProtocolType},
				},
			}
			p := &published{configGeneration: "12"}
			for _, fixture := range []struct {
				name       string
				programmed bool
				condition  string
				expect     string
			}{
				{"current", true, "", "Healthy"},
				{"lagging-replica", false, "", "Progressing"},
				{"zero-ready-replicas", false, "", "Progressing"},
				{"unresolved-reference", true, "InvalidCertificateRef", "Degraded"},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					status := *s
					status.unresolved = fixture.condition
					status.parents = []parentStatus{{ref: ref, outcome: status.outcome}}
					item := *s.listeners[0]
					item.outcome = status.outcome
					status.listeners = []*listenerStatus{&item}
					rendered, err := status.render(nil, p, fixture.programmed)
					requireNoError(t, err)
					expected := fixture.expect
					if res == listenerSets && fixture.condition != "" {
						expected = "Progressing"
					}
					// The pinned upstream BackendTLSPolicy script only checks
					// Accepted and ResolvedRefs, and ignores Programmed.
					if res == tlsPolicies && fixture.condition == "" {
						expected = "Healthy"
					}
					runLuaHealth(t, res, status.generation, rendered, expected)
				})
			}
		})
	}
}

func runLuaHealth(
	t *testing.T,
	res resource,
	generation int64,
	status map[string]any,
	expected string,
) {
	t.Helper()
	vm := lua.NewState()
	defer vm.Close()
	vm.SetGlobal("obj", toLua(vm, map[string]any{
		"metadata": map[string]any{"generation": generation}, "status": status,
	}))
	requireNoError(t, vm.DoFile("../../tests/integration/testdata/argocd/"+res.kind+".lua"))
	table, ok := vm.Get(-1).(*lua.LTable)
	if !ok || table.RawGetString("status").String() != expected {
		t.Fatalf("Argo health = %v, want %s", vm.Get(-1), expected)
	}
}

//nolint:ireturn // Lua requires its value interface to build a heterogeneous table.
func toLua(vm *lua.LState, input any) lua.LValue {
	switch data := input.(type) {
	case map[string]any:
		table := vm.NewTable()
		for key, value := range data {
			table.RawSetString(key, toLua(vm, value))
		}
		return table
	case []any:
		table := vm.NewTable()
		for _, value := range data {
			table.Append(toLua(vm, value))
		}
		return table
	case string:
		return lua.LString(data)
	case int64:
		return lua.LNumber(data)
	case bool:
		return lua.LBool(data)
	}
	return lua.LNil
}

func TestFreshAcknowledgements(t *testing.T) {
	t.Parallel()
	now := time.Now()
	pod := &corev1.Pod{Name: "demo", UID: "uid"}
	ready := &corev1.PodCondition{LastTransitionTime: metav1.NewTime(now.Add(-time.Minute))}
	uid := string(pod.UID)
	for _, tc := range []struct {
		name   string
		digest string
		age    time.Duration
		want   bool
	}{
		{"current", "snapshot", 5 * time.Second, true},
		{"lagging", "old-snapshot", 5 * time.Second, false},
		{"stale", "snapshot", 31 * time.Second, false},
		{"future", "snapshot", -time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			renew := metav1.NewMicroTime(now.Add(-tc.age))
			lease := coordination.Lease{
				Annotations: map[string]string{digestAnnotation: tc.digest},
				Spec:        coordination.LeaseSpec{HolderIdentity: &uid, RenewTime: &renew},
			}
			if got := acknowledged(pod, ready, lease, "snapshot", now); got != tc.want {
				t.Fatalf("acknowledged = %v, want %v", got, tc.want)
			}
		})
	}
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
