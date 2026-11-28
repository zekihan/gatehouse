package controller

import (
	"context"
	"log/slog"
	"reflect"
	"slices"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"
)

const configAccepted = "ConfigAccepted"

func referenceFor(id key, section string) gateway.ParentReference {
	kind := gateway.Kind(id.kind)
	group := gateway.Group(id.gvr.Group)
	namespace := gateway.Namespace(id.namespace)
	ref := gateway.ParentReference{
		Group: &group, Kind: &kind, Namespace: &namespace, Name: gateway.ObjectName(id.name),
	}
	if section != "" {
		name := gateway.SectionName(section)
		ref.SectionName = &name
	}
	return ref
}

func sameRef(a, b gateway.ParentReference) bool { return reflect.DeepEqual(a, b) }

func (c *Controller) publishBootstrapStatus(objects Objects, rejected bool) {
	id := key{gateways, c.options.Namespace, c.options.Gateway}
	obj := objects.get(id.resource, id.namespace, id.name)
	gw, ok := decode[gateway.Gateway](obj)
	if !ok {
		return
	}
	class, ok := decode[gateway.GatewayClass](
		objects.get(classes, "", string(gw.Spec.GatewayClassName)),
	)
	if !ok || class.Spec.ControllerName != controllerName {
		return
	}
	status := &objectStatus{id: id, generation: obj.GetGeneration(), object: obj}
	for _, listener := range gw.Spec.Listeners {
		status.listeners = append(status.listeners, &listenerStatus{
			name: string(
				listener.Name,
			),
			port:     portNumber(listener.Port),
			protocol: listener.Protocol,
		})
	}
	c.startup.Store(
		&published{statuses: map[key]*objectStatus{id: status}, configRejected: rejected},
	)
}

func (c *Controller) publishStatus(
	ctx context.Context,
	current *published,
	replicasProgrammed bool,
) {
	for _, status := range current.statuses {
		if ctx.Err() != nil || !sameReport(current, c.currentReport()) {
			return
		}
		err := c.writeStatus(ctx, current, status, replicasProgrammed)
		if err != nil && ctx.Err() == nil && !kerror.IsNotFound(err) && !kerror.IsConflict(err) {
			c.logger.WarnContext(ctx, "Could not publish Gatehouse status",
				slog.String("kind", status.id.kind),
				slog.String("namespace", status.id.namespace),
				slog.String("name", status.id.name),
			)
		}
	}
}

func sameReport(a, b *published) bool {
	if a.configGeneration != b.configGeneration || a.configRejected != b.configRejected {
		return false
	}
	if a.snapshot == nil || b.snapshot == nil {
		return a.snapshot == b.snapshot
	}
	return a.snapshot.Digest == b.snapshot.Digest
}

func (c *Controller) writeStatus(
	ctx context.Context,
	current *published,
	status *objectStatus,
	replicasProgrammed bool,
) error {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	before, _, err := unstructured.NestedMap(status.object.Object, "status")
	if err != nil {
		return err
	}
	next, err := status.render(runtime.DeepCopyJSON(before), current, replicasProgrammed)
	if err != nil || reflect.DeepEqual(before, next) {
		return err
	}
	// Keep the informer object's resourceVersion on the write. A concurrent
	// spec or status change causes a conflict and is picked up by the watch.
	obj := status.object.DeepCopy()
	obj.Object["status"] = next
	id := status.id
	_, err = c.client.Resource(id.gvr).
		Namespace(id.namespace).
		UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	return err
}

func (s *objectStatus) render(
	before map[string]any,
	current *published,
	replicasProgrammed bool,
) (map[string]any, error) {
	switch s.id.resource {
	case httpRoutes, tlsRoutes:
		return s.renderParents(before, "parents", "parentRef", replicasProgrammed)
	case backendPolicies, routePolicies, tlsPolicies:
		return s.renderParents(before, "ancestors", "ancestorRef", replicasProgrammed)
	default:
		return s.renderListeners(before, current, replicasProgrammed)
	}
}

type relatedStatus struct {
	Ref        gateway.ParentReference
	Conditions []metav1.Condition
}

func (s *objectStatus) renderParents(
	status map[string]any,
	field, refField string,
	replicasProgrammed bool,
) (map[string]any, error) {
	parents, _, err := unstructured.NestedSlice(status, field)
	if err != nil {
		return nil, err
	}
	ours, others, err := splitParents(parents, refField)
	if err != nil {
		return nil, err
	}
	for _, parent := range s.parents {
		prior := slices.IndexFunc(
			ours,
			func(old relatedStatus) bool { return sameRef(old.Ref, parent.ref) },
		)
		var conditions []metav1.Condition
		if prior >= 0 {
			conditions = ours[prior].Conditions
		}
		conditions = mergeConditions(conditions, s.generation, parent.outcome, replicasProgrammed)
		mappedRef, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&parent.ref)
		if err != nil {
			return nil, err
		}
		record := map[string]any{refField: mappedRef, "controllerName": controllerName}
		if err := setConditions(record, conditions); err != nil {
			return nil, err
		}
		others = append(others, record)
	}
	if status == nil {
		status = make(map[string]any)
	}
	status[field] = others
	return status, nil
}

func splitParents(parents []any, refField string) ([]relatedStatus, []any, error) {
	var ours []relatedStatus
	others := make([]any, 0, len(parents))
	for _, item := range parents {
		object, ok := item.(map[string]any)
		if !ok || object["controllerName"] != controllerName {
			others = append(others, item)
			continue
		}
		var prior relatedStatus
		ref, _, err := unstructured.NestedMap(object, refField)
		if err != nil {
			return nil, nil, err
		}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
			ref,
			&prior.Ref,
		); err != nil {
			return nil, nil, err
		}
		prior.Conditions, err = getConditions(object)
		if err != nil {
			return nil, nil, err
		}
		ours = append(ours, prior)
	}
	return ours, others, nil
}

func (s *objectStatus) renderListeners(
	status map[string]any,
	current *published,
	replicasProgrammed bool,
) (map[string]any, error) {
	if status == nil {
		status = make(map[string]any)
	}
	old, err := getConditions(status)
	if err != nil {
		return nil, err
	}
	if s.id.resource == classes {
		updateCondition(&old, s.generation, accepted, "")
		return status, setConditions(status, old)
	}
	overall := s.aggregate()
	conditions := mergeConditions(old, s.generation, overall, replicasProgrammed)
	if s.id.resource == gateways {
		if err := s.renderGateway(status, current, &conditions); err != nil {
			return nil, err
		}
	}
	if err := setConditions(status, conditions); err != nil {
		return nil, err
	}
	return s.renderListenerItems(status, replicasProgrammed)
}

func (s *objectStatus) aggregate() outcome {
	result := s.outcome
	if len(s.listeners) == 0 || result.rejected != "" {
		return result
	}
	valid := false
	for _, status := range s.listeners {
		if status.rejected == "" {
			valid = true
		}
		if !status.valid() {
			result.unresolved = "ListenersNotReady"
		}
	}
	if !valid {
		result.rejected = "NoValidListeners"
	}
	return result
}

func (s *objectStatus) renderGateway(
	status map[string]any,
	current *published,
	conditions *[]metav1.Condition,
) error {
	reason, conditionStatus, message := configCondition(current)

	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               configAccepted,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: s.generation,
	})
	attached := int64(0)
	for _, item := range current.statuses {
		if item.id.resource == listenerSets && item.aggregate().rejected == "" {
			attached++
		}
	}
	status["attachedListenerSets"] = attached
	addresses := make([]any, 0, len(s.addresses))
	for _, address := range s.addresses {
		converted, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&address)
		if err != nil {
			return err
		}
		addresses = append(addresses, converted)
	}
	status["addresses"] = addresses
	return nil
}

func configCondition(current *published) (string, metav1.ConditionStatus, string) {
	if current.configRejected {
		message := "Rejected the operator ConfigMap"
		if current.configGeneration != "" {
			message += ". Serving resource version " + current.configGeneration
		}
		return "InvalidOperatorConfiguration", metav1.ConditionFalse, message
	}
	if current.configGeneration == "" {
		return pending, metav1.ConditionUnknown, "Waiting for bootstrap configuration and trust"
	}
	return "Valid", metav1.ConditionTrue, "Serving operator ConfigMap resource version " + current.configGeneration
}

func (s *objectStatus) renderListenerItems(
	status map[string]any,
	replicasProgrammed bool,
) (map[string]any, error) {
	old, _, err := unstructured.NestedSlice(status, "listeners")
	if err != nil {
		return nil, err
	}
	listeners := make([]any, 0, len(s.listeners))
	for _, listener := range s.listeners {
		record, err := listener.render(old, s.generation, replicasProgrammed)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, record)
	}
	status["listeners"] = listeners
	return status, nil
}

func (l *listenerStatus) render(
	old []any,
	generation int64,
	replicasProgrammed bool,
) (map[string]any, error) {
	var prior []metav1.Condition
	for _, item := range old {
		if record, ok := item.(map[string]any); ok && record["name"] == l.name {
			conditions, err := getConditions(record)
			if err != nil {
				return nil, err
			}
			prior = conditions
			break
		}
	}
	kinds := make([]any, 0, 1)
	if kind := protocolRouteKind(l.protocol); kind != "" {
		kinds = append(kinds, map[string]any{"group": gatewayGroup, "kind": kind})
	}
	next := map[string]any{
		"name":           l.name,
		"supportedKinds": kinds,
		"attachedRoutes": int64(l.attached),
	}
	return next, setConditions(
		next,
		mergeConditions(prior, generation, l.outcome, replicasProgrammed),
	)
}

func mergeConditions(
	conditions []metav1.Condition,
	generation int64,
	decision outcome,
	replicasProgrammed bool,
) []metav1.Condition {
	updateCondition(&conditions, generation, accepted, decision.rejected)
	updateCondition(&conditions, generation, resolved, decision.unresolved)
	reason := decision.rejected
	if reason == "" {
		reason = decision.unresolved
	}
	if reason == "" && !replicasProgrammed {
		reason = pending
	}
	updateCondition(&conditions, generation, programmed, reason)
	return conditions
}

func updateCondition(conditions *[]metav1.Condition, generation int64, condition, failure string) {
	status := metav1.ConditionTrue
	reason, message := condition, condition
	if failure != "" {
		status = metav1.ConditionFalse
		reason, message = failure, failure
		if failure == pending {
			message = "Waiting for all ready Gatehouse replicas to acknowledge this snapshot"
		}
	}
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               condition,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
}

func getConditions(status map[string]any) ([]metav1.Condition, error) {
	var container struct {
		Conditions []metav1.Condition `json:"conditions"`
	}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(status, &container)
	return container.Conditions, err
}

func setConditions(status map[string]any, conditions []metav1.Condition) error {
	container := struct {
		Conditions []metav1.Condition `json:"conditions"`
	}{conditions}
	data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&container)
	if err == nil {
		status["conditions"] = data["conditions"]
	}
	return err
}

func hasOwnedParent(obj *unstructured.Unstructured, field string) bool {
	parents, _, err := unstructured.NestedSlice(obj.Object, "status", field)
	if err != nil {
		return false
	}
	for _, item := range parents {
		if parent, ok := item.(map[string]any); ok &&
			parent["controllerName"] == controllerName {
			return true
		}
	}
	return false
}
