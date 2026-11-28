package controller

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/cache"

	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kschema "k8s.io/apimachinery/pkg/runtime/schema"
	gateway "sigs.k8s.io/gateway-api/apis/v1"

	policy "github.com/zekihan/gatehouse/internal/policy/v1alpha1"
)

const (
	gatewayGroup    = gateway.GroupName
	attachmentLabel = policy.Group + "/listeners"
	controllerName  = policy.Group + "/controller"
	caKey           = "ca.crt"
)

type resource struct {
	gvr  kschema.GroupVersionResource
	kind string
}

func kind(group, version, plural, singular string) resource {
	return resource{
		kschema.GroupVersionResource{Group: group, Version: version, Resource: plural},
		singular,
	}
}

var (
	classes         = kind(gatewayGroup, "v1", "gatewayclasses", "GatewayClass")
	gateways        = kind(gatewayGroup, "v1", "gateways", "Gateway")
	listenerSets    = kind(gatewayGroup, "v1", "listenersets", "ListenerSet")
	httpRoutes      = kind(gatewayGroup, "v1", "httproutes", "HTTPRoute")
	tlsRoutes       = kind(gatewayGroup, "v1", "tlsroutes", "TLSRoute")
	tlsPolicies     = kind(gatewayGroup, "v1", "backendtlspolicies", "BackendTLSPolicy")
	grants          = kind(gatewayGroup, "v1", "referencegrants", "ReferenceGrant")
	routePolicies   = kind(policy.Group, "v1alpha1", "routepolicies", "RoutePolicy")
	backendPolicies = kind(policy.Group, "v1alpha1", "backendpolicies", "BackendPolicy")
	services        = kind("", "v1", "services", "Service")
	endpointSlices  = kind("discovery.k8s.io", "v1", "endpointslices", "EndpointSlice")
	namespaces      = kind("", "v1", "namespaces", "Namespace")
	pods            = kind("", "v1", "pods", "Pod")
	configMaps      = kind("", "v1", "configmaps", "ConfigMap")
	secrets         = kind("", "v1", "secrets", "Secret")
)

type key struct {
	resource

	namespace string
	name      string
}

type informer struct {
	cache.SharedIndexInformer

	cancel context.CancelFunc
	denied atomic.Bool
}

func startInformer(
	ctx context.Context,
	client dynamic.Interface,
	meta metadata.Interface,
	id key,
	changed func(),
) (*informer, error) {
	ctx, cancel := context.WithCancel(ctx)
	named := id.name != ""
	objects := client.Resource(id.gvr).Namespace(id.namespace)
	watcher := &informer{cancel: cancel}
	recordAccess := func(err error) {
		if named && (err == nil || kerror.IsForbidden(err) || kerror.IsUnauthorized(err)) {
			denied := err != nil
			if watcher.denied.Swap(denied) != denied {
				changed()
			}
		}
	}
	list := func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		if named {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", id.name).String()
		}
		list, err := objects.List(ctx, opts)
		recordAccess(err)
		return list, err
	}
	subscribe := func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
		if named {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", id.name).String()
			// Renew authorization for named trust references even when the
			// object has not changed.
			timeout := int64(30)
			opts.TimeoutSeconds = &timeout
		}
		stream, err := objects.Watch(ctx, opts)
		recordAccess(err)
		return stream, err
	}
	var item runtime.Object = &unstructured.Unstructured{}
	if id.resource == namespaces {
		metadataOnly := meta.Resource(id.gvr)
		list = func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return metadataOnly.List(ctx, opts)
		}
		subscribe = metadataOnly.Watch
		item = &metav1.PartialObjectMetadata{}
	}
	source := cache.NewSharedIndexInformer(
		&cache.ListWatch{ListWithContextFunc: list, WatchFuncWithContext: subscribe},
		item, 0, cache.Indexers{},
	)
	if err := source.SetTransform(dropManagedFields); err != nil {
		cancel()
		return nil, err
	}
	if _, err := source.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { changed() },
		DeleteFunc: func(any) { changed() },
		UpdateFunc: func(previous, next any) {
			if objectChanged(id.resource, previous, next) {
				changed()
			}
		},
	}); err != nil {
		cancel()
		return nil, err
	}
	watcher.SharedIndexInformer = source
	go source.RunWithContext(ctx)
	return watcher, nil
}

func dropManagedFields(obj any) (any, error) {
	switch item := obj.(type) {
	case *unstructured.Unstructured:
		item.SetManagedFields(nil)
	case *metav1.PartialObjectMetadata:
		item.SetManagedFields(nil)
	default:
		return nil, fmt.Errorf("unexpected informer type %T", obj)
	}
	return obj, nil
}

func objectChanged(res resource, previous, next any) bool {
	if res.gvr.Group == gatewayGroup || res.gvr.Group == policy.Group {
		old, oldOK := previous.(*unstructured.Unstructured)
		current, currentOK := next.(*unstructured.Unstructured)
		return !oldOK || !currentOK || old.GetGeneration() != current.GetGeneration() ||
			old.GetUID() != current.GetUID()
	}
	return true
}

// Objects is a point-in-time view of the informer stores. Objects are read-only.
type Objects struct {
	items map[key]*unstructured.Unstructured
}

func (o Objects) get(res resource, namespace, name string) *unstructured.Unstructured {
	return o.items[key{res, namespace, name}]
}

func (o Objects) list(res resource, namespace string) []*unstructured.Unstructured {
	var found []*unstructured.Unstructured
	for id, obj := range o.items {
		if id.resource == res && (namespace == "" || namespace == id.namespace) {
			found = append(found, obj)
		}
	}
	slices.SortFunc(found, compareObjectAge)
	return found
}

func compareObjectAge(a, b *unstructured.Unstructured) int {
	return compareIdentity(
		a.GetCreationTimestamp().Compare(b.GetCreationTimestamp().Time),
		a,
		b,
	)
}

func compareIdentity(age int, a, b *unstructured.Unstructured) int {
	if age != 0 {
		return age
	}
	aKey := a.GetNamespace() + "/" + a.GetName()
	bKey := b.GetNamespace() + "/" + b.GetName()
	if aKey < bKey {
		return -1
	}
	if aKey > bKey {
		return 1
	}
	return 0
}

func informerObjects(watches map[key]*informer) Objects {
	objects := Objects{items: make(map[key]*unstructured.Unstructured)}
	for id, watcher := range watches {
		if watcher.denied.Load() {
			continue
		}
		for _, obj := range watcher.GetStore().List() {
			switch item := obj.(type) {
			case *unstructured.Unstructured:
				objects.items[key{id.resource, item.GetNamespace(), item.GetName()}] = item
			case *metav1.PartialObjectMetadata:
				metadataMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(item)
				if err == nil {
					objects.items[key{id.resource, "", item.Name}] = &unstructured.Unstructured{
						Object: metadataMap,
					}
				}
			}
		}
	}
	return objects
}

func decode[T any](obj *unstructured.Unstructured) (*T, bool) {
	if obj == nil {
		return nil, false
	}
	var typed T
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &typed)
	return &typed, err == nil
}
