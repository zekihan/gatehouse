// Package controller builds a Kubernetes-backed Gatehouse snapshot on each replica.
package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coordination "k8s.io/client-go/kubernetes/typed/coordination/v1"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/observability"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

const (
	bootstrapSecret  = "gatehouse-bootstrap"
	defaultNamespace = "gatehouse"
	defaultGateway   = "gatehouse"
	defaultConfigMap = "gatehouse-operator"
	defaultConfigKey = "operator.yaml"
	defaultSelector  = "app.kubernetes.io/name=gatehouse"

	ackInterval       = 10 * time.Second
	ackFreshness      = 30 * time.Second
	reconcileInterval = 2 * time.Second
	apiTimeout        = 5 * time.Second
	outageAlert       = 15 * time.Minute
)

type Options struct {
	Namespace   string
	Gateway     string
	ConfigMap   string
	ConfigKey   string
	PodName     string
	PodUID      string
	PodSelector string
	Logger      *slog.Logger

	// Install atomically replaces the serving snapshot. Acknowledgements only
	// advance after this callback succeeds.
	Install func(*snapshot.Snapshot) error

	// Serving reports whether the installed snapshot has live listening sockets.
	Serving func() bool
}

type Controller struct {
	options      Options
	client       dynamic.Interface
	meta         metadata.Interface
	leases       coordination.LeaseInterface
	coordination coordination.LeasesGetter
	logger       *slog.Logger

	ready        atomic.Bool
	configErrors atomic.Uint64
	apiContact   atomic.Int64
	startedAt    atomic.Int64
	current      atomic.Pointer[published]
	startup      atomic.Pointer[published]
}

type published struct {
	result

	configGeneration string
	configRejected   bool
}

func New(cfg *rest.Config, options Options) (*Controller, error) {
	if cfg == nil || options.PodName == "" || options.PodUID == "" || options.Install == nil {
		return nil, errors.New(
			"kubernetes config, pod name and UID, and a snapshot installer are required",
		)
	}
	options.Namespace = fallback(options.Namespace, defaultNamespace)
	options.ConfigMap = fallback(options.ConfigMap, defaultConfigMap)
	options.ConfigKey = fallback(options.ConfigKey, defaultConfigKey)
	options.Gateway = fallback(options.Gateway, defaultGateway)
	options.PodSelector = fallback(options.PodSelector, defaultSelector)
	if _, err := labels.Parse(options.PodSelector); err != nil {
		return nil, errors.New("invalid pod label selector")
	}
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	meta, err := metadata.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	coordinator, err := coordination.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	return &Controller{
		options: options,
		client:  client,
		meta:    meta,
		leases: coordinator.Leases(
			options.Namespace,
		),
		coordination: coordinator,
		logger:       options.Logger,
	}, nil
}

func fallback(value, other string) string {
	if value == "" {
		return other
	}
	return value
}

func (c *Controller) Ready() bool {
	return c.ready.Load() && (c.options.Serving == nil || c.options.Serving())
}

func (c *Controller) Snapshot() *snapshot.Snapshot {
	if current := c.current.Load(); current != nil {
		return current.snapshot
	}
	return nil
}

// OperatorStatus reports the ConfigMap revision installed by this replica and
// whether the latest observed revision was rejected.
func (c *Controller) OperatorStatus() (string, bool) {
	if report := c.currentReport(); report != nil {
		return report.configGeneration, report.configRejected
	}
	return "", false
}

func (c *Controller) ReadyHTTP(w http.ResponseWriter, _ *http.Request) {
	if !c.Ready() {
		http.Error(w, "Waiting for a valid bootstrap snapshot", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (c *Controller) ObservabilityState() observability.ControllerState {
	generation, rejected := c.OperatorStatus()
	return observability.ControllerState{
		OperatorConfigGeneration: generation,
		OperatorConfigRejected:   rejected,
		ConfigErrors:             c.configErrors.Load(),
		APILastSyncTimestamp:     c.apiContact.Load(),
	}
}

func (c *Controller) WriteMetrics(w io.Writer) {
	state := c.ObservabilityState()
	fmt.Fprintf(
		w,
		"# TYPE gatehouse_config_errors counter\ngatehouse_config_errors %d\n",
		state.ConfigErrors,
	)
	fmt.Fprintf(
		w,
		"# TYPE gatehouse_api_last_sync_timestamp gauge\ngatehouse_api_last_sync_timestamp %d\n",
		state.APILastSyncTimestamp,
	)
	fmt.Fprintf(
		w,
		"# TYPE gatehouse_kubernetes_api_stale gauge\ngatehouse_kubernetes_api_stale %d\n",
		observability.BoolMetric(c.apiStale()),
	)
}

// Run blocks until ctx is canceled or a controller initialization fails.
func (c *Controller) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer c.ready.Store(false)
	c.startedAt.Store(time.Now().Unix())

	state, err := c.startWatches(ctx)
	if err != nil {
		return err
	}
	go c.runStatus(ctx)
	reconcile := time.NewTicker(reconcileInterval)
	defer reconcile.Stop()
	health := time.NewTicker(ackInterval)
	defer health.Stop()
	apiAvailable := c.probe(ctx)
	alerted := false
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return nil
		case <-health.C:
			apiAvailable = c.probe(ctx)
			stale := !apiAvailable && c.apiStale()
			if stale && !alerted {
				c.logger.ErrorContext(ctx, "Kubernetes API unavailable for at least 15 minutes")
			}
			alerted = stale
		case <-state.changed:
		case <-reconcile.C:
		}
		if apiAvailable {
			if err := state.reconcile(ctx, c); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) currentReport() *published {
	if current := c.current.Load(); current != nil {
		return current
	}
	return c.startup.Load()
}

func (c *Controller) operatorID() key {
	return key{configMaps, c.options.Namespace, c.options.ConfigMap}
}

type watchState struct {
	watches            map[key]*informer
	base               []key
	changed            chan struct{}
	operator           *config.Config
	operatorGeneration string
	lastSeen           string
	rejected           bool
}

func (c *Controller) startWatches(ctx context.Context) (*watchState, error) {
	s := &watchState{watches: make(map[key]*informer), changed: make(chan struct{}, 1)}
	for _, res := range []resource{
		classes, gateways, listenerSets, httpRoutes, tlsRoutes, tlsPolicies, grants,
		routePolicies, backendPolicies, services, endpointSlices, namespaces,
	} {
		s.base = append(s.base, key{resource: res})
	}
	s.base = append(s.base, c.operatorID())
	for _, id := range s.base {
		if err := s.watch(ctx, c, id); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *watchState) watch(ctx context.Context, c *Controller, id key) error {
	if s.watches[id] != nil {
		return nil
	}
	watcher, err := startInformer(ctx, c.client, c.meta, id, func() {
		select {
		case s.changed <- struct{}{}:
		default:
		}
	})
	if err == nil {
		s.watches[id] = watcher
	}
	return err
}

func (c *Controller) apiStale() bool {
	last := c.apiContact.Load()
	if last == 0 {
		last = c.startedAt.Load()
	}
	return last != 0 && time.Since(time.Unix(last, 0)) >= outageAlert
}

func (c *Controller) probe(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	id := c.operatorID()
	_, err := c.client.Resource(id.gvr).
		Namespace(id.namespace).
		Get(ctx, id.name, metav1.GetOptions{})
	if err == nil || kerror.IsNotFound(err) {
		c.apiContact.Store(time.Now().Unix())
		return true
	}
	return false
}

func (s *watchState) reconcile(ctx context.Context, c *Controller) error {
	for _, id := range s.base {
		if !s.watches[id].HasSynced() {
			return nil
		}
	}
	objects := informerObjects(s.watches)
	s.loadOperator(c, objects)
	if c.current.Load() == nil {
		c.publishBootstrapStatus(objects, s.rejected)
	}
	if s.operator == nil {
		return nil
	}
	required, named := requiredWatches(c.operatorID(), s.operator)
	parent := key{gateways, c.options.Namespace, c.options.Gateway}
	deps := compiler{objects: objects}
	maps.Copy(named, deps.certificateWatches(parent, s.operator))
	now := time.Now()
	bootstrap := bootstrapReady(objects, required, now)
	if c.current.Load() == nil && (s.rejected || !bootstrap) {
		return s.updateNamed(ctx, c, named)
	}
	next, err := compile(objects, s.operator, c.operatorID(), c.options.Gateway, now)
	if err != nil {
		return err
	}
	maps.Copy(named, next.caWatches)
	if err := s.updateNamed(ctx, c, named); err != nil {
		return err
	}
	return s.publish(c, next, bootstrap)
}

func (s *watchState) publish(c *Controller, next result, bootstrap bool) error {
	old := c.current.Load()
	if old == nil || old.snapshot.Digest != next.snapshot.Digest {
		if err := c.options.Install(next.snapshot); err != nil {
			return errors.New("data plane rejected the compiled snapshot")
		}
	}
	c.current.Store(&published{next, s.operatorGeneration, s.rejected})
	c.ready.Store(bootstrap)
	return nil
}

func (s *watchState) loadOperator(c *Controller, objects Objects) {
	id := c.operatorID()
	obj := objects.get(id.resource, id.namespace, id.name)
	revision := "missing"
	if obj != nil {
		revision = obj.GetResourceVersion()
	}
	if s.lastSeen == revision {
		return
	}
	s.lastSeen = revision
	cm, ok := decode[corev1.ConfigMap](obj)
	if ok {
		if cfg, err := config.Parse([]byte(cm.Data[c.options.ConfigKey])); err == nil {
			s.operator = cfg
			s.operatorGeneration = revision
			s.rejected = false
			return
		}
	}
	s.rejected = true
	c.configErrors.Add(1)
	c.logger.Warn(
		"Rejected operator configuration",
		slog.String("configMap", id.name),
		slog.String("revision", revision),
	)
}

func (s *watchState) updateNamed(ctx context.Context, c *Controller, desired map[key]bool) error {
	for id := range desired {
		if err := s.watch(ctx, c, id); err != nil {
			return err
		}
	}
	for id, watch := range s.watches {
		if id.name != "" && id != c.operatorID() && !desired[id] {
			watch.cancel()
			delete(s.watches, id)
		}
	}
	return nil
}
