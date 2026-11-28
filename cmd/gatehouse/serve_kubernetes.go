package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/zekihan/gatehouse/internal/controller"
	"github.com/zekihan/gatehouse/internal/dataplane"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

func serveKubernetes(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve-kubernetes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bind := flags.String("bind", "", "edge listen IP")
	management := flags.String("management", ":8080", "readiness and metrics listen address")
	kubeconfig := flags.String(
		"kubeconfig",
		"",
		"Kubernetes config file (defaults to in-cluster credentials)",
	)
	options := controller.Options{
		PodName: os.Getenv(
			"POD_NAME",
		),
		PodUID:    os.Getenv("POD_UID"),
		Namespace: os.Getenv("POD_NAMESPACE"),
	}
	flags.StringVar(
		&options.PodSelector,
		"pod-selector",
		"",
		"label selector identifying this Gateway's replicas",
	)
	flags.StringVar(&options.ConfigMap, "config-map", "", "operator ConfigMap name")
	flags.StringVar(&options.Gateway, "gateway", "", "Gateway name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve-kubernetes accepts flags only")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runKubernetes(ctx, stdout, options, *kubeconfig, *bind, *management)
}

func runKubernetes(
	ctx context.Context,
	stdout io.Writer,
	options controller.Options,
	kubeconfig, bind, management string,
) error {
	cfg, err := kubernetesConfig(kubeconfig)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, 3)
	runtime := &edgeRuntime{listening: make(chan struct{}, 1)}
	runtime.plane = dataplane.New(dataplane.Options{
		AccessLog: stdout,
		OnListening: func() {
			runtime.serving.Store(true)
			runtime.listening <- struct{}{}
		},
	})
	options.Serving = runtime.serving.Load
	options.Install = func(snap *snapshot.Snapshot) error { return runtime.install(ctx, snap, bind, failures) }
	rec, err := controller.New(cfg, options)
	if err != nil {
		return err
	}
	server, listener, err := managementServer(ctx, management, rec, runtime.plane)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	go func() { failures <- server.Serve(listener) }()
	go func() { failures <- rec.Run(ctx) }()
	select {
	case <-ctx.Done():
		err = nil
	case err = <-failures:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	cancel()
	return errors.Join(err, server.Close())
}

func kubernetesConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func managementServer(
	ctx context.Context,
	address string,
	rec *controller.Controller,
	proxy *dataplane.Plane,
) (*http.Server, net.Listener, error) {
	var cfg net.ListenConfig
	listener, err := cfg.Listen(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", rec.ReadyHTTP)
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		proxy.Metrics().ServeHTTP(w, r)
		rec.Metrics(w, r)
	})
	return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}, listener, nil
}

// edgeRuntime serializes socket changes. Same-topology installs swap only the
// snapshot, so normal API changes leave the listening sockets open.
type edgeRuntime struct {
	plane      *dataplane.Plane
	listening  chan struct{}
	serving    atomic.Bool
	topology   map[uint16]string
	closeServe context.CancelFunc
	stopped    chan error
}

//nolint:contextcheck // The data plane compiles snapshots without a request context.
func (e *edgeRuntime) install(
	ctx context.Context,
	snap *snapshot.Snapshot,
	bind string,
	failures chan<- error,
) error {
	topology := make(map[uint16]string, len(snap.Config.Ports))
	for port, cfg := range snap.Config.Ports {
		topology[port] = cfg.Mode
	}
	if maps.Equal(e.topology, topology) {
		return e.plane.Update(
			snap,
		)
	}
	if e.closeServe != nil {
		e.serving.Store(false)
		e.closeServe()
		if err := <-e.stopped; err != nil {
			return err
		}
	}
	if err := e.plane.Update(
		snap,
	); err != nil {
		return err
	}
	serving, stop := context.WithCancel(ctx)
	stopped := make(chan error, 1)
	e.closeServe, e.stopped = stop, stopped
	go func() {
		err := e.plane.Serve(serving, bind)
		e.serving.Store(false)
		stopped <- err
		if err != nil && serving.Err() == nil {
			failures <- err
		}
	}()
	select {
	case <-e.listening:
		e.topology = topology
		return nil
	case err := <-stopped:
		stop()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
