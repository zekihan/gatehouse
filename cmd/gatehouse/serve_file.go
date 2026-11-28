package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/dataplane"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

func serveFile(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	operator := flags.String("config", "", "operator configuration file")
	input := flags.String("snapshot", "", "resolved JSON snapshot file")
	bind := flags.String("bind", "127.0.0.1", "address to bind to")
	metrics := flags.String("metrics", "", "metrics listen address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *operator == "" || *input == "" {
		return errors.New("serve requires --config and --snapshot")
	}
	raw, err := os.ReadFile(*operator)
	if err != nil {
		return err
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return err
	}
	snap, err := snapshot.LoadFile(cfg, *input)
	if err != nil {
		return err
	}
	proxy := dataplane.New(dataplane.Options{AccessLog: stdout})
	if err := proxy.Update(snap); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *metrics == "" {
		return proxy.Serve(ctx, *bind)
	}
	return serveWithMetrics(ctx, proxy, *bind, *metrics)
}

func serveWithMetrics(ctx context.Context, proxy *dataplane.Plane, bind, address string) error {
	var cfg net.ListenConfig
	listener, err := cfg.Listen(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", proxy.Metrics())
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- server.Serve(listener) }()
	go func() { errs <- proxy.Serve(ctx, bind) }()
	err = <-errs
	cancel()
	_ = server.Close()
	if other := <-errs; err == nil && !errors.Is(other, http.ErrServerClosed) {
		err = other
	}
	return err
}
