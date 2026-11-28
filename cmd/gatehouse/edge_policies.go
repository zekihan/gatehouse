package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/zekihan/gatehouse/internal/crowdsec"
	"github.com/zekihan/gatehouse/internal/dataplane"
	"github.com/zekihan/gatehouse/internal/limiter"
	"github.com/zekihan/gatehouse/internal/observability"
)

type policyFlags struct {
	lapi, lapiKey                   string
	discover, gossipBind, advertise string
	gossipName, incarnation, keyDir string
	readyRoute, readyCA             string
}

func (p *policyFlags) register(flags *flag.FlagSet) {
	flags.StringVar(&p.lapi, "crowdsec-lapi", "", "CrowdSec LAPI base URL")
	flags.StringVar(&p.lapiKey, "crowdsec-key-file", "", "mounted CrowdSec bouncer key")
	flags.StringVar(&p.discover, "gossip-discover", "", "headless gossip Service DNS name and port")
	flags.StringVar(
		&p.gossipBind,
		"gossip-bind",
		"",
		"gossip listen IP and port (default 0.0.0.0:7946)",
	)
	flags.StringVar(&p.advertise, "gossip-advertise", "", "gossip advertised IP and port")
	flags.StringVar(&p.gossipName, "gossip-name", os.Getenv("POD_NAME"), "stable gossip identity")
	flags.StringVar(
		&p.incarnation,
		"gossip-incarnation-file",
		"",
		"gossip incarnation path on a pod-local volume",
	)
	flags.StringVar(
		&p.keyDir,
		"gossip-key-dir",
		"",
		"directory containing gossip-current and optional gossip-previous",
	)
	flags.StringVar(&p.readyRoute, "ready-route", "", "local HTTPS route exercised by readiness")
	flags.StringVar(
		&p.readyCA,
		"ready-route-ca-file",
		"",
		"optional PEM CA for the readiness route",
	)
}

func (p *policyFlags) start(ctx context.Context, stderr io.Writer) (edgePolicies, func(), error) {
	policies := edgePolicies{limits: limiter.NewLocal()}
	if (p.lapi == "") != (p.lapiKey == "") {
		return policies, nil, errors.New("CrowdSec requires both a LAPI URL and a key file")
	}
	if p.lapi != "" {
		bouncer, err := crowdsec.New(p.lapi, func() (string, error) {
			data, err := os.ReadFile(p.lapiKey)
			return string(bytes.TrimSpace(data)), err
		})
		if err != nil {
			return policies, nil, err
		}
		policies.bouncer = bouncer
	}
	var cluster *limiter.Cluster
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	if p.discover != "" {
		keys, err := readGossipKeys(p.keyDir)
		if err != nil {
			return policies, nil, err
		}
		cluster, err = limiter.NewCluster(limiter.Gossip{
			Name: p.gossipName, StateFile: p.incarnation, Bind: p.gossipBind,
			Advertise: p.advertise, Discover: p.discover, Keyring: keys,
			Logger: log.New(memberlistLog{stderr}, "", log.LstdFlags),
		})
		if err != nil {
			return policies, nil, err
		}
		policies.limits = cluster.Limiter
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	if policies.bouncer != nil {
		workers.Go(func() {
			policies.bouncer.Run(ctx, func(err error) {
				logger.WarnContext(ctx, "CrowdSec refresh failed", slog.Any("error", err))
			})
		})
	}
	if cluster != nil {
		workers.Go(func() { cluster.Run(ctx) })
	}
	return policies, func() {
		cancel()
		workers.Wait()
	}, nil
}

func readGossipKeys(dir string) ([][]byte, error) {
	if dir == "" {
		return nil, errors.New("gossip discovery requires a key directory")
	}
	var keys [][]byte
	for _, name := range []string{"gossip-current", "gossip-previous"} {
		encoded, err := os.ReadFile(dir + "/" + name)
		if errors.Is(err, os.ErrNotExist) && len(keys) != 0 {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		key, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encoded)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("%s must contain a base64-encoded 32-byte key", name)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

type edgePolicies struct {
	bouncer *crowdsec.Bouncer
	limits  *limiter.Limiter
}

func (p edgePolicies) options(options dataplane.Options) dataplane.Options {
	options.CrowdSec = p.checkCrowdSec
	options.Limits = p.admit
	options.PolicyReady = func(required bool) bool {
		return p.limits.Ready() && (!required || (p.bouncer != nil && p.bouncer.Ready()))
	}
	if p.bouncer != nil {
		options.CrowdSecMetrics = p.bouncer.Metrics
	}
	options.LimiterMetrics = p.limits.Metrics
	return options
}

func (p edgePolicies) checkCrowdSec(
	w http.ResponseWriter,
	_ *http.Request,
	info dataplane.RequestInfo,
) bool {
	if !info.CrowdSecEnabled || p.bouncer == nil || !p.bouncer.Banned(info.ClientIP) {
		return true
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
	return false
}

func (p edgePolicies) admit(
	w http.ResponseWriter,
	_ *http.Request,
	info dataplane.RequestInfo,
) (func(), bool) {
	key := observability.RouteID(info.Route.Namespace, info.Route.Name)
	release, allowed := p.limits.Admit(key, info.ClientIP, info.Host, info.Limits)
	if !allowed {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
	}
	return release, allowed
}

type routeProbe struct {
	url    *url.URL
	client *http.Client
}

func (p *policyFlags) probe(bind string) (*routeProbe, error) {
	if p.readyRoute == "" {
		//nolint:nilnil // Standalone readiness can omit a routed check.
		return nil, nil
	}
	route, err := url.ParseRequestURI(p.readyRoute)
	if err != nil || route.Scheme != "https" || route.Hostname() == "" || route.User != nil {
		return nil, errors.New("ready route must be an HTTPS URL")
	}
	switch bind {
	case "", "0.0.0.0":
		bind = "127.0.0.1"
	case "::":
		bind = "::1"
	}
	port := route.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(bind, port)
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	}
	if p.readyCA != "" {
		data, err := os.ReadFile(p.readyCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("ready route CA file contains no certificates")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return &routeProbe{url: route, client: &http.Client{
		Transport:     transport,
		Timeout:       time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (p *routeProbe) check(ctx context.Context) bool {
	if p == nil {
		return true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url.String(), nil)
	if err != nil {
		return false
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices
}

// Memberlist logs each successful TCP message at debug level.
type memberlistLog struct{ io.Writer }

func (w memberlistLog) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte("[DEBUG] memberlist:")) {
		return len(data), nil
	}
	return w.Writer.Write(data)
}
