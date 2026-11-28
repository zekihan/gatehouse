package dataplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

func TestMandatoryDeniesSurviveRouteRemoval(t *testing.T) {
	var requests atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(backend.Close)
	l, port := newListener(t)
	cert, roots := makeCertificate(t)
	routes := []snapshot.Route{{
		Name: "catch-all", Path: "/", Backend: &snapshot.Backend{
			Service:   "ns/storage",
			Port:      80,
			Endpoints: []string{strings.TrimPrefix(backend.URL, "http://")},
		},
	}}
	host := snapshot.Host{Certificate: cert, Routes: routes}
	snap := testSnapshot(port, config.Port{Identity: "direct"}, host)
	registry := snap.Config.Hosts[fixtureHost]
	prefixes := []string{
		"/minio/admin", "/rustfs/admin", "/rustfs/console",
		"/metrics/minio/admin", "/metrics/rustfs/admin", "/metrics/rustfs/console",
	}
	registry.Deny = &config.Deny{Prefixes: prefixes}
	snap.Config.Hosts[fixtureHost] = registry
	plane := New(Options{})
	startListener(t, l, plane, port, "")
	client := testClient(t, l, roots)
	for _, state := range []struct {
		name   string
		routes []snapshot.Route
		allow  int
	}{
		{"cold start", nil, http.StatusNotFound},
		{"broad route", routes, http.StatusNoContent},
		{"route removed", nil, http.StatusNotFound},
	} {
		t.Run(state.name, func(t *testing.T) {
			host.Routes = state.routes
			snap.DataPlane.Ports[port][fixtureHost] = host
			if err := plane.Update(snap); err != nil {
				t.Fatal(err)
			}
			checkRegistryPath(t, client, "/s3/bucket", state.allow)
			before := requests.Load()
			for _, prefix := range prefixes {
				checkRegistryPath(t, client, prefix, http.StatusForbidden)
				checkRegistryPath(t, client, prefix+"/fixture", http.StatusForbidden)
			}
			if requests.Load() != before {
				t.Fatal("registry deny forwarded an upstream request")
			}
		})
	}
}

func checkRegistryPath(t *testing.T, client *http.Client, path string, want int) {
	t.Helper()
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://"+fixtureHost+path,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := doRequest(t, client, req); got != want {
		t.Errorf("GET %s returned %d, want %d", path, got, want)
	}
}
