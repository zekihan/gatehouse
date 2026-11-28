package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/controller"
	"github.com/zekihan/gatehouse/internal/dataplane"
	"github.com/zekihan/gatehouse/internal/observability"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

func TestManagementObservability(t *testing.T) {
	base := startManagementFixture(t)
	client := &http.Client{Timeout: time.Second}
	checkManagementState(t, client, base+"/state")
	checkManagementMetrics(t, client, base+"/metrics")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/state", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /state status = %d", resp.StatusCode)
	}
}

func startManagementFixture(t *testing.T) string {
	t.Helper()
	rec, err := controller.New(&rest.Config{Host: "https://127.0.0.1"}, controller.Options{
		PodName: "fixture",
		PodUID:  "fixture-uid",
		Install: func(*snapshot.Snapshot) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := dataplane.New(dataplane.Options{})
	err = proxy.Update(&snapshot.Snapshot{
		Digest: "fixture",
		Config: &config.Config{Ports: map[uint16]config.Port{
			8443: {Identity: "direct"},
			8000: {Identity: "direct", Mode: "redirect"},
		}},
		DataPlane: &snapshot.DataPlane{EdgeSecrets: map[string]map[string]string{
			"fixture-secret": {"key": "disposable-secret"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, listener, err := managementServer(t.Context(), "127.0.0.1:0", rec, proxy, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})
	return "http://" + listener.Addr().String()
}

func checkManagementState(t *testing.T, client *http.Client, url string) {
	t.Helper()
	body, stateType, cache := fetchManagement(t, client, url)
	if stateType != "application/json" || cache != "no-store" {
		t.Fatalf("unexpected state headers: %q, %q", stateType, cache)
	}
	var state observability.State
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	if state.Ready || state.SnapshotDigest != "fixture" || state.Controller == nil ||
		state.Controller.APILastSyncTimestamp != 0 ||
		!slices.Equal(
			state.Listeners,
			[]observability.ListenerState{{Port: 8000, Mode: "redirect"}, {Port: 8443}},
		) {
		t.Fatalf("unexpected initial state: %+v", state)
	}
	if strings.Contains(string(body), "disposable-secret") ||
		strings.Contains(string(body), "fixture-secret") {
		t.Fatal("state leaked snapshot inputs")
	}
}

func checkManagementMetrics(t *testing.T, client *http.Client, url string) {
	t.Helper()
	body, metricsType, _ := fetchManagement(t, client, url)
	if metricsType != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("wrong metrics content type: %q", metricsType)
	}
	for _, sample := range []string{
		`gatehouse_snapshot_digest_info{digest="fixture"} 1`,
		"gatehouse_config_errors 0",
		"gatehouse_api_last_sync_timestamp 0",
	} {
		if !strings.Contains(string(body), sample+"\n") {
			t.Errorf("metrics missing %q", sample)
		}
	}
}

func fetchManagement(t *testing.T, client *http.Client, url string) ([]byte, string, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %v", resp.StatusCode, err)
	}
	return body, resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control")
}
