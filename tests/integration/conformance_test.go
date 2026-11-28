//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/observability"
)

func TestGatehouseConformance(t *testing.T) {
	binary := os.Getenv("GATEHOUSE_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal(
			"set GATEHOUSE_BINARY to the absolute path to gatehouse (make test/integration does this)",
		)
	}
	t.Run("operator config process", func(t *testing.T) {
		output, err := exec.CommandContext(t.Context(), binary, "validate", "../../examples/operator.yaml").
			CombinedOutput()
		if err != nil {
			t.Fatalf("validate exited with %v: %s", err, output)
		}
		file := filepath.Join(t.TempDir(), "invalid.yaml")
		if err := os.WriteFile(
			file,
			[]byte("ports: {0: {identity: direct}}\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		output, err = exec.CommandContext(t.Context(), binary, "validate", file).CombinedOutput()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 ||
			!strings.Contains(string(output), "/ports") {
			t.Fatalf("wanted status 1 and a ports diagnostic, got %v: %s", err, output)
		}
	})
	t.Run("bench suite", func(t *testing.T) {
		runBench(t, binary)
	})
}

func runBench(t *testing.T, binary string) {
	t.Helper()
	dir := t.TempDir()
	fixtures, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	app, auth, lapi := appFixture(), authFixture(), lapiFixture()
	t.Cleanup(app.Close)
	t.Cleanup(auth.Close)
	t.Cleanup(lapi.Close)
	logFile := filepath.Join(dir, "access.log")
	ready := filepath.Join(dir, "ready")
	metricsPort := loopbackPort(t)
	env := append(os.Environ(),
		"GATEHOUSE_BINARY="+binary,
		"BENCH_DIR="+dir,
		"BENCH_READY="+ready,
		"BENCH_LOG="+logFile,
		"BENCH_TLS_PORT="+loopbackPort(t),
		"BENCH_METRICS_PORT="+metricsPort,
		"BENCH_APP_URL="+app.URL,
		"BENCH_AUTH_URL="+auth.URL,
		"BENCH_LAPI_URL="+lapi.URL,
	)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	gen := exec.CommandContext(ctx, "python3", filepath.Join(fixtures, "fixtures.py"))
	gen.Dir = dir
	gen.Env = env
	if output, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generate bench fixtures: %v\n%s", err, output)
	}
	checkBenchFixture(t, dir)

	driver := os.Getenv("GATEHOUSE_BENCH_DRIVER")
	features := "proxy,identity,streaming,routing,tls,mtls,crowdsec,limits,forward-auth,uploads,alpn,observability"
	if driver == "" {
		driver = filepath.Join(fixtures, "driver.py")
	} else {
		features = enabledFeatures(t)
	}
	startDriver(ctx, t, driver, dir, logFile, ready, env)
	if driver == filepath.Join(fixtures, "driver.py") {
		management := "http://127.0.0.1:" + metricsPort
		checkFileState(t, management)
		checkPolicyMetrics(t, management)
	}
	check := exec.CommandContext(ctx, "bash", filepath.Join(fixtures, "conformance.sh"))
	check.Env = append(env, "BENCH_FEATURES="+features)
	output, err := check.CombinedOutput()
	if err != nil {
		t.Fatalf("wire checks: %v\n%s", err, output)
	}
	t.Logf("\n%s", output)
}

func checkFileState(t *testing.T, management string) {
	t.Helper()
	resp := managementResponse(t, management+"/state")
	defer resp.Body.Close()
	var state observability.State
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if !state.Ready || state.SnapshotDigest == "" || len(state.Listeners) == 0 ||
		state.Controller != nil {
		t.Fatalf("unexpected standalone state: %+v", state)
	}
}

func checkPolicyMetrics(t *testing.T, management string) {
	t.Helper()
	resp := managementResponse(t, management+"/metrics")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{
		"gatehouse_crowdsec_decisions 40000\n",
		"gatehouse_limiter_isolated 1\n",
		"gatehouse_limiter_resync_pending 0\n",
		`gatehouse_limiter_pressure{route="bench/web`,
	} {
		if !strings.Contains(string(body), sample) {
			t.Errorf("running process metrics missing %q", sample)
		}
	}
}

func managementResponse(t *testing.T, endpoint string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("GET %s returned %d", endpoint, resp.StatusCode)
	}
	return resp
}

func enabledFeatures(t *testing.T) string {
	t.Helper()
	all := []string{
		"proxy", "identity", "streaming", "routing", "tls", "mtls", "crowdsec", "limits",
		"forward-auth", "uploads", "alpn", "observability",
	}
	value := os.Getenv("GATEHOUSE_BENCH_FEATURES")
	if value == "" {
		return strings.Join(all, ",")
	}
	for name := range strings.SplitSeq(value, ",") {
		if !slices.Contains(all, name) {
			t.Fatalf("unknown benchmark feature %q", name)
		}
	}
	return value
}

func checkBenchFixture(t *testing.T, dir string) {
	t.Helper()
	var config struct {
		Routes []json.RawMessage `json:"routes"`
		TLS    struct {
			Hosts []struct {
				Cert string `json:"cert"`
				Key  string `json:"key"`
			} `json:"hosts"`
		} `json:"tls"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "bench.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.TLS.Hosts) != 63 || len(config.Routes) != 90 {
		t.Fatalf(
			"fixture has %d hosts and %d routes, want 63 and 90",
			len(config.TLS.Hosts),
			len(config.Routes),
		)
	}
	for _, host := range config.TLS.Hosts {
		if !filepath.IsLocal(host.Cert) || !filepath.IsLocal(host.Key) {
			t.Fatal("bench certificate path is outside the fixture")
		}
		cert, err := tls.LoadX509KeyPair(
			filepath.Join(dir, host.Cert),
			filepath.Join(dir, host.Key),
		)
		if err != nil || len(cert.Certificate) != 2 {
			t.Fatalf("load bench TLS certificate chain: %v", err)
		}
	}
}

func loopbackPort(t *testing.T) string {
	t.Helper()
	var cfg net.ListenConfig
	listener, err := cfg.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if closeErr := listener.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func startDriver(
	ctx context.Context,
	t *testing.T,
	driver, dir, access, ready string,
	env []string,
) {
	t.Helper()
	if !filepath.IsAbs(driver) {
		t.Fatal("GATEHOUSE_BENCH_DRIVER must be an absolute path")
	}
	out, err := os.Create(access)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	diagnostics, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = diagnostics.Close() })
	cmd := exec.CommandContext(ctx, driver)
	// The driver forwards the interrupt to its Gatehouse child and reaps it.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Env, cmd.Dir = env, dir
	cmd.Stdout, cmd.Stderr = out, diagnostics
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bench driver: %v", err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() { <-done })
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for bench driver readiness")
		case <-done:
			details, err := os.ReadFile(diagnostics.Name())
			if err != nil {
				t.Fatalf(
					"bench driver exited before readiness: %v (read diagnostics: %v)",
					waitErr,
					err,
				)
			}
			t.Fatalf("bench driver exited before readiness: %v\n%s", waitErr, details)
		case <-ticker.C:
			if _, err := os.Stat(ready); err == nil {
				return
			}
		}
	}
}
