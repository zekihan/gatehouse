package dataplane

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

func TestReservedStickyCookieIsNotInstalled(t *testing.T) {
	t.Parallel()
	ordinary := fixtureBackend(t, "app-sticky")
	if ordinary == nil || ordinary.cookie != "app-sticky" {
		t.Fatal("ordinary sticky cookie backend was rejected")
	}
	if reserved := fixtureBackend(t, "__Secure-gatehouse-session-user"); reserved != nil {
		t.Fatal("reserved sticky cookie was installed on a backend")
	}
}

func fixtureBackend(t *testing.T, cookie string) *backend {
	t.Helper()
	return newBackend(&config.Config{}, &snapshot.Backend{
		Service: "ns/app", Port: 80, Endpoints: []string{"127.0.0.1:9"}, StickyCookie: cookie,
	}, snapshot.Deadlines{}, false)
}

func TestExceptionRewriteCannotLeaveGrantedPath(t *testing.T) {
	t.Parallel()
	var path atomic.Value
	path.Store("")
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.RequestURI + " host=" + r.Host)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(back.Close)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer fixture" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(auth.Close)
	l, port := newListener(t)
	pair, roots := makeCertificate(t)
	upstream := &snapshot.Backend{
		Port: 80, Endpoints: []string{strings.TrimPrefix(back.URL, "http://")},
	}
	input := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{
		Certificate: pair,
		Routes: []snapshot.Route{
			{
				Name: "health", Namespace: "ns", Path: "/health", Exact: true,
				Method: http.MethodGet, ForwardAuth: "gatus-bearer", Backend: upstream,
				Rewrite: &snapshot.Rewrite{Path: "/secret", Host: "other.internal"},
			},
			{
				Name: "prefix", Namespace: "ns", Path: "/health", Method: http.MethodGet,
				ForwardAuth: "gatus-bearer", Backend: upstream,
			},
			{Name: "catch-all", Namespace: "ns", Path: "/", Backend: upstream},
		},
	})
	input.Config.ForwardAuthClasses = map[string]config.ForwardAuthClass{
		"gatus-bearer": {
			Address: auth.URL + "/auth", RequestHeaders: []string{"Authorization"},
			StripAfter: []string{"Authorization"}, MaxResponseBytes: 64,
		},
	}
	registry := input.Config.Hosts[fixtureHost]
	registry.Protection = "oidc:user"
	registry.Exceptions = []config.Exception{{
		Path: "/health", Methods: []string{http.MethodGet}, ForwardAuth: "gatus-bearer",
	}}
	input.Config.Hosts[fixtureHost] = registry
	plane := New(Options{})
	if err := plane.Update(input); err != nil {
		t.Fatal(err)
	}
	startListener(t, l, plane, port, "")
	client := testClient(t, l, roots)
	var failed []string
	for _, tc := range []struct {
		name, method, urlPath, credential string
		code                              int
		upstream                          string
	}{
		{
			name: "exact grant", method: http.MethodGet, urlPath: "/health",
			credential: "Bearer fixture", code: http.StatusNoContent,
			upstream: "/health host=" + fixtureHost,
		},
		{
			name: "prefix", method: http.MethodGet, urlPath: "/health/admin",
			credential: "Bearer fixture", code: http.StatusServiceUnavailable,
		},
		{
			name: "encoded", method: http.MethodGet, urlPath: "/%68ealth",
			credential: "Bearer fixture", code: http.StatusServiceUnavailable,
		},
		{
			name: "dot segment", method: http.MethodGet, urlPath: "/x/../health",
			credential: "Bearer fixture", code: http.StatusServiceUnavailable,
		},
		{
			name: "wrong method", method: http.MethodPost, urlPath: "/health",
			credential: "Bearer fixture", code: http.StatusServiceUnavailable,
		},
		{
			name: "missing bearer", method: http.MethodGet, urlPath: "/health",
			code: http.StatusUnauthorized,
		},
	} {
		path.Store("")
		status := routingStatus(t, client, tc.method, tc.urlPath, tc.credential)
		got, _ := path.Load().(string)
		if status != tc.code || (tc.upstream != "" && got != tc.upstream) {
			failed = append(failed, fmt.Sprintf(
				"%s: status %d upstream %q, want %d %q", tc.name, status, got, tc.code, tc.upstream,
			))
		}
	}
	if len(failed) != 0 {
		t.Fatal(strings.Join(failed, "\n"))
	}
}

func TestRewriteCannotReachRegistryDeny(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	var path atomic.Value
	path.Store("")
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		path.Store(r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(back.Close)
	l, port := newListener(t)
	pair, roots := makeCertificate(t)
	upstream := &snapshot.Backend{
		Port: 80, Endpoints: []string{strings.TrimPrefix(back.URL, "http://")},
	}
	input := testSnapshot(port, config.Port{Identity: "direct"}, snapshot.Host{
		Certificate: pair,
		Routes: []snapshot.Route{
			{
				Name: "broad", Namespace: "ns", Path: "/", Backend: upstream,
				Rewrite: &snapshot.Rewrite{Path: "/minio/admin"},
			},
			{
				Name: "prefix", Namespace: "ns", Path: "/pub", Backend: upstream,
				Rewrite: &snapshot.Rewrite{Path: "/minio/admin", Prefix: true},
			},
			{
				Name: "safe", Namespace: "ns", Path: "/safe", Exact: true, Backend: upstream,
				Rewrite: &snapshot.Rewrite{Path: "/public"},
			},
		},
	})
	registry := input.Config.Hosts[fixtureHost]
	registry.Deny = &config.Deny{
		Prefixes: []string{"/minio/admin", "/rustfs/admin", "/rustfs/console"},
	}
	input.Config.Hosts[fixtureHost] = registry
	plane := New(Options{})
	if err := plane.Update(input); err != nil {
		t.Fatal(err)
	}
	startListener(t, l, plane, port, "")
	client := testClient(t, l, roots)
	var failed []string
	for _, tc := range []struct {
		name, urlPath string
		code          int
		upstream      string
	}{
		{name: "direct prefix", urlPath: "/minio/admin/console", code: http.StatusForbidden},
		{name: "encoded slash", urlPath: "/minio/admin%2Fconsole", code: http.StatusBadRequest},
		{name: "dot escape", urlPath: "/x/../minio/admin", code: http.StatusForbidden},
		{name: "encoded dot", urlPath: "/x/%2e%2e/minio/admin", code: http.StatusForbidden},
		{name: "full rewrite", urlPath: "/anywhere", code: http.StatusForbidden},
		{name: "prefix rewrite", urlPath: "/pub/object", code: http.StatusForbidden},
		{name: "safe rewrite", urlPath: "/safe", code: http.StatusNoContent, upstream: "/public"},
		{name: "metrics redirect", urlPath: "/metrics", code: http.StatusNoContent, upstream: "/"},
		{name: "metrics slash", urlPath: "/metrics/", code: http.StatusNoContent, upstream: "/"},
	} {
		before := hits.Load()
		path.Store("")
		status := routingStatus(t, client, http.MethodGet, tc.urlPath, "")
		got, _ := path.Load().(string)
		if status != tc.code || (tc.upstream != "" && got != tc.upstream) {
			failed = append(failed, fmt.Sprintf(
				"%s: status %d upstream %q, want %d %q", tc.name, status, got, tc.code, tc.upstream,
			))
		}
		if tc.code != http.StatusNoContent && hits.Load() != before {
			failed = append(failed, tc.name+": denied path reached the backend")
		}
	}
	if len(failed) != 0 {
		t.Fatal(strings.Join(failed, "\n"))
	}
}

func routingStatus(t *testing.T, client *http.Client, method, path, credential string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, "https://"+fixtureHost+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if credential != "" {
		req.Header.Set("Authorization", credential)
	}
	status, _, _ := doRequest(t, client, req)
	return status
}
