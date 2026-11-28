//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
)

const (
	objectBytes = 15360
	pageBytes   = 8192
	megabyte    = 1 << 20
)

func appFixture() *httptest.Server {
	router := http.NewServeMux()
	page := bytes.Repeat([]byte("<p>bench!</p>   "), pageBytes/16)
	router.HandleFunc("GET /page", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(page)
	})
	router.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	router.HandleFunc("GET /echo", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"method": r.Method, "path": r.URL.RequestURI(), "host": r.Host,
			"proto": r.Proto, "headers": r.Header,
		})
	})
	router.HandleFunc("GET /probe", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(
			w,
			map[string]string{"probe": "ok", "authorization": r.Header.Get("Authorization")},
		)
	})
	router.HandleFunc("GET /s3/{object}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(objectBytes))
		w.Header().Set("ETag", `"bench"`)
		if r.Method != http.MethodHead {
			_, _ = w.Write(make([]byte, objectBytes))
		}
	})
	router.HandleFunc("GET /big", serveDownload)
	router.HandleFunc("POST /api/v1/write", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "incomplete upload", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	router.HandleFunc("POST /insert/journald/upload", func(w http.ResponseWriter, r *http.Request) {
		read, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, "incomplete upload", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]int64{"bytes": read})
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "bench-backend")
		w.Header().Set("X-Powered-By", "bench")
		router.ServeHTTP(w, r)
	}))
}

func serveDownload(w http.ResponseWriter, r *http.Request) {
	size, err := strconv.Atoi(r.URL.Query().Get("mb"))
	if err != nil || size <= 0 || size > 256 {
		http.Error(w, "invalid download size", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(size*megabyte))
	block := make([]byte, megabyte)
	for range size {
		if _, err := w.Write(block); err != nil {
			return
		}
	}
}

func authFixture() *httptest.Server {
	router := http.NewServeMux()
	var mu sync.Mutex
	var last http.Header
	router.HandleFunc("GET /api/authz/gatus", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = r.Header.Clone()
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer good-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	router.HandleFunc("GET /last", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		headers := last
		mu.Unlock()
		writeJSON(w, headers)
	})
	return httptest.NewServer(router)
}

type decision struct {
	ID       int    `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

func lapiFixture() *httptest.Server {
	decisions := make([]decision, 40000)
	decisions[0] = decision{1, "cscli", "ban", "Ip", "127.0.0.2", "167h", "bench/banned-loopback"}
	for i := 1; i < len(decisions); i++ {
		ip := fmt.Sprintf("198.18.%d.%d", i/256, i%256)
		decisions[i] = decision{i + 1, "CAPI", "ban", "Ip", ip, "167h", "bench/filler"}
	}
	router := http.NewServeMux()
	router.HandleFunc("GET /v1/decisions/stream", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "bench-lapi-key" {
			http.Error(w, "access forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("startup") == "true" {
			writeJSON(w, map[string][]decision{"new": decisions, "deleted": {}})
			return
		}
		writeJSON(w, map[string][]decision{"new": nil, "deleted": nil})
	})
	router.HandleFunc("POST /v1/usage-metrics", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	})
	return httptest.NewServer(router)
}

func writeJSON(w http.ResponseWriter, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "encode fixture response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
