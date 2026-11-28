package oidclogin

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/zekihan/gatehouse/internal/config"
)

// A deeply nested unprotected header field is parsed by go-jose before the
// signature check. Past the goroutine stack limit this crashes Verify instead
// of returning errToken. The 8MiB limit makes the crash small; the runtime
// default is 1GB and the parser has no depth cap.
func TestIssuerNestedHeaderIsRejected(t *testing.T) {
	debug.SetMaxStack(8 << 20)
	const depth = 100000
	var nested strings.Builder
	nested.Grow(depth*2 + 1)
	for range depth {
		nested.WriteByte('[')
	}
	nested.WriteByte('0')
	for range depth {
		nested.WriteByte(']')
	}
	token := compactToken(`{"alg":"RS256","x":`+nested.String()+`}`, []byte(`{"sub":"x"}`))

	var issuerURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuerURL,
				"authorization_endpoint":                issuerURL + "/auth",
				"token_endpoint":                        issuerURL + "/token",
				"jwks_uri":                              issuerURL + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "disposable", "token_type": "Bearer", "id_token": token,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	issuerURL = server.URL
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	class := NewClass("nested", config.AuthClass{
		Issuer: issuerURL, ClientID: "synthetic-client", Scopes: []string{"openid"},
		Callback: issuerURL + "/callback", RedirectHosts: []string{"127.0.0.1"},
		SoftExpiry: "1m", HardExpiry: "2m",
	}, map[string]string{
		"oidc-nested-client-secret": "synthetic-client-secret",
		"cookie-nested-current":     base64.StdEncoding.EncodeToString(keyBytes),
	}, server.Client().Transport, nil)
	if class == nil {
		t.Fatal("class")
	}
	session, err := class.exchange(t.Context(), "auth-code-1", flow{
		Nonce: "nonce-1", Verifier: "verifier-1",
	})
	if err == nil {
		t.Fatalf("accepted nested token as %q", session.User)
	}
}

func compactToken(header string, payload []byte) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc(payload) + "." + enc([]byte{1})
}
