package oidclogin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
)

func TestUsedCodeAndStateReplay(t *testing.T) {
	t.Parallel()
	issuer := newFakeIssuer(t)
	class := issuer.userClass(t)
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	flow, query := startLogin(t, issuer, class, now)
	first := callbackOn(t, class, "local-code", query.Get("state"), flow, now)
	if first.Code != http.StatusFound {
		t.Fatalf("first callback status %d body %s", first.Code, first.Body.String())
	}
	replay := callbackOn(t, class, "local-code", query.Get("state"), flow, now)
	if replay.Code == http.StatusFound {
		t.Fatalf(
			"replayed code and state issued another session to %s",
			replay.Header().Get("Location"),
		)
	}
}

func TestBackendSetCookieCannotPlantGatehousePrefix(t *testing.T) {
	t.Parallel()
	header := http.Header{}
	header.Add("Set-Cookie", "__Secure-gatehouse-session-user=planted; "+
		"Domain=noqer.com; Path=/; Secure; HttpOnly; SameSite=Lax")
	header.Add("Set-Cookie", "__Secure-gatehouse-flow-admin=planted; "+
		"Domain=noqer.com; Path=/; Secure; HttpOnly")
	header.Add("Set-Cookie", "app=kept; Path=/")
	StripCookies(header)
	for _, line := range header.Values("Set-Cookie") {
		name, _, _ := strings.Cut(line, "=")
		if strings.HasPrefix(strings.TrimSpace(name), cookiePrefix) {
			t.Fatalf("backend Set-Cookie still plants %q", line)
		}
	}
	if got := header.Values("Set-Cookie"); len(got) != 1 || got[0] != "app=kept; Path=/" {
		t.Fatalf("application Set-Cookie = %#v", got)
	}
}

func TestStripCookiesDropsCommaSeparatedGatehouseCookie(t *testing.T) {
	t.Parallel()
	for _, line := range []string{
		"app=1, __Secure-gatehouse-session-user=SECRET",
		"app=1,__Secure-gatehouse-session-admin=SECRET",
		"__Secure-gatehouse-flow-user=SECRET, theme=dark",
	} {
		t.Run(line, func(t *testing.T) {
			t.Parallel()
			header := http.Header{"Cookie": {line}}
			StripCookies(header)
			kept := header.Get("Cookie")
			for _, name := range cookiePairNames(kept) {
				if strings.HasPrefix(name, cookiePrefix) {
					t.Fatalf("forwarded cookie %q from %q", name, line)
				}
			}
			if strings.Contains(line, "theme=dark") && !strings.Contains(kept, "theme=dark") {
				t.Fatalf("application cookie dropped from %q, kept %q", line, kept)
			}
		})
	}
}

const userCallbackURL = "https://auth-user-cluster-1.noqer.com/oauth2/callback"

type fakeIssuer struct {
	server *httptest.Server
	key    *ecdsa.PrivateKey
	issuer string
	mu     sync.Mutex
	nonce  string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &fakeIssuer{key: key}
	issuer.server = httptest.NewTLSServer(http.HandlerFunc(issuer.serve))
	issuer.issuer = issuer.server.URL
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (f *fakeIssuer) userClass(t *testing.T) *Class {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	class := NewClass("user", config.AuthClass{
		Issuer:        f.issuer,
		ClientID:      "edge-user-cluster-1",
		Scopes:        []string{"openid"},
		Callback:      userCallbackURL,
		SoftExpiry:    "1h",
		HardExpiry:    "8h",
		CookieDomain:  ".noqer.com",
		RedirectHosts: []string{"app.noqer.com"},
	}, map[string]string{
		"oidc-user-client-secret": "disposable-client",
		"cookie-user-current":     base64.StdEncoding.EncodeToString(raw),
	}, f.server.Client().Transport, nil)
	if class == nil {
		t.Fatal("NewClass rejected the local fake issuer")
	}
	return class
}

func (f *fakeIssuer) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, map[string]any{
			"issuer":                                f.issuer,
			"authorization_endpoint":                f.issuer + "/authorize",
			"token_endpoint":                        f.issuer + "/token",
			"jwks_uri":                              f.issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	case "/jwks":
		writeJSON(w, map[string]any{"keys": []any{ecJWK(f.key)}})
	case "/token":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		nonce := f.nonce
		f.mu.Unlock()
		clientID, _, _ := r.BasicAuth()
		token, err := signIDToken(map[string]any{
			"iss":                f.issuer,
			"aud":                clientID,
			"nonce":              nonce,
			"sub":                "subject-id",
			"iat":                time.Now().Unix(),
			"exp":                time.Now().Add(time.Hour).Unix(),
			"preferred_username": "fixture",
			"email_verified":     true,
			"groups":             []string{"users"},
		}, f.key)
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"access_token": "local-access",
			"token_type":   "Bearer",
			"id_token":     token,
		})
	default:
		http.NotFound(w, r)
	}
}

func startLogin(
	t *testing.T,
	issuer *fakeIssuer,
	class *Class,
	now time.Time,
) (*http.Cookie, url.Values) {
	t.Helper()
	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, "https://app.noqer.com/library", nil,
	)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	rec := httptest.NewRecorder()
	if class.Authorize(rec, req, "app.noqer.com", "/library", now) {
		t.Fatal("unauthenticated navigation was forwarded")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("login start status %d body %s", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || location.Scheme == "" {
		t.Fatalf("location %q: %v", rec.Header().Get("Location"), err)
	}
	issuer.mu.Lock()
	issuer.nonce = location.Query().Get("nonce")
	issuer.mu.Unlock()
	return cookieNamed(t, rec, class.cookieName(flowCookie)), location.Query()
}

func callbackOn(
	t *testing.T,
	class *Class,
	code, state string,
	flow *http.Cookie,
	now time.Time,
) *httptest.ResponseRecorder {
	t.Helper()
	target := userCallbackURL + "?code=" + url.QueryEscape(code) +
		"&state=" + url.QueryEscape(state)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	class.Callback(rec, req, "auth-user-cluster-1.noqer.com", "/oauth2/callback", now)
	return rec
}

func cookieNamed(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("missing cookie %s", name)
	return nil
}

func cookiePairNames(line string) []string {
	var names []string
	for part := range strings.SplitSeq(line, ";") {
		for piece := range strings.SplitSeq(part, ",") {
			name, _, _ := strings.Cut(piece, "=")
			if name = strings.TrimSpace(name); name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
	}
}

func ecJWK(key *ecdsa.PrivateKey) map[string]string {
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"alg": "ES256",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(fixedCoord(key.X)),
		"y":   base64.RawURLEncoding.EncodeToString(fixedCoord(key.Y)),
	}
}

func fixedCoord(value *big.Int) []byte {
	raw := value.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(raw):], raw)
	return out
}

func signIDToken(claims map[string]any, key *ecdsa.PrivateKey) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encode := base64.RawURLEncoding.EncodeToString
	input := encode([]byte(`{"alg":"ES256"}`)) + "." + encode(payload)
	digest := sha256.Sum256([]byte(input))
	sigR, sigS, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	raw := make([]byte, 64)
	sigR.FillBytes(raw[:32])
	sigS.FillBytes(raw[32:])
	return input + "." + encode(raw), nil
}
