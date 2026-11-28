package oidclogin

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const (
	fixtureIssuer = "https://issuer.example.test"
	fixtureClient = "disposable-client"
	fixtureNonce  = "original-nonce"
)

// fakeIssuer answers discovery, token, and JWKS requests on the loopback
// transport. It never dials a network.
type fakeIssuer struct {
	mu       sync.Mutex
	jwks     string
	token    string
	jwksCode int
	jwksErr  error
	jwksHits int
}

func (f *fakeIssuer) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		return jsonResponse(http.StatusOK, `{
			"issuer":"`+fixtureIssuer+`",
			"authorization_endpoint":"`+fixtureIssuer+`/authorize",
			"token_endpoint":"`+fixtureIssuer+`/token",
			"jwks_uri":"`+fixtureIssuer+`/jwks",
			"id_token_signing_alg_values_supported":["RS256","ES256","HS256","none"]
		}`), nil
	case "/token":
		body := `{"access_token":"disposable","token_type":"Bearer","id_token":"` + f.token + `"}`
		return jsonResponse(http.StatusOK, body), nil
	case "/jwks":
		f.jwksHits++
		if f.jwksErr != nil {
			return nil, f.jwksErr
		}
		code := f.jwksCode
		if code == 0 {
			code = http.StatusOK
		}
		return jsonResponse(code, f.jwks), nil
	default:
		return jsonResponse(http.StatusNotFound, `{"error":"unknown"}`), nil
	}
}

func (f *fakeIssuer) setToken(token string) {
	f.mu.Lock()
	f.token = token
	f.mu.Unlock()
}

func (f *fakeIssuer) setJWKS(status int, body string, err error) {
	f.mu.Lock()
	f.jwksCode = status
	f.jwks = body
	f.jwksErr = err
	f.mu.Unlock()
}

func (f *fakeIssuer) hits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jwksHits
}

func (f *fakeIssuer) class() *Class {
	return &Class{
		provider: newProvider(fixtureIssuer, fixtureClient, f),
		oauth: oauth2.Config{
			ClientID:     fixtureClient,
			ClientSecret: "disposable-secret",
			RedirectURL:  fixtureIssuer + "/callback",
		},
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func jwksOf(t *testing.T, keys ...any) string {
	t.Helper()
	set := jose.JSONWebKeySet{}
	for _, key := range keys {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			set.Keys = append(set.Keys, jose.JSONWebKey{
				Key: &k.PublicKey, KeyID: "rsa-" + k.N.String()[:6],
				Algorithm: string(jose.RS256), Use: "sig",
			})
		case jose.JSONWebKey:
			set.Keys = append(set.Keys, k)
		default:
			t.Fatalf("unsupported key %T", key)
		}
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func rsaJWK(key *rsa.PrivateKey, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig",
	}
}

func signClaims(
	t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any,
) string {
	t.Helper()
	var opts *jose.SignerOptions
	if kid != "" {
		opts = (&jose.SignerOptions{}).WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func fixtureClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":                fixtureIssuer,
		"aud":                fixtureClient,
		"nonce":              fixtureNonce,
		"sub":                "subject-id",
		"iat":                now.Unix(),
		"exp":                now.Add(time.Minute).Unix(),
		"preferred_username": "fixture",
		"email":              "fixture@example.test",
		"email_verified":     true,
		"groups":             []string{"readers"},
	}
}

func newRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func exchangeFixture(t *testing.T, class *Class) (session, error) {
	t.Helper()
	return class.exchange(t.Context(), "disposable-code", flow{
		Nonce: fixtureNonce, Verifier: "fixture-verifier",
	})
}

func TestNotYetValidClockSkew(t *testing.T) {
	key := newRSA(t)
	issuer := &fakeIssuer{}
	issuer.setJWKS(http.StatusOK, jwksOf(t, rsaJWK(key, "rsa-1")), nil)
	class := issuer.class()
	now := time.Now()
	var accepted []time.Duration
	for _, skew := range []time.Duration{
		61 * time.Second,
		90 * time.Second,
		4 * time.Minute,
		5*time.Minute - time.Second,
		5 * time.Minute,
		5*time.Minute + 2*time.Second,
	} {
		claims := fixtureClaims(now)
		claims["nbf"] = now.Add(skew).Unix()
		issuer.setToken(signClaims(t, jose.RS256, key, "rsa-1", claims))
		session, err := exchangeFixture(t, class)
		if err == nil {
			accepted = append(accepted, skew.Round(time.Second))
			if session.User != "fixture" {
				t.Fatalf("accepted skew %s as %q", skew, session.User)
			}
		}
	}
	expired := fixtureClaims(now)
	expired["exp"] = now.Add(-30 * time.Second).Unix()
	issuer.setToken(signClaims(t, jose.RS256, key, "rsa-1", expired))
	if _, err := exchangeFixture(t, class); err == nil {
		t.Fatal("accepted a token expired for 30s")
	}
	if len(accepted) > 0 {
		t.Fatalf("accepted not-yet-valid tokens at %v; skew must be at most 60s", accepted)
	}
}

func TestRemovedJWKSKeyStillVerifies(t *testing.T) {
	current := newRSA(t)
	replacement := newRSA(t)
	issuer := &fakeIssuer{}
	issuer.setJWKS(http.StatusOK, jwksOf(t, rsaJWK(current, "current")), nil)
	class := issuer.class()
	now := time.Now()
	issuer.setToken(signClaims(t, jose.RS256, current, "current", fixtureClaims(now)))
	if _, err := exchangeFixture(t, class); err != nil {
		t.Fatalf("priming login failed: %v", err)
	}
	issuer.setJWKS(http.StatusOK, jwksOf(t, rsaJWK(replacement, "replacement")), nil)
	issuer.setToken(signClaims(t, jose.RS256, current, "current", fixtureClaims(now)))
	session, err := exchangeFixture(t, class)
	if err == nil {
		t.Fatalf("accepted a token after its signing key left the JWKS (user %q, jwks fetches %d)",
			session.User, issuer.hits())
	}
	if !errors.Is(err, errToken) {
		t.Fatalf("removed key returned %v", err)
	}
}
