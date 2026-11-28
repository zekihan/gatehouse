package oidclogin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type tokenTransport func(*http.Request) (*http.Response, error)

func (f tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestIDTokenValidation(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const issuer, client, nonce = "https://auth.example.test", "disposable-client", "original-nonce"
	now := time.Now()
	for _, tc := range []struct {
		name  string
		claim string
		value any
		key   *ecdsa.PrivateKey
		valid bool
	}{
		{name: "valid", key: key, valid: true},
		{name: "issuer", key: key, claim: "iss", value: "https://another.example.test"},
		{name: "audience", key: key, claim: "aud", value: "another-client"},
		{name: "authorized party", key: key, claim: "azp", value: "another-client"},
		{name: "nonce", key: key, claim: "nonce", value: "another-nonce"},
		{name: "expiration", key: key, claim: "exp", value: now.Add(-time.Minute).Unix()},
		{name: "signature", key: wrongSigner},
		{name: "header value", key: key, claim: "preferred_username", value: "invalid\nvalue"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := map[string]any{
				"iss":                issuer,
				"aud":                client,
				"nonce":              nonce,
				"sub":                "subject-id",
				"iat":                now.Unix(),
				"exp":                now.Add(time.Minute).Unix(),
				"preferred_username": "fixture",
			}
			if tc.claim != "" {
				claims[tc.claim] = tc.value
			}
			token := signTestToken(t, claims, tc.key)
			class := &Class{
				provider: newProvider(
					issuer,
					client,
					tokenTransport(func(r *http.Request) (*http.Response, error) {
						if err := r.ParseForm(); err != nil ||
							r.PostForm.Get("code_verifier") != "fixture-verifier" {
							t.Error("token exchange did not send the original PKCE verifier")
						}
						return &http.Response{
							StatusCode: http.StatusOK,
							Header:     http.Header{"Content-Type": {"application/json"}},
							Body: io.NopCloser(
								strings.NewReader(
									`{"access_token":"disposable","id_token":"` + token + `"}`,
								),
							),
						}, nil
					}),
				),
				oauth: oauth2.Config{ClientID: client},
			}
			class.provider.metadata = &metadata{
				endpoint: oauth2.Endpoint{
					TokenURL:  issuer + "/token",
					AuthStyle: oauth2.AuthStyleInHeader,
				},
				verifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{
					PublicKeys: []crypto.PublicKey{&key.PublicKey},
				}, &oidc.Config{ClientID: client, SupportedSigningAlgs: []string{oidc.ES256}}),
			}
			session, err := class.exchange(t.Context(), "disposable-code", flow{
				Nonce: nonce, Verifier: "fixture-verifier",
			})
			if tc.valid && (err != nil || session.User != "fixture") {
				t.Fatal("valid ID token did not yield the expected session identity")
			}
			if !tc.valid && !errors.Is(err, errToken) {
				t.Fatalf("invalid token returned %v", err)
			}
		})
	}
}

func signTestToken(t *testing.T, claims map[string]any, key *ecdsa.PrivateKey) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	input := encode([]byte(`{"alg":"ES256"}`)) + "." + encode(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	// JOSE uses fixed-width coordinates rather than DER encoding.
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return input + "." + encode(raw)
}
