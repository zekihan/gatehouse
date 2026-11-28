package oidclogin

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const providerTimeout = 5 * time.Second

var errProvider = errors.New("OIDC provider unavailable")

type provider struct {
	issuer   string
	clientID string
	client   *http.Client
	mu       sync.Mutex
	retryAt  time.Time
	metadata *metadata
}

func newProvider(issuer, clientID string, transport http.RoundTripper) *provider {
	return &provider{issuer: issuer, clientID: clientID, client: &http.Client{
		Transport: transport, Timeout: providerTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

type metadata struct {
	endpoint oauth2.Endpoint
	verifier *oidc.IDTokenVerifier
}

func (p *provider) load(ctx context.Context) (*metadata, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.metadata != nil {
		return p.metadata, nil
	}
	if time.Now().Before(p.retryAt) {
		return nil, errProvider
	}
	discovery, err := oidc.NewProvider(oidc.ClientContext(ctx, p.client), p.issuer)
	if err != nil {
		p.retryAt = time.Now().Add(time.Second)
		return nil, errProvider
	}
	endpoint := discovery.Endpoint()
	var claims struct {
		JWKS string `json:"jwks_uri"`
	}
	if discovery.Claims(&claims) != nil || httpsEndpoint(claims.JWKS) == nil ||
		httpsEndpoint(endpoint.AuthURL) == nil || httpsEndpoint(endpoint.TokenURL) == nil {
		p.retryAt = time.Now().Add(time.Second)
		return nil, errProvider
	}
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	p.metadata = &metadata{
		endpoint: endpoint,
		verifier: discovery.Verifier(&oidc.Config{ClientID: p.clientID}),
	}
	return p.metadata, nil
}

func httpsEndpoint(raw string) *url.URL {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" ||
		endpoint.User != nil || endpoint.Fragment != "" {
		return nil
	}
	return endpoint
}
