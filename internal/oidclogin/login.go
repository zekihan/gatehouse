// Package oidclogin implements the Gatehouse browser login and session protocol.
package oidclogin

import (
	"crypto/subtle"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/zekihan/gatehouse/internal/config"
)

const (
	SignInPath    = "/oauth2/sign_in"
	SignOutPath   = "/oauth2/sign_out"
	sessionCookie = "session"
	flowCookie    = "flow"
)

// Class is immutable except for its lazily loaded provider metadata and keys.
type Class struct {
	name     string
	domain   string
	keys     cookieKeys
	provider *provider
	oauth    oauth2.Config
	callback *url.URL
	groups   []string
	hosts    []string
	soft     time.Duration
	hard     time.Duration
}

type flow struct {
	State    string
	Nonce    string
	Verifier string
	Return   string
	Expires  time.Time
}

type session struct {
	User     string
	Email    string
	Groups   []string
	IssuedAt time.Time
}

func NewClass(
	name string,
	cfg config.AuthClass,
	secrets map[string]string,
	transport http.RoundTripper,
	old *Class,
) *Class {
	secret := secrets["oidc-"+name+"-client-secret"]
	current := decodeKey(secrets["cookie-"+name+"-current"])
	previousValue := secrets["cookie-"+name+"-previous"]
	previous := decodeKey(previousValue)
	if secret == "" || current == nil || (previousValue != "" && previous == nil) {
		return nil
	}
	callback := httpsEndpoint(cfg.Callback)
	if callback == nil || httpsEndpoint(cfg.Issuer) == nil {
		return nil
	}
	soft, softErr := time.ParseDuration(cfg.SoftExpiry)
	hard, hardErr := time.ParseDuration(cfg.HardExpiry)
	if softErr != nil || hardErr != nil || soft <= 0 || hard <= soft {
		return nil
	}
	p := newProvider(cfg.Issuer, cfg.ClientID, transport)
	if old != nil && old.provider.issuer == cfg.Issuer && old.provider.clientID == cfg.ClientID {
		p = old.provider
	}
	return &Class{
		name: name, domain: strings.TrimPrefix(cfg.CookieDomain, "."),
		keys:     cookieKeys{current: current, previous: previous},
		provider: p,
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: secret, RedirectURL: cfg.Callback,
			Scopes: cfg.Scopes,
		},
		callback: callback, groups: cfg.Groups, hosts: cfg.RedirectHosts,
		soft: soft, hard: hard,
	}
}

// Authorize returns true only for requests that can be forwarded to the app.
func (c *Class) Authorize(
	w http.ResponseWriter,
	r *http.Request,
	host, path string,
	now time.Time,
) bool {
	switch {
	case c == nil:
		authError(w, http.StatusServiceUnavailable)
	case (path == SignOutPath || path == SignInPath) && path != r.URL.EscapedPath():
		http.NotFound(w, r)
	case path == SignOutPath:
		c.logout(w, r, host)
	case path == SignInPath:
		c.signIn(w, r, host, now)
	default:
		return c.authorizeSession(w, r, host, now)
	}
	return false
}

func (c *Class) Callback(w http.ResponseWriter, r *http.Request, host, path string, now time.Time) {
	if c == nil {
		authError(w, http.StatusServiceUnavailable)
		return
	}
	if host != c.callback.Hostname() || path != c.callback.Path ||
		r.URL.EscapedPath() != c.callback.EscapedPath() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		authError(w, http.StatusMethodNotAllowed)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	flow, valid := c.readFlow(r, query["state"], now)
	if err != nil || !valid {
		authError(w, http.StatusBadRequest)
		return
	}
	http.SetCookie(w, c.cookie(flowCookie, "", 0))
	if len(query["code"]) != 1 || query.Get("code") == "" || query.Has("error") {
		authError(w, http.StatusUnauthorized)
		return
	}
	c.issueSession(w, r, query.Get("code"), flow, now)
}

func (c *Class) authorizeSession(
	w http.ResponseWriter,
	r *http.Request,
	host string,
	now time.Time,
) bool {
	var session session
	navigate := navigation(r)
	if c.openCookie(r, sessionCookie, &session) && now.Before(session.IssuedAt.Add(c.hard)) &&
		!session.IssuedAt.After(now.Add(time.Minute)) {
		if !c.permits(session.Groups) {
			authError(w, http.StatusForbidden)
			return false
		}
		if !navigate || now.Before(session.IssuedAt.Add(c.soft)) {
			r.Header.Set("X-Auth-Request-User", session.User)
			r.Header.Set("X-Auth-Request-Email", session.Email)
			r.Header.Set("X-Auth-Request-Groups", strings.Join(session.Groups, ","))
			return true
		}
	}
	if !navigate {
		authError(w, http.StatusUnauthorized)
		return false
	}
	target := url.URL{
		Scheme: "https", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath,
		RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery,
	}
	c.start(w, r, target.String(), now)
	return false
}

func navigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		return true
	}
	for _, line := range r.Header.Values("Accept") {
		for media := range strings.SplitSeq(line, ",") {
			mimeType, params, err := mime.ParseMediaType(media)
			if err == nil && mimeType == "text/html" && acceptableQuality(params["q"]) {
				return true
			}
		}
	}
	return false
}

func (c *Class) permits(groups []string) bool {
	return len(c.groups) == 0 || slices.ContainsFunc(c.groups, func(group string) bool {
		return slices.Contains(groups, group)
	})
}

func authError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}

func redirect(w http.ResponseWriter, target string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

func (c *Class) validReturn(target string) bool {
	u, err := url.Parse(target)
	return err == nil && u.Scheme == "https" && u.User == nil && u.Fragment == "" &&
		slices.Contains(c.hosts, u.Host) && strings.HasPrefix(u.Path, "/") &&
		!strings.Contains(u.Path, "\\")
}

func (c *Class) signIn(w http.ResponseWriter, r *http.Request, host string, now time.Time) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		authError(w, http.StatusMethodNotAllowed)
		return
	}
	if !navigation(r) {
		authError(w, http.StatusUnauthorized)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["rd"]) > 1 {
		authError(w, http.StatusBadRequest)
		return
	}
	target := query.Get("rd")
	if target == "" {
		target = "https://" + host + "/"
	}
	c.start(w, r, target, now)
}

func (c *Class) start(w http.ResponseWriter, r *http.Request, target string, now time.Time) {
	if !c.validReturn(target) {
		authError(w, http.StatusBadRequest)
		return
	}
	provider, err := c.provider.load(r.Context())
	if err != nil {
		authError(w, http.StatusServiceUnavailable)
		return
	}
	flow := flow{
		State: oauth2.GenerateVerifier(), Nonce: oauth2.GenerateVerifier(),
		Verifier: oauth2.GenerateVerifier(), Return: target, Expires: now.Add(flowLifetime),
	}
	if !c.sealCookie(w, flowCookie, flow, flowLifetime) {
		authError(w, http.StatusBadRequest)
		return
	}
	client := c.oauth
	client.Endpoint = provider.endpoint
	redirect(w, client.AuthCodeURL(flow.State, oauth2.S256ChallengeOption(flow.Verifier),
		oauth2.SetAuthURLParam("nonce", flow.Nonce)))
}

func (c *Class) logout(w http.ResponseWriter, r *http.Request, host string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		authError(w, http.StatusMethodNotAllowed)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "https://"+host {
		authError(w, http.StatusForbidden)
		return
	}
	http.SetCookie(w, c.cookie(flowCookie, "", 0))
	http.SetCookie(w, c.cookie(sessionCookie, "", 0))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (c *Class) readFlow(r *http.Request, states []string, now time.Time) (flow, bool) {
	var data flow
	valid := len(states) == 1 && c.openCookie(r, flowCookie, &data) &&
		subtle.ConstantTimeCompare([]byte(data.State), []byte(states[0])) == 1 &&
		now.Before(data.Expires) && c.validReturn(data.Return)
	return data, valid
}

func (c *Class) issueSession(
	w http.ResponseWriter,
	r *http.Request,
	code string,
	flow flow,
	now time.Time,
) {
	session, err := c.exchange(r.Context(), code, flow)
	switch {
	case errors.Is(err, errProvider):
		authError(w, http.StatusServiceUnavailable)
	case err != nil:
		authError(w, http.StatusUnauthorized)
	case !c.permits(session.Groups):
		http.SetCookie(w, c.cookie(sessionCookie, "", 0))
		authError(w, http.StatusForbidden)
	default:
		session.IssuedAt = now
		if !c.sealCookie(w, sessionCookie, session, c.hard) {
			authError(w, http.StatusUnauthorized)
			return
		}
		redirect(w, flow.Return)
	}
}

func acceptableQuality(value string) bool {
	if value == "" {
		return true
	}
	q, err := strconv.ParseFloat(value, 64)
	return err == nil && q > 0 && q <= 1
}
