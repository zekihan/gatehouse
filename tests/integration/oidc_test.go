//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	sessionName = "__Secure-gatehouse-session-user"
	flowName    = "__Secure-gatehouse-flow-user"
	echoURL     = appURL + "/echo?return=original"
	consentAPI  = issuerURL + "/api/oidc/consent"
)

func TestGatehouseAuthelia(t *testing.T) {
	fixture := newOIDCFixture(t)
	var posts atomic.Int32
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		body, _ := io.ReadAll(r.Body)
		writeJSON(w, map[string]string{
			"user":   r.Header.Get("X-Auth-Request-User"),
			"email":  r.Header.Get("X-Auth-Request-Email"),
			"groups": r.Header.Get("X-Auth-Request-Groups"),
			"cookie": r.Header.Get("Cookie"),
			"body":   string(body),
		})
	}))
	t.Cleanup(app.Close)
	endpoint := strings.TrimPrefix(app.URL, "http://")
	initial := testCookieKey()
	_, _, edgeA := fixture.newReplica(t, endpoint, initial, "")
	planeB, snapB, edgeB := fixture.newReplica(t, endpoint, initial, "")
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browserA := browser(edgeA, jar)
	browserB := browser(edgeB, jar)
	rawB := browser(edgeB, nil)
	verifyMachineAndReturn(t, browserA, fixture)

	authURL := startLogin(t, browserA, echoURL)
	if fixture.discover.Load() != 1 || fixture.jwks.Load() != 0 {
		t.Fatal("authorization start must load discovery without loading signing keys")
	}
	fixture.signInToAuthelia(t, browserA)
	callback := authorizationCallback(t, browserA, authURL, true)
	flow := jarCookie(t, jar, callback, flowName)
	expectStatus(t, request(t, rawB, http.MethodGet, callback, nil, tamper(flow)),
		http.StatusBadRequest)
	checkWrongState(t, rawB, callback, flow)

	saved := completeLogin(t, browserB, callback, echoURL)
	savedAt := time.Now()
	if fixture.jwks.Load() != 1 {
		t.Fatal("the callback on the second replica did not load the signing keys")
	}
	expectStatus(
		t,
		request(t, browserB, http.MethodGet, strings.TrimSuffix(callbackURL, callbackPath)+"/other",
			nil, nil),
		http.StatusNotFound,
	)
	checkBackendIdentity(t, rawB, saved)
	expectStatus(t, request(t, rawB, http.MethodGet, echoURL, nil, tamper(saved)),
		http.StatusUnauthorized)

	// The active replica keeps its provider cache across a cookie key rotation.
	snapB.DataPlane.OIDCSecrets["cookie-user-current"] = testCookieKey()
	snapB.DataPlane.OIDCSecrets["cookie-user-previous"] = initial
	if err := planeB.Update(snapB); err != nil {
		t.Fatal(err)
	}
	checkBackendIdentity(t, rawB, saved)
	waitUntil(t, savedAt.Add(softExpiry))
	formPost(t, rawB, saved, http.StatusOK)
	renew := startLogin(t, browserB, echoURL)
	completeLogin(t, browserB, authorizationCallback(t, browserB, renew, false), echoURL)
	if fixture.jwks.Load() != 1 {
		t.Fatal("renewal unexpectedly reloaded the provider signing key")
	}

	waitUntil(t, savedAt.Add(hardExpiry))
	formPost(t, rawB, saved, http.StatusUnauthorized)
	expectStatus(t, request(t, rawB, http.MethodGet, echoURL, nil, cookieHeader(saved)),
		http.StatusUnauthorized)
	expiredHeaders := cookieHeader(saved)
	expiredHeaders.Set("Sec-Fetch-Mode", "navigate")
	expired := request(t, rawB, http.MethodGet, echoURL, nil, expiredHeaders)
	requireRedirect(t, expired, issuerHost)
	if posts.Load() != 1 {
		t.Fatalf("upstream received %d form writes, want exactly one", posts.Load())
	}

	fixture.rotateSigningKey(t)
	login := startLogin(t, browserB, echoURL)
	fixture.signInToAuthelia(t, browserB)
	current := completeLogin(t, browserB, authorizationCallback(t, browserB, login, false), echoURL)
	if fixture.jwks.Load() != 1 || fixture.discover.Load() != 0 {
		t.Fatal("the existing verifier did not refresh its signing keys independently of discovery")
	}
	checkBackendIdentity(t, rawB, current)
	logout := request(t, browserB, http.MethodPost, appURL+"/oauth2/sign_out", nil,
		http.Header{"Origin": {appURL}})
	expectStatus(t, logout, http.StatusNoContent)
	deletion := responseCookie(t, logout, sessionName)
	if deletion.MaxAge != -1 || deletion.Domain != "gatehouse.test" || deletion.Path != "/" {
		t.Fatal("logout did not expire the domain session")
	}
	expectStatus(
		t,
		request(t, browserB, http.MethodGet, echoURL, nil, nil),
		http.StatusUnauthorized,
	)
}

func verifyMachineAndReturn(t *testing.T, client *http.Client, fixture *oidcFixture) {
	t.Helper()
	expectStatus(t, request(t, client, http.MethodGet, echoURL, nil, nil), http.StatusUnauthorized)
	formPost(t, client, nil, http.StatusUnauthorized)
	for _, target := range []string{
		"https://foreign.gatehouse.test/", "//foreign.example/",
		"https://app.gatehouse.test:444/",
	} {
		signIn := appURL + "/oauth2/sign_in?rd=" + url.QueryEscape(target)
		resp := request(
			t,
			client,
			http.MethodGet,
			signIn,
			nil,
			http.Header{"Accept": {"text/html"}},
		)
		expectStatus(t, resp, http.StatusBadRequest)
		if resp.Header.Get("Location") != "" {
			t.Fatal("unapproved destination produced a redirect")
		}
	}
	if fixture.discover.Load() != 0 || fixture.jwks.Load() != 0 {
		t.Fatal("unauthenticated machine requests or invalid returns contacted Authelia")
	}
}

func startLogin(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	response := request(
		t,
		client,
		http.MethodGet,
		target,
		nil,
		http.Header{"Accept": {"text/html"}},
	)
	location := requireRedirect(t, response, issuerHost)
	query := location.Query()
	if query.Get("code_challenge_method") != "S256" || len(query.Get("code_challenge")) != 43 ||
		query.Get("response_type") != "code" || query.Get("redirect_uri") != callbackURL ||
		query.Get("nonce") == "" || query.Get("state") == "" ||
		strings.Contains(query.Get("scope"), "offline_access") {
		t.Fatal("missing or invalid authorization parameters")
	}
	cookie := responseCookie(t, response, flowName)
	if cookie.MaxAge != 600 || cookie.Domain != "gatehouse.test" || !cookie.Secure ||
		!cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("unexpected flow cookie attributes")
	}
	return location.String()
}

func (f *oidcFixture) signInToAuthelia(t *testing.T, client *http.Client) {
	t.Helper()
	var login struct{ Status string }
	postJSON(t, client, issuerURL+"/api/firstfactor", map[string]string{
		"username": testUser, "password": f.password,
	}, &login)
	if login.Status != "OK" {
		t.Fatal("Authelia did not authenticate the fixture user")
	}
}

func authorizationCallback(
	t *testing.T,
	client *http.Client,
	authorize string,
	consent bool,
) string {
	t.Helper()
	resp := request(t, client, http.MethodGet, authorize, nil, nil)
	location := requireRedirect(t, resp, "")
	if !consent {
		if location.Hostname() != callbackHost || location.Query().Get("code") == "" {
			t.Fatalf("renewal requested another consent screen or failed, path %s", location.Path)
		}
		return location.String()
	}
	flow := location.Query().Get("flow_id")
	if location.Hostname() != issuerHost || flow == "" {
		t.Fatalf("first authorization did not request consent, path %s", location.Path)
	}
	var form struct {
		Status string
		Data   struct {
			ClientID         string `json:"client_id"`
			PreConfiguration bool   `json:"pre_configuration"`
			Claims           []string
		}
	}
	readJSON(
		t,
		request(t, client, http.MethodGet, consentAPI+"?flow_id="+url.QueryEscape(flow), nil, nil),
		&form,
	)
	if form.Status != "OK" || !form.Data.PreConfiguration || form.Data.ClientID != testClient {
		t.Fatal("Authelia did not offer pre-configured consent")
	}
	var result struct {
		Status string
		Data   struct {
			Redirect string `json:"redirect_uri"`
		}
	}
	postJSON(t, client, consentAPI, map[string]any{
		"flow_id": flow, "client_id": testClient, "consent": true, "pre_configure": true,
		"claims": form.Data.Claims,
	}, &result)
	if result.Status != "OK" || result.Data.Redirect == "" {
		t.Fatal("Authelia did not save consent")
	}
	consented := request(t, client, http.MethodGet, result.Data.Redirect, nil, nil)
	callback := requireRedirect(t, consented, callbackHost)
	if callback.Query().Get("code") == "" || callback.Query().Has("error") {
		t.Fatalf("Authelia did not issue an authorization code after consent: %s",
			safeOAuthError(callback.Query().Get("error")))
	}
	return callback.String()
}

func completeLogin(t *testing.T, client *http.Client, callback, target string) *http.Cookie {
	t.Helper()
	resp := request(t, client, http.MethodGet, callback, nil, nil)
	if requireRedirect(t, resp, protectedHost).String() != target {
		t.Fatal("callback did not restore the original request target")
	}
	cookie := responseCookie(t, resp, sessionName)
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode ||
		cookie.MaxAge != int(hardExpiry.Seconds()) || cookie.Domain != "gatehouse.test" {
		t.Fatal("unexpected session cookie attributes")
	}
	if responseCookie(t, resp, flowName).MaxAge != -1 {
		t.Fatal("successful callback did not clear the flow")
	}
	return cookie
}

func checkWrongState(t *testing.T, client *http.Client, callback string, flow *http.Cookie) {
	t.Helper()
	wrong, err := url.Parse(callback)
	if err != nil {
		t.Fatal(err)
	}
	q := wrong.Query()
	q.Set("state", "unrelated")
	wrong.RawQuery = q.Encode()
	resp := request(t, client, http.MethodGet, wrong.String(), nil, cookieHeader(flow))
	expectStatus(t, resp, http.StatusBadRequest)
}

func checkBackendIdentity(t *testing.T, client *http.Client, session *http.Cookie) {
	t.Helper()
	header := cookieHeader(session)
	header.Set("Cookie", header.Get("Cookie")+"; application=kept")
	header.Set("X-Auth-Request-User", "spoof")
	header.Set("X_Auth_Request_Groups", "spoof")
	header.Set("Connection", "X-Auth-Request-Email")
	var body map[string]string
	readJSON(t, request(t, client, http.MethodGet, echoURL, nil, header), &body)
	if body["user"] != testUser || body["email"] != "tester@gatehouse.test" ||
		body["groups"] != "test-users" || body["cookie"] != "application=kept" {
		t.Errorf("unexpected upstream identity headers or cookie stripping")
	}
}

func formPost(t *testing.T, client *http.Client, session *http.Cookie, status int) {
	t.Helper()
	headers := http.Header{"Accept": {"text/html"}, "Sec-Fetch-Mode": {"navigate"}}
	if session != nil {
		headers.Set("Cookie", cookieHeader(session).Get("Cookie"))
	}
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	const body = "requested=write"
	resp := request(t, client, http.MethodPost, echoURL, strings.NewReader(body), headers)
	if status != http.StatusOK {
		expectStatus(t, resp, status)
		if resp.Header.Get("Location") != "" {
			t.Fatal("form POST received a redirect")
		}
		return
	}
	var forwarded map[string]string
	readJSON(t, resp, &forwarded)
	if forwarded["body"] != body {
		t.Fatal("form body changed on delivery")
	}
}

func waitUntil(t *testing.T, when time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(when))
	defer timer.Stop()
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-timer.C:
	}
}

func browser(transport http.RoundTripper, jar http.CookieJar) *http.Client {
	return &http.Client{
		Transport:     transport,
		Jar:           jar,
		Timeout:       5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type oidcResponse struct {
	*http.Response

	body []byte
}

func request(
	t *testing.T,
	client *http.Client,
	method, target string,
	body io.Reader,
	headers http.Header,
) oidcResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal("build test request")
	}
	if headers != nil {
		req.Header = headers
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, req.URL.Path, err)
	}
	return captureResponse(t, resp)
}

func expectStatus(t *testing.T, resp oidcResponse, wanted int) {
	t.Helper()
	if resp.StatusCode != wanted {
		t.Fatalf(
			"%s %s status %d, want %d",
			resp.Request.Method,
			resp.Request.URL.Path,
			resp.StatusCode,
			wanted,
		)
	}
}

func requireRedirect(t *testing.T, resp oidcResponse, wantHost string) *url.URL {
	t.Helper()
	status := http.StatusFound
	if resp.Request.URL.Hostname() == issuerHost && resp.StatusCode == http.StatusSeeOther {
		status = http.StatusSeeOther
	}
	expectStatus(t, resp, status)
	location, err := resp.Location()
	if err != nil || location.Scheme != "https" ||
		(wantHost != "" && location.Hostname() != wantHost) {
		t.Fatalf("unexpected redirect from %s", resp.Request.URL.Path)
	}
	return location
}

func responseCookie(t *testing.T, resp oidcResponse, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("expected %s cookie", name)
	return nil
}

func jarCookie(t *testing.T, jar http.CookieJar, target, name string) *http.Cookie {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal("parse callback URL")
	}
	for _, cookie := range jar.Cookies(u) {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie jar missing %s", name)
	return nil
}

func tamper(cookie *http.Cookie) http.Header {
	prefix := "A"
	if cookie.Value[0] == 'A' {
		prefix = "B"
	}
	return http.Header{"Cookie": {cookie.Name + "=" + prefix + cookie.Value[1:]}}
}

func cookieHeader(cookie *http.Cookie) http.Header {
	return http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}
}

func postJSON(t *testing.T, client *http.Client, target string, body, result any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	readJSON(t, request(t, client, http.MethodPost, target, bytes.NewReader(data), http.Header{
		"Content-Type": {"application/json"}, "Origin": {issuerURL},
	}), result)
}

func readJSON(t *testing.T, resp oidcResponse, value any) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf(
			"%s %s gave status %d",
			resp.Request.Method,
			resp.Request.URL.Path,
			resp.StatusCode,
		)
	}
	if err := json.Unmarshal(resp.body, value); err != nil {
		t.Fatal("invalid fixture response JSON")
	}
}

func captureResponse(t *testing.T, resp *http.Response) oidcResponse {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("read fixture response")
	}
	return oidcResponse{Response: resp, body: body}
}
