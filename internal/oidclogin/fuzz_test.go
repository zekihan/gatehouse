package oidclogin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func FuzzSessionCookie(f *testing.F) {
	f.Add("ada", "ada@example.test", "users", sessionCookie, "synthetic")
	f.Add("\x80", "ada@example.test", "users", sessionCookie, "synthetic")
	f.Add("", "", "", flowCookie, "")
	f.Fuzz(func(t *testing.T, user, email, group, purpose, raw string) {
		defer rejectPanic(t)
		class := syntheticClass()
		checkSessionRoundTrip(t, class, user, email, group)
		checkRawCookie(t, class, purpose, raw)
	})
}

var syntheticClass = sync.OnceValue(func() *Class {
	return &Class{
		name:   "user",
		domain: "auth.example.test",
		keys: cookieKeys{
			current:  mustAEAD(bytes.Repeat([]byte{0x42}, 32)),
			previous: mustAEAD(bytes.Repeat([]byte{0x24}, 32)),
		},
		provider: &provider{issuer: "https://issuer.example.test"},
		oauth: oauth2.Config{
			ClientID:    "synthetic-client",
			RedirectURL: "https://auth.example.test/callback",
		},
	}
})

func mustAEAD(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		panic(err)
	}
	return aead
}

func checkSessionRoundTrip(t *testing.T, class *Class, user, email, group string) {
	t.Helper()
	issued := time.Unix(1_700_000_000, 0).UTC()
	sealedSession := session{User: user, Email: email, Groups: []string{group}, IssuedAt: issued}
	recorder := httptest.NewRecorder()
	if !class.sealCookie(recorder, sessionCookie, sealedSession, time.Hour) {
		plain, err := json.Marshal(sealedSession) //nolint:musttag // untagged cookie schema
		overhead := class.keys.current.Overhead()
		if err == nil && base64.RawURLEncoding.EncodedLen(len(plain)+overhead) <= maxCookieValue {
			t.Fatal("session within the cookie limit did not seal")
		}
		return
	}
	response := recorder.Result()
	defer func() { _ = response.Body.Close() }()
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatal("sealed session did not set one cookie")
	}
	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://auth.example.test/app",
		nil,
	)
	request.AddCookie(cookies[0])
	var got session
	if !class.openCookie(request, sessionCookie, &got) {
		t.Fatal("sealed session did not open")
	}
	want, ok := jsonSession(sealedSession)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatal("session round trip mismatch")
	}
	rotated := *class
	rotated.keys.current = mustAEAD(bytes.Repeat([]byte{0x7e}, 32))
	rotated.keys.previous = class.keys.current
	var previous session
	if !rotated.openCookie(request, sessionCookie, &previous) || !reflect.DeepEqual(previous, got) {
		t.Fatal("previous synthetic key did not open the sealed session")
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(cookies[0].Value)
	if err != nil || len(sealed) == 0 {
		t.Fatal("sealed cookie was not raw base64")
	}
	sealed[0] ^= 1
	bad := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://auth.example.test/app",
		nil,
	)
	bad.AddCookie(&http.Cookie{
		Name:     cookies[0].Name,
		Value:    base64.RawURLEncoding.EncodeToString(sealed),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	var ignored session
	if class.openCookie(bad, sessionCookie, &ignored) {
		t.Fatal("tampered cookie opened")
	}
}

func jsonSession(value session) (session, bool) {
	plain, err := json.Marshal(value) //nolint:musttag // untagged cookie schema
	if err != nil {
		return session{}, false
	}
	var out session
	if json.Unmarshal(plain, &out) != nil { //nolint:musttag // untagged cookie schema
		return session{}, false
	}
	return out, true
}

func checkRawCookie(t *testing.T, class *Class, purpose, raw string) {
	t.Helper()
	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://auth.example.test/app",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name:     class.cookieName(purpose),
		Value:    raw,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	var ignored session
	_ = class.openCookie(request, purpose, &ignored)
}

func rejectPanic(t *testing.T) {
	t.Helper()
	if recovered := recover(); recovered != nil {
		t.Fatalf("panic: %v\n%s", recovered, debug.Stack())
	}
}
