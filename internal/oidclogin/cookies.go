package oidclogin

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	cookiePrefix   = "__Secure-gatehouse-"
	maxCookieValue = 3600
	flowLifetime   = 10 * time.Minute
)

type cookieKeys struct {
	current  cipher.AEAD
	previous cipher.AEAD
}

func decodeKey(value string) cipher.AEAD {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil
	}
	return aead
}

func (c *Class) cookieName(purpose string) string {
	return cookiePrefix + purpose + "-" + c.name
}

func (c *Class) cookie(purpose, value string, lifetime time.Duration) *http.Cookie {
	cookie := &http.Cookie{
		Name: c.cookieName(purpose), Value: value, Domain: c.domain, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(lifetime.Round(time.Second) / time.Second),
	}
	if lifetime <= 0 {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0).UTC()
	}
	return cookie
}

func (c *Class) cookieContext(purpose string) []byte {
	return []byte(c.cookieName(purpose) + "\x00" + c.domain + "\x00" + c.provider.issuer +
		"\x00" + c.oauth.ClientID + "\x00" + c.oauth.RedirectURL)
}

func (c *Class) sealCookie(
	w http.ResponseWriter,
	purpose string,
	value any,
	lifetime time.Duration,
) bool {
	plain, err := json.Marshal(value)
	encoding := base64.RawURLEncoding
	if err != nil || encoding.EncodedLen(len(plain)+c.keys.current.Overhead()) > maxCookieValue {
		return false
	}
	//nolint:gosec // G407: NewGCMWithRandomNonce generates and prepends the nonce.
	sealed := c.keys.current.Seal(nil, nil, plain, c.cookieContext(purpose))
	http.SetCookie(w, c.cookie(purpose, encoding.EncodeToString(sealed), lifetime))
	return true
}

func (c *Class) openCookie(r *http.Request, purpose string, value any) bool {
	cookies := r.CookiesNamed(c.cookieName(purpose))
	if len(cookies) != 1 || len(cookies[0].Value) > maxCookieValue {
		return false
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(cookies[0].Value)
	if err != nil {
		return false
	}
	context := c.cookieContext(purpose)
	plain, err := c.keys.current.Open(nil, nil, sealed, context)
	if err != nil && c.keys.previous != nil {
		plain, err = c.keys.previous.Open(nil, nil, sealed, context)
	}
	return err == nil && json.Unmarshal(plain, value) == nil
}

// StripCookies removes Gatehouse credentials from all backend-bound requests.
func StripCookies(header http.Header) {
	cookies := header.Values("Cookie")
	if len(cookies) == 0 {
		return
	}
	kept := cookies[:0]
	for _, line := range cookies {
		if !strings.Contains(line, cookiePrefix) {
			kept = append(kept, line)
			continue
		}
		var parts []string
		for part := range strings.SplitSeq(line, ";") {
			name, _, _ := strings.Cut(part, "=")
			if !strings.HasPrefix(strings.TrimSpace(name), cookiePrefix) {
				parts = append(parts, part)
			}
		}
		if remaining := strings.TrimSpace(strings.Join(parts, ";")); remaining != "" {
			kept = append(kept, remaining)
		}
	}
	if len(kept) == 0 {
		header.Del("Cookie")
	} else {
		header["Cookie"] = kept
	}
}
