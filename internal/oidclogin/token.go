package oidclogin

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var errToken = errors.New("invalid OIDC token")

func (c *Class) exchange(ctx context.Context, code string, flow flow) (session, error) {
	ctx = oidc.ClientContext(ctx, c.provider.client)
	provider, err := c.provider.load(ctx)
	if err != nil {
		return session{}, err
	}
	client := c.oauth
	client.Endpoint = provider.endpoint
	token, err := client.Exchange(ctx, code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		var response *oauth2.RetrieveError
		if errors.As(err, &response) && response.Response != nil &&
			response.Response.StatusCode >= 400 && response.Response.StatusCode < 500 {
			return session{}, errToken
		}
		return session{}, errProvider
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return session{}, errToken
	}
	verified, err := provider.verifier.Verify(ctx, idToken)
	if err != nil || verified.Subject == "" || verified.Issuer != c.provider.issuer ||
		subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(flow.Nonce)) != 1 {
		return session{}, errToken
	}
	return c.identity(verified)
}

func (c *Class) identity(verified *oidc.IDToken) (session, error) {
	var claims struct {
		Username      string   `json:"preferred_username"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Groups        []string `json:"groups"`
		Party         string   `json:"azp"`
	}
	if verified.Claims(&claims) != nil ||
		((len(verified.Audience) != 1 || claims.Party != "") && claims.Party != c.oauth.ClientID) {
		return session{}, errToken
	}
	if claims.Username == "" {
		claims.Username = verified.Subject
	}
	if !claims.EmailVerified {
		claims.Email = ""
	}
	if !validHeaderValue(claims.Username) || !validHeaderValue(claims.Email) ||
		slices.ContainsFunc(claims.Groups, invalidGroup) {
		return session{}, errToken
	}
	return session{User: claims.Username, Email: claims.Email, Groups: claims.Groups}, nil
}

func invalidGroup(group string) bool {
	return !validHeaderValue(group) || strings.Contains(group, ",")
}

func validHeaderValue(value string) bool {
	for _, b := range []byte(value) {
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}
