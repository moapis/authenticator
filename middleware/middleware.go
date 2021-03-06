// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

// Package middleware provides means of verifying JWTs generated by
// `cmd/admin`'s login handler or similar mechanisms.
// It is compatible with Gorilla mux middleware.
package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/moapis/authenticator"
	"github.com/moapis/authenticator/verify"
	"github.com/pascaldekloe/jwt"
	log "github.com/usrpro/clog15"
)

const (
	// DefaultLoginURL is the default value for Client.LoginURL
	DefaultLoginURL = "/login"
	// DefaultRedirectKey is the default value for Client.RedirectKey
	DefaultRedirectKey = "redirect"
)

// getJwt from url or cookie.
// Token in url take precedence.
func getJwt(r *http.Request) (string, bool, error) {
	if tkn := r.URL.Query().Get("jwt"); tkn != "" {
		return tkn, true, nil
	}

	cookie, err := r.Cookie("jwt")
	if err != nil {
		return "", false, fmt.Errorf("getJwt: %w", err)
	}

	return cookie.Value, false, nil
}

// Client holds a Verificator and AuthenticatorClient
type Client struct {
	Verificator *verify.Verificator

	// Groups of which as least 1 needs to be mentioned in the token.
	// A check is performed on the extra "groups" field which should
	// hold a JSON array of group names this user is member of.
	// If Groups is empty, checking is disabled.
	Groups []string

	// LoginURL is the path to a login handler.
	// Defaults to "/login".
	LoginURL string

	// Whenever the client needs to be redirected for login,
	// the original called URI is embedded as query parameter under RedirectKey.
	// This allows for a login hander (like cmd/admin) to send the client back to
	// the original URI upon succesfull login.
	// Defaults to "redirect".
	RedirectKey string

	// Scheme, hostname and optionaly port number of this host.
	// It is used for redirecting back to this server after login.
	ServerAddress string
	RefreshWithin time.Duration
}

func (c *Client) loginRedirect(ctx context.Context, w http.ResponseWriter, r *http.Request, err error) {
	log.Info(ctx, "loginRedirect", "reason", err)

	lu, rk := c.LoginURL, c.RedirectKey
	if lu == "" {
		lu = DefaultLoginURL
	}
	if rk == "" {
		rk = DefaultRedirectKey
	}

	// Take out any old jwt of url, perserve any other arguments
	url := r.URL
	q := url.Query()
	q.Del("jwt")

	var qs string
	if len(q) > 0 {
		qs = fmt.Sprint("?", q.Encode())
	}

	http.Redirect(w, r,
		// http://serv.com/login?redirect=http://here.com/path?foo=bar
		fmt.Sprintf("%s?%s=%s%s%s", lu, rk, c.ServerAddress, url.Path, qs),
		http.StatusSeeOther,
	)
}

func (c *Client) refreshToken(ctx context.Context, tkn string) (string, error) {
	reply, err := c.Verificator.Client.RefreshToken(ctx, &authenticator.AuthReply{Jwt: tkn})
	if err != nil {
		return "", err
	}
	return reply.GetJwt(), nil
}

// newCookie with the jwt token is added to the writer and current request.
func (c *Client) newCookie(w http.ResponseWriter, r *http.Request, tkn string, expires time.Time) {
	cookie := &http.Cookie{
		Name:    "jwt",
		Value:   tkn,
		Path:    "/",
		Expires: expires,
	}

	http.SetCookie(w, cookie)
}

var verErr = &verify.VerificationErr{}

const intServErr = "Internal server error"

func (c *Client) assertVerErr(ctx context.Context, w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.As(err, &verErr):
		c.loginRedirect(ctx, w, r, err)
		return true
	default:
		log.Error(ctx, intServErr, "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(intServErr))
		return true
	}
}

var errGroup = errors.New("Not member of any required group")

func (c *Client) isGroupMember(set map[string]interface{}) error {
	if len(c.Groups) == 0 {
		return nil
	}

	if is, ok := set["groups"].([]interface{}); ok {
		for _, i := range is {
			s, ok := i.(string)
			if !ok {
				continue
			}

			for _, g := range c.Groups {
				if g == s {
					return nil
				}
			}
		}
	}

	return errGroup
}

// Claims is added to the request context
type Claims struct {
	*jwt.Claims
}

type claimsKeyType struct{}

// ClaimsKey is under which key Claims will be stored in the request Context.
var ClaimsKey claimsKeyType

// Middleware checks for a valid authentication token, named "jwt", in url or cookie.
// A token in the URL is copied to a newly set cookie in the response headers.
// The claims from the token added to the request context under "ClaimsKey" and type "Claims"
//
// If the token is missing, invalid, expired
// or user is not member of the correct group and audience,
// the client is redirected for login.
// In case of a call error to the AuthenticatorClient,
// internal server error will be transmitted to the client.
// In both cases "next.ServeHttp()" is not called, halting the middleware call chain.
//
// When the token is close to expire, "AuthenticatorClient.RefreshToken()" is called.
// The resulting new token is set in a new cookie.
// An error from RefreshToken is only logged, "next.ServeHttp()" will be called regardless.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := log.AddArgs(r.Context(), "module", "authenticator")

		tkn, newCookie, err := getJwt(r)
		if err != nil {
			c.loginRedirect(ctx, w, r, err)
			return
		}

		claims, err := c.Verificator.Token(ctx, tkn)
		if c.assertVerErr(ctx, w, r, err) {
			return
		}
		log.Debug(ctx, "token verified", "claims", claims)

		if claims.Expires.Time().Before(
			time.Now().Add(c.RefreshWithin),
		) {
			if t, err := c.refreshToken(ctx, tkn); err == nil {
				tkn, newCookie = t, true

				claims, err = c.Verificator.Token(ctx, tkn)
				if c.assertVerErr(ctx, w, r, err) {
					return
				}
				log.Info(ctx, "token refreshed", "claims", claims)

			} else {
				log.Error(ctx, "refreshToken", "err", err)
			}
		}

		if err = c.isGroupMember(claims.Set); err != nil {
			c.loginRedirect(ctx, w, r, err)
			return
		}

		if newCookie {
			c.newCookie(w, r, tkn, claims.Expires.Time())
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ClaimsKey, Claims{claims})))
	})
}
