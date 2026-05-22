package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// handleVerify is the Traefik ForwardAuth target.
//
// 200 → request is authenticated (Traefik allows it through)
// 302 → not authenticated; browser is redirected to /oauth2/sign_in
//
// Traefik sends the original request info via X-Forwarded-* headers; we use
// those to remember where the user was trying to go.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	sess, err := s.readSession(r)
	if err != nil {
		s.redirectToSignIn(w, r)
		return
	}

	if !sess.Expiry.IsZero() && time.Now().After(sess.Expiry) {
		if sess.RefreshToken != "" {
			s.redirectToRefresh(w, r)
			return
		}
		s.redirectToSignIn(w, r)
		return
	}

	if !s.userAllowed(sess.Email) {
		s.clearSession(w)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if sess.Email != "" {
		w.Header().Set("X-Auth-Request-Email", sess.Email)
	}
	if sess.Subject != "" {
		w.Header().Set("X-Auth-Request-User", sess.Subject)
	}
	w.WriteHeader(http.StatusOK)
}

// handleSignIn renders a minimal HTML login screen. The "Sign in" button just
// links to /oauth2/start, which kicks off the OIDC redirect dance.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeRedirect(r.URL.Query().Get("rd"))
	startURL := "/oauth2/start"
	if rd != "" {
		startURL += "?rd=" + url.QueryEscape(rd)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = signInTemplate.Execute(w, signInData{
		Title:    s.cfg.SignInTitle,
		Button:   s.cfg.SignInButton,
		StartURL: template.URL(startURL),
	})
}

// handleStart generates PKCE + state + nonce, stashes them in an encrypted
// flow cookie, and 302s the browser to the issuer's authorize endpoint.
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeRedirect(r.URL.Query().Get("rd"))
	if rd == "" {
		rd = "/"
	}

	verifier := oauth2.GenerateVerifier()
	state, err := randURLSafe(24)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randURLSafe(24)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redirectURI := s.callbackURL(r)
	flow := &flowState{
		State:        state,
		CodeVerifier: verifier,
		Nonce:        nonce,
		Redirect:     rd,
		RedirectURI:  redirectURI,
	}
	if err := s.writeFlow(w, flow); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	cfg := s.oauth2Config(redirectURI)
	authURL := cfg.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.AccessTypeOffline,
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback receives the redirect from the issuer, validates state, swaps
// the code for tokens (PKCE), verifies the ID token, and persists a session.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	flow, err := s.readFlow(r)
	if err != nil {
		http.Error(w, "missing or invalid flow cookie", http.StatusBadRequest)
		return
	}
	s.clearFlow(w)

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("oidc error: %s: %s", errParam, desc), http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != flow.State {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cfg := s.oauth2Config(flow.RedirectURI)
	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(flow.CodeVerifier))
	if err != nil {
		log.Printf("token exchange failed: %v", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	sess, err := s.sessionFromToken(ctx, tok, flow.Nonce)
	if err != nil {
		log.Printf("session build failed: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !s.userAllowed(sess.Email) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := s.writeSession(w, sess); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, flow.Redirect, http.StatusFound)
}

// handleRefresh uses the refresh token in the existing session cookie to mint
// a new access/ID token, rewrites the session cookie, and bounces the user
// back to the original URL. Reached as a direct browser request (not via
// forward-auth), so Set-Cookie works without extra Traefik configuration.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeRedirect(r.URL.Query().Get("rd"))
	if rd == "" {
		rd = "/"
	}

	sess, err := s.readSession(r)
	if err != nil || sess.RefreshToken == "" {
		s.redirectToSignInWith(w, r, rd)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cfg := s.oauth2Config(s.callbackURL(r))
	src := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: sess.RefreshToken})
	tok, err := src.Token()
	if err != nil {
		log.Printf("refresh failed: %v", err)
		s.clearSession(w)
		s.redirectToSignInWith(w, r, rd)
		return
	}

	newSess, err := s.sessionFromToken(ctx, tok, "")
	if err != nil {
		log.Printf("session rebuild failed: %v", err)
		s.clearSession(w)
		s.redirectToSignInWith(w, r, rd)
		return
	}
	// Some IdPs don't return a new refresh token on refresh — keep the old one.
	if newSess.RefreshToken == "" {
		newSess.RefreshToken = sess.RefreshToken
	}

	if !s.userAllowed(newSess.Email) {
		s.clearSession(w)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := s.writeSession(w, newSess); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	rd := sanitizeRedirect(r.URL.Query().Get("rd"))
	if rd == "" {
		rd = "/"
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

// sessionFromToken extracts the ID token, verifies it, and folds the claims
// plus refresh token into a Session.
func (s *Server) sessionFromToken(ctx context.Context, tok *oauth2.Token, expectedNonce string) (*Session, error) {
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, errors.New("id_token missing from token response")
	}
	idTok, err := s.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("id_token verify: %w", err)
	}
	if expectedNonce != "" && idTok.Nonce != expectedNonce {
		return nil, errors.New("nonce mismatch")
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	_ = idTok.Claims(&claims)

	return &Session{
		AccessToken:  tok.AccessToken,
		IDToken:      rawID,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
		Email:        claims.Email,
		Subject:      idTok.Subject,
	}, nil
}

func (s *Server) oauth2Config(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:    s.cfg.ClientID,
		Endpoint:    s.endpoints,
		RedirectURL: redirectURI,
		Scopes:      s.cfg.Scopes,
	}
}

// callbackURL builds the redirect URI from the current request. For
// forward-auth verify calls this comes from X-Forwarded-*; for direct hits
// (the user is at /oauth2/...) it comes from the actual request.
func (s *Server) callbackURL(r *http.Request) string {
	proto, host := forwardedProto(r), forwardedHost(r)
	return proto + "://" + host + "/oauth2/callback"
}

func (s *Server) redirectToSignIn(w http.ResponseWriter, r *http.Request) {
	s.redirectToSignInWith(w, r, originalURL(r))
}

func (s *Server) redirectToSignInWith(w http.ResponseWriter, r *http.Request, rd string) {
	proto, host := forwardedProto(r), forwardedHost(r)
	u := proto + "://" + host + "/oauth2/sign_in"
	if rd != "" {
		u += "?rd=" + url.QueryEscape(rd)
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) redirectToRefresh(w http.ResponseWriter, r *http.Request) {
	proto, host := forwardedProto(r), forwardedHost(r)
	u := proto + "://" + host + "/oauth2/refresh?rd=" + url.QueryEscape(originalURL(r))
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) userAllowed(email string) bool {
	if len(s.cfg.AllowedEmails) == 0 && len(s.cfg.AllowedDomains) == 0 {
		return true
	}
	email = strings.ToLower(email)
	if s.cfg.AllowedEmails[email] {
		return true
	}
	if at := strings.LastIndexByte(email, '@'); at >= 0 {
		if s.cfg.AllowedDomains[email[at+1:]] {
			return true
		}
	}
	return false
}

// forwardedProto / forwardedHost prefer Traefik-set headers, falling back to
// the request itself so direct hits during local testing still work.
func forwardedProto(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return firstField(v)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func forwardedHost(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		return firstField(v)
	}
	return r.Host
}

// originalURL reconstructs the URL the user was originally trying to reach,
// using Traefik's X-Forwarded-* headers (Uri carries path+query).
func originalURL(r *http.Request) string {
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	return forwardedProto(r) + "://" + forwardedHost(r) + uri
}

// sanitizeRedirect blocks open-redirects: only allow same-origin paths or
// fully-qualified URLs whose host matches the forwarded host.
func sanitizeRedirect(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	// Anything else gets dropped; we'll fall back to "/" upstream.
	return ""
}

func firstField(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
