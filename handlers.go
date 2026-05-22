package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// handleVerify is the Traefik ForwardAuth target.
//
// 200 → cookie carries a valid ID token (signature + iss/aud/exp check pass)
// 302 → no/expired cookie; redirected to sign_in or refresh
// 403 → authenticated but email not in the allowlist
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	sess, err := s.readSession(r)
	if err != nil {
		s.redirectToSignIn(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, err := s.verifyFn(ctx, sess.IDToken); err != nil {
		if sess.RefreshToken != "" {
			s.redirectToRefresh(w, r)
			return
		}
		s.clearSession(w)
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

// handleSignIn is the minimal HTML login screen. Single button → /oauth2/start.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeRedirect(r.URL.Query().Get("rd"))
	startURL := "/oauth2/start"
	if rd != "" {
		startURL += "?rd=" + url.QueryEscape(rd)
	}
	s.renderHTML(w, signInTemplate, signInData{
		Title:    s.cfg.SignInTitle,
		Button:   s.cfg.SignInButton,
		StartURL: startURL,
	})
}

// handleStart serves a tiny HTML+JS page that generates a PKCE verifier,
// state, and nonce in the browser, stashes them in sessionStorage, then
// redirects to the provider's authorize endpoint. Nothing is exchanged here.
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeRedirect(r.URL.Query().Get("rd"))
	if rd == "" {
		rd = "/"
	}
	s.renderHTML(w, startTemplate, flowData{
		ClientID:          s.cfg.ClientID,
		Scopes:            strings.Join(s.cfg.Scopes, " "),
		AuthorizeEndpoint: s.endpoints.AuthURL,
		TokenEndpoint:     s.endpoints.TokenURL,
		Redirect:          rd,
	})
}

// handleCallback serves a tiny HTML+JS page that finishes the OIDC flow in
// the browser: it reads the code from the URL, calls the token endpoint via
// fetch() (so the browser sets the `Origin` header — required by Entra SPA),
// and POSTs the tokens to /oauth2/session for verification + cookie sealing.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	s.renderHTML(w, callbackTemplate, flowData{
		ClientID:          s.cfg.ClientID,
		Scopes:            strings.Join(s.cfg.Scopes, " "),
		AuthorizeEndpoint: s.endpoints.AuthURL,
		TokenEndpoint:     s.endpoints.TokenURL,
	})
}

// handleRefresh serves a tiny HTML+JS page that fetches the refresh token
// from the backend, calls the token endpoint in the browser, and POSTs the
// new tokens back to /oauth2/session.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeRedirect(r.URL.Query().Get("rd"))
	if rd == "" {
		rd = "/"
	}
	s.renderHTML(w, refreshTemplate, flowData{
		ClientID:          s.cfg.ClientID,
		Scopes:            strings.Join(s.cfg.Scopes, " "),
		AuthorizeEndpoint: s.endpoints.AuthURL,
		TokenEndpoint:     s.endpoints.TokenURL,
		Redirect:          rd,
	})
}

// handleSession receives the tokens the browser obtained from the provider,
// verifies the ID token, and seals an encrypted HttpOnly cookie. This is the
// only place the backend touches the tokens, and it never makes outbound
// calls to the provider's token endpoint — only inbound JWKS lookups (cached
// by go-oidc) during ID token verification.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.sameOrigin(r) {
		http.Error(w, "bad origin", http.StatusForbidden)
		return
	}

	var body struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Nonce        string `json:"nonce"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.IDToken == "" {
		http.Error(w, "missing id_token", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	idTok, err := s.verifyFn(ctx, body.IDToken)
	if err != nil {
		log.Printf("id_token verify failed: %v", err)
		http.Error(w, "id_token invalid", http.StatusUnauthorized)
		return
	}
	if body.Nonce != "" && idTok.Nonce != body.Nonce {
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	_ = idTok.Claims(&claims)

	if !s.userAllowed(claims.Email) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Preserve a refresh token from a prior session if the new response omits
	// one (some IdPs only return refresh_token on the initial exchange).
	if body.RefreshToken == "" {
		if prev, err := s.readSession(r); err == nil {
			body.RefreshToken = prev.RefreshToken
		}
	}

	expiry := time.Time{}
	if body.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	}

	sess := &Session{
		AccessToken:  body.AccessToken,
		IDToken:      body.IDToken,
		RefreshToken: body.RefreshToken,
		Expiry:       expiry,
		Email:        claims.Email,
		Subject:      idTok.Subject,
	}
	if err := s.writeSession(w, sess); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRefreshToken hands the refresh token back to the browser so the
// /oauth2/refresh page can call the provider's token endpoint itself.
// Same-origin only; the response is JSON and CORS blocks cross-origin reads.
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "bad origin", http.StatusForbidden)
		return
	}
	sess, err := s.readSession(r)
	if err != nil || sess.RefreshToken == "" {
		http.Error(w, "no refresh token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"refresh_token": sess.RefreshToken,
		"client_id":     s.cfg.ClientID,
	})
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	rd := sanitizeRedirect(r.URL.Query().Get("rd"))
	if rd == "" {
		rd = "/"
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

func (s *Server) renderHTML(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	connect := "'self'"
	if o := originOf(s.endpoints.TokenURL); o != "" {
		connect += " " + o
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src "+connect)
	if err := t.Execute(w, data); err != nil {
		log.Printf("template render: %v", err)
	}
}

// sameOrigin guards same-origin-only endpoints (POST /oauth2/session and GET
// /oauth2/refresh_token). It rejects requests whose Origin header doesn't
// match the forwarded host.
func (s *Server) sameOrigin(r *http.Request) bool {
	got := r.Header.Get("Origin")
	if got == "" {
		// Some browsers omit Origin on same-origin GET; accept Referer fallback
		// only when no Origin is set at all (POST always has Origin set).
		if r.Method == http.MethodGet {
			if ref := r.Header.Get("Referer"); ref != "" {
				return originOf(ref) == s.expectedOrigin(r)
			}
			return true
		}
		return false
	}
	return got == s.expectedOrigin(r)
}

func (s *Server) expectedOrigin(r *http.Request) string {
	return forwardedProto(r) + "://" + forwardedHost(r)
}

func (s *Server) redirectToSignIn(w http.ResponseWriter, r *http.Request) {
	s.redirectToSignInWith(w, r, originalURL(r))
}

func (s *Server) redirectToSignInWith(w http.ResponseWriter, r *http.Request, rd string) {
	u := s.expectedOrigin(r) + "/oauth2/sign_in"
	if rd != "" {
		u += "?rd=" + url.QueryEscape(rd)
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) redirectToRefresh(w http.ResponseWriter, r *http.Request) {
	u := s.expectedOrigin(r) + "/oauth2/refresh?rd=" + url.QueryEscape(originalURL(r))
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

// originalURL reconstructs the URL the user was originally trying to reach
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

// sanitizeRedirect blocks open-redirects: only same-origin paths are allowed.
func sanitizeRedirect(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	return ""
}

func firstField(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

