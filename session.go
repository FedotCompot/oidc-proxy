package main

import (
	"net/http"
	"time"
)

const (
	cookieSuffixIDToken      = "_id_token"
	cookieSuffixAccessToken  = "_access_token"
	cookieSuffixRefreshToken = "_refresh_token"
)

// Tokens is the set of OAuth/OIDC tokens we mirror into individual cookies.
// The cookies are plaintext and JS-readable — the static site's JS already
// touches them during the SPA flow, so HttpOnly would protect nothing.
type Tokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
}

func (s *Server) cookieName(suffix string) string { return s.cfg.CookiePrefix + suffix }

func (s *Server) readTokens(r *http.Request) Tokens {
	return Tokens{
		IDToken:      cookieValue(r, s.cookieName(cookieSuffixIDToken)),
		AccessToken:  cookieValue(r, s.cookieName(cookieSuffixAccessToken)),
		RefreshToken: cookieValue(r, s.cookieName(cookieSuffixRefreshToken)),
	}
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *Server) writeTokens(w http.ResponseWriter, t Tokens) {
	exp := time.Now().Add(30 * 24 * time.Hour)
	if t.IDToken != "" {
		http.SetCookie(w, s.makeCookie(s.cookieName(cookieSuffixIDToken), t.IDToken, exp))
	}
	if t.AccessToken != "" {
		http.SetCookie(w, s.makeCookie(s.cookieName(cookieSuffixAccessToken), t.AccessToken, exp))
	}
	if t.RefreshToken != "" {
		http.SetCookie(w, s.makeCookie(s.cookieName(cookieSuffixRefreshToken), t.RefreshToken, exp))
	}
}

func (s *Server) clearTokens(w http.ResponseWriter) {
	for _, suffix := range []string{cookieSuffixIDToken, cookieSuffixAccessToken, cookieSuffixRefreshToken} {
		http.SetCookie(w, s.makeCookie(s.cookieName(suffix), "", time.Unix(0, 0)))
	}
}

func (s *Server) makeCookie(name, value string, expires time.Time) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		Expires:  expires,
		HttpOnly: false, // JS-readable: the static site needs to read tokens
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	if value == "" {
		c.MaxAge = -1
	}
	return c
}
