package web

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/fedot/oidc-proxy/internal/utils"
)

// handleVerify is the Traefik ForwardAuth target.
//
// 200 → id_token cookie verifies (signature + iss/aud/exp)
// 302 → no/expired token; redirected to sign_in or refresh
// 403 → authenticated but email not in the allowlist
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	tokens := s.readTokens(r)
	if tokens.IDToken == "" {
		s.redirectToSignIn(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	idTok, err := s.verifyFn(ctx, tokens.IDToken)
	if err != nil {
		if tokens.RefreshToken != "" {
			s.redirectToRefresh(w, r)
			return
		}
		s.clearTokens(w)
		s.redirectToSignIn(w, r)
		return
	}

	if !s.userAllowed(idTok.Email) {
		s.clearTokens(w)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if idTok.Email != "" {
		w.Header().Set("X-Auth-Request-Email", idTok.Email)
	}
	if idTok.Subject != "" {
		w.Header().Set("X-Auth-Request-User", idTok.Subject)
	}
	w.WriteHeader(http.StatusOK)
}

// handleSignIn is the minimal HTML login screen. Single button → /oauth2/start.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	rd := utils.SanitizeRedirect(r.URL.Query().Get("rd"))
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

// handleStart serves an HTML+JS page that generates PKCE verifier+state+nonce
// in the browser, stashes them in sessionStorage, then redirects to the
// provider's authorize endpoint.
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	rd := utils.SanitizeRedirect(r.URL.Query().Get("rd"))
	if rd == "" {
		rd = "/"
	}
	s.renderHTML(w, startTemplate, flowData{
		ClientID:          s.cfg.ClientID,
		Scopes:            s.cfg.Scopes,
		AuthorizeEndpoint: s.provider.Endpoint().AuthURL,
		TokenEndpoint:     s.provider.Endpoint().TokenURL,
		CookiePrefix:      s.cfg.CookiePrefix,
		Redirect:          rd,
	})
}

// handleCallback serves an HTML+JS page that finishes the OIDC flow in the
// browser: reads the code from the URL, calls the provider's token endpoint
// via fetch() (the browser sets `Origin`, satisfying Entra's SPA check), and
// POSTs the tokens to /oauth2/session for verification + cookie write.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	s.renderHTML(w, callbackTemplate, flowData{
		ClientID:          s.cfg.ClientID,
		Scopes:            s.cfg.Scopes,
		AuthorizeEndpoint: s.provider.Endpoint().AuthURL,
		TokenEndpoint:     s.provider.Endpoint().TokenURL,
		CookiePrefix:      s.cfg.CookiePrefix,
	})
}

// handleRefresh serves an HTML+JS page that reads the refresh_token cookie
// directly (no backend roundtrip needed — cookies are JS-readable), calls
// the provider's token endpoint in the browser, then POSTs the new tokens
// back to /oauth2/session.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	rd := utils.SanitizeRedirect(r.URL.Query().Get("rd"))
	if rd == "" {
		rd = "/"
	}
	s.renderHTML(w, refreshTemplate, flowData{
		ClientID:          s.cfg.ClientID,
		Scopes:            s.cfg.Scopes,
		AuthorizeEndpoint: s.provider.Endpoint().AuthURL,
		TokenEndpoint:     s.provider.Endpoint().TokenURL,
		CookiePrefix:      s.cfg.CookiePrefix,
		Redirect:          rd,
	})
}

// handleSession verifies the ID token the browser obtained from the
// provider and writes the tokens as individual JS-readable cookies. This is
// the only endpoint where the backend touches tokens; it never calls the
// provider's token endpoint, only fetches JWKS (cached by go-oidc) to
// verify signatures. Same-origin guard blocks session-fixation attacks.
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
		log.Print("id_token verify failed")
		http.Error(w, "id_token invalid", http.StatusUnauthorized)
		return
	}
	if body.Nonce != "" && idTok.Nonce != body.Nonce {
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}

	if !s.userAllowed(idTok.Email) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Some IdPs only return refresh_token on the initial exchange; carry the
	// existing one forward if the new response omits it.
	if body.RefreshToken == "" {
		body.RefreshToken = cookieValue(r, s.cookieName(cookieSuffixRefreshToken))
	}

	s.writeTokens(w, Tokens{
		IDToken:      body.IDToken,
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleSignOut clears the token cookies. Cross-site requests are rejected so
// a third party can't log the user out with `<img src=…/sign_out>`. We accept
// same-origin/same-site/none (typed URL), and POST from anywhere — POST has
// no <img>-style gadget.
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.clearTokens(w)
	rd := utils.SanitizeRedirect(r.URL.Query().Get("rd"))
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
	if o := utils.OriginOf(s.provider.Endpoint().TokenURL); o != "" {
		connect += " " + o
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src "+connect)
	if err := t.Execute(w, data); err != nil {
		log.Printf("template render: %v", err)
	}
}

// sameOrigin guards /oauth2/session against session-fixation: only accept
// POSTs whose Origin matches the forwarded host.
func (s *Server) sameOrigin(r *http.Request) bool {
	got := r.Header.Get("Origin")
	if got == "" {
		return false
	}
	return got == s.expectedOrigin(r)
}

func (s *Server) expectedOrigin(r *http.Request) string {
	return utils.ForwardedProto(r) + "://" + utils.ForwardedHost(r)
}

func (s *Server) redirectToSignIn(w http.ResponseWriter, r *http.Request) {
	s.redirectToSignInWith(w, r, utils.OriginalURL(r))
}

func (s *Server) redirectToSignInWith(w http.ResponseWriter, r *http.Request, rd string) {
	u := s.expectedOrigin(r) + "/oauth2/sign_in"
	if rd != "" {
		u += "?rd=" + url.QueryEscape(rd)
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) redirectToRefresh(w http.ResponseWriter, r *http.Request) {
	u := s.expectedOrigin(r) + "/oauth2/refresh?rd=" + url.QueryEscape(utils.OriginalURL(r))
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) userAllowed(email string) bool {
	if len(s.cfg.AllowedEmails) == 0 && len(s.cfg.AllowedDomains) == 0 {
		return true
	}
	email = strings.ToLower(email)
	if slices.Contains(s.cfg.AllowedEmails, email) {
		return true
	}
	if at := strings.LastIndexByte(email, '@'); at >= 0 {
		if slices.Contains(s.cfg.AllowedDomains, email[at+1:]) {
			return true
		}
	}
	return false
}
