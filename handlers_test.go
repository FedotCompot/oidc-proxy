package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		cfg: Config{
			ClientID:     "test-client",
			CookiePrefix: "_oidc_proxy",
			SignInTitle:  "Sign in",
			SignInButton: "Sign in with SSO",
			Scopes:       []string{"openid", "profile", "email"},
		},
		verifyFn: func(_ context.Context, tok string) (*VerifiedToken, error) {
			if tok == "valid" {
				return &VerifiedToken{Subject: "stub-sub", Nonce: "stub-nonce"}, nil
			}
			return nil, errors.New("invalid id_token")
		},
	}
}

// addTokenCookies puts plain token cookies on req with the same names the
// production code uses.
func addTokenCookies(req *http.Request, s *Server, t Tokens) {
	if t.IDToken != "" {
		req.AddCookie(&http.Cookie{Name: s.cookieName(cookieSuffixIDToken), Value: t.IDToken})
	}
	if t.AccessToken != "" {
		req.AddCookie(&http.Cookie{Name: s.cookieName(cookieSuffixAccessToken), Value: t.AccessToken})
	}
	if t.RefreshToken != "" {
		req.AddCookie(&http.Cookie{Name: s.cookieName(cookieSuffixRefreshToken), Value: t.RefreshToken})
	}
}

func TestVerifyRedirectsWhenNoToken(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Uri", "/secret?x=1")
	w := httptest.NewRecorder()

	s.handleVerify(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example.com/oauth2/sign_in?rd=") {
		t.Fatalf("Location = %q", loc)
	}
	if !strings.Contains(loc, "%2Fsecret%3Fx%3D1") {
		t.Fatalf("Location does not preserve original URI: %q", loc)
	}
}

func TestVerifyAllowsValidToken(t *testing.T) {
	s := newTestServer(t)
	// verifyFn returns Subject="stub-sub" for the "valid" token; the email
	// claim isn't populated, so X-Auth-Request-Email is expected empty here.
	s.verifyFn = func(_ context.Context, tok string) (*VerifiedToken, error) {
		if tok == "valid" {
			return &VerifiedToken{Subject: "alice-sub", Email: "alice@example.com"}, nil
		}
		return nil, errors.New("invalid id_token")
	}

	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()

	s.handleVerify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Auth-Request-Email"); got != "alice@example.com" {
		t.Fatalf("X-Auth-Request-Email = %q", got)
	}
	if got := w.Header().Get("X-Auth-Request-User"); got != "alice-sub" {
		t.Fatalf("X-Auth-Request-User = %q", got)
	}
}

func TestVerifyRedirectsToRefreshOnInvalidIDToken(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Uri", "/some/page")
	addTokenCookies(req, s, Tokens{IDToken: "expired", RefreshToken: "rt"})
	w := httptest.NewRecorder()

	s.handleVerify(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "https://app.example.com/oauth2/refresh?rd=") {
		t.Fatalf("Location = %q, want refresh redirect", loc)
	}
}

func TestVerifyRedirectsToSignInWhenNoRefreshToken(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	addTokenCookies(req, s, Tokens{IDToken: "expired"})
	w := httptest.NewRecorder()

	s.handleVerify(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "https://app.example.com/oauth2/sign_in") {
		t.Fatalf("Location = %q, want sign_in redirect", loc)
	}
}

func TestVerifyDeniesDisallowedEmail(t *testing.T) {
	s := newTestServer(t)
	s.cfg.AllowedDomains = map[string]bool{"example.com": true}
	s.verifyFn = func(_ context.Context, tok string) (*VerifiedToken, error) {
		return &VerifiedToken{Subject: "x", Email: "mallory@evil.test"}, nil
	}
	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()

	s.handleVerify(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestSessionEndpointRejectsBadOrigin(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"id_token": "valid"})
	req := httptest.NewRequest(http.MethodPost, "http://oidc-proxy:8080/oauth2/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://attacker.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	w := httptest.NewRecorder()

	s.handleSession(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestSessionEndpointWritesPlainCookies(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]any{
		"id_token":      "valid",
		"access_token":  "at-value",
		"refresh_token": "rt-value",
		"nonce":         "stub-nonce",
	})
	req := httptest.NewRequest(http.MethodPost, "http://oidc-proxy:8080/oauth2/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	w := httptest.NewRecorder()

	s.handleSession(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body=%s)", w.Code, w.Body.String())
	}

	cookies := w.Result().Cookies()
	want := map[string]string{
		"_oidc_proxy_id_token":      "valid",
		"_oidc_proxy_access_token":  "at-value",
		"_oidc_proxy_refresh_token": "rt-value",
	}
	got := map[string]string{}
	for _, c := range cookies {
		got[c.Name] = c.Value
		if c.HttpOnly {
			t.Errorf("cookie %s set HttpOnly; expected JS-readable", c.Name)
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("cookie %s = %q, want %q", k, got[k], v)
		}
	}
}

func TestSessionEndpointPreservesRefreshTokenWhenOmitted(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"id_token": "valid"})
	req := httptest.NewRequest(http.MethodPost, "http://oidc-proxy:8080/oauth2/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.AddCookie(&http.Cookie{Name: s.cookieName(cookieSuffixRefreshToken), Value: "carried-rt"})
	w := httptest.NewRecorder()

	s.handleSession(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	var rtCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cookieName(cookieSuffixRefreshToken) {
			rtCookie = c
		}
	}
	if rtCookie == nil || rtCookie.Value != "carried-rt" {
		t.Fatalf("refresh_token cookie not carried forward: %+v", rtCookie)
	}
}

func TestSessionEndpointRejectsInvalidIDToken(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"id_token": "expired"})
	req := httptest.NewRequest(http.MethodPost, "http://oidc-proxy:8080/oauth2/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	w := httptest.NewRecorder()

	s.handleSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestSessionEndpointRejectsNonceMismatch(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"id_token": "valid", "nonce": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "http://oidc-proxy:8080/oauth2/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	w := httptest.NewRecorder()

	s.handleSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestSignOutClearsAllTokenCookies(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/oauth2/sign_out", nil)
	w := httptest.NewRecorder()

	s.handleSignOut(w, req)

	want := map[string]bool{
		"_oidc_proxy_id_token":      false,
		"_oidc_proxy_access_token":  false,
		"_oidc_proxy_refresh_token": false,
	}
	for _, c := range w.Result().Cookies() {
		if _, ok := want[c.Name]; ok {
			if c.MaxAge != -1 {
				t.Errorf("cookie %s MaxAge = %d, want -1 (delete)", c.Name, c.MaxAge)
			}
			want[c.Name] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("cookie %s not cleared", k)
		}
	}
}

func TestSanitizeRedirect(t *testing.T) {
	cases := map[string]string{
		"/foo":                "/foo",
		"/":                   "/",
		"":                    "",
		"//evil.com/x":        "",
		"https://evil.com/x":  "",
		"javascript:alert(1)": "",
		"/foo?x=1&y=2":        "/foo?x=1&y=2",
	}
	for in, want := range cases {
		if got := sanitizeRedirect(in); got != want {
			t.Errorf("sanitizeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignInRendersHTML(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/oauth2/sign_in?rd=/dashboard", nil)
	w := httptest.NewRecorder()

	s.handleSignIn(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `href="/oauth2/start?rd=%2Fdashboard"`) {
		t.Fatalf("body missing start link with rd: %s", body)
	}
}

func TestStartRendersJSPage(t *testing.T) {
	s := newTestServer(t)
	s.endpoints.AuthURL = "https://issuer.example.com/authorize"
	s.endpoints.TokenURL = "https://issuer.example.com/token"
	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/oauth2/start?rd=/page", nil)
	w := httptest.NewRecorder()

	s.handleStart(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"test-client",                           // client_id injected
		"https://issuer.example.com/authorize",  // authorize endpoint injected
		"sessionStorage.setItem('oidc.verifier", // PKCE bits present
		"code_challenge_method",                 // PKCE param wired
		"/page",                                 // redirect injected
	} {
		if !strings.Contains(body, want) {
			t.Errorf("start page missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestRefreshPageReadsCookieDirectly(t *testing.T) {
	s := newTestServer(t)
	s.endpoints.TokenURL = "https://issuer.example.com/token"
	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/oauth2/refresh?rd=/page", nil)
	w := httptest.NewRecorder()

	s.handleRefresh(w, req)

	body := w.Body.String()
	for _, want := range []string{
		"readCookie(cookiePrefix + '_refresh_token')", // direct cookie read
		`"_oidc_proxy"`, // cookie prefix interpolated
	} {
		if !strings.Contains(body, want) {
			t.Errorf("refresh page missing %q\nbody:\n%s", want, body)
		}
	}
	// Make sure we no longer call the removed /oauth2/refresh_token endpoint.
	if strings.Contains(body, "/oauth2/refresh_token") {
		t.Errorf("refresh page still references the removed /oauth2/refresh_token endpoint")
	}
}

