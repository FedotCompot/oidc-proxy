package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return &Server{
		cfg: Config{
			ClientID:     "test-client",
			CookiePrefix: "_oidc_proxy",
			CookieKey:    key,
			SignInTitle:  "Sign in",
			SignInButton: "Sign in with SSO",
		},
	}
}

func TestVerifyRedirectsWhenNoSession(t *testing.T) {
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

func TestVerifyAllowsValidSession(t *testing.T) {
	s := newTestServer(t)
	sess := &Session{
		AccessToken: "at",
		IDToken:     "it",
		Expiry:      time.Now().Add(1 * time.Hour),
		Email:       "alice@example.com",
		Subject:     "alice-sub",
	}
	token, err := s.sealJSON(sess)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.AddCookie(&http.Cookie{Name: s.sessionCookieName(), Value: token})
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

func TestVerifyRefreshesWhenExpired(t *testing.T) {
	s := newTestServer(t)
	sess := &Session{
		AccessToken:  "at",
		RefreshToken: "rt",
		Expiry:       time.Now().Add(-1 * time.Minute),
		Email:        "alice@example.com",
	}
	token, err := s.sealJSON(sess)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Uri", "/some/page")
	req.AddCookie(&http.Cookie{Name: s.sessionCookieName(), Value: token})
	w := httptest.NewRecorder()

	s.handleVerify(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example.com/oauth2/refresh?rd=") {
		t.Fatalf("Location = %q, expected refresh redirect", loc)
	}
}

func TestVerifyDeniesDisallowedEmail(t *testing.T) {
	s := newTestServer(t)
	s.cfg.AllowedDomains = map[string]bool{"example.com": true}
	sess := &Session{
		Expiry: time.Now().Add(1 * time.Hour),
		Email:  "mallory@evil.test",
	}
	token, _ := s.sealJSON(sess)

	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.AddCookie(&http.Cookie{Name: s.sessionCookieName(), Value: token})
	w := httptest.NewRecorder()

	s.handleVerify(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestSanitizeRedirect(t *testing.T) {
	cases := map[string]string{
		"/foo":                  "/foo",
		"/":                     "/",
		"":                      "",
		"//evil.com/x":          "",
		"https://evil.com/x":    "",
		"javascript:alert(1)":   "",
		"/foo?x=1&y=2":          "/foo?x=1&y=2",
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
