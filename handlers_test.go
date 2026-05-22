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

	"github.com/coreos/go-oidc/v3/oidc"
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
			Scopes:       []string{"openid", "profile", "email"},
		},
		verifyFn: func(_ context.Context, tok string) (*oidc.IDToken, error) {
			if tok == "valid" {
				return &oidc.IDToken{Subject: "stub-sub", Nonce: "stub-nonce"}, nil
			}
			return nil, errors.New("invalid id_token")
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
		IDToken: "valid",
		Email:   "alice@example.com",
		Subject: "alice-sub",
	}
	token, err := s.sealJSON(sess)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.AddCookie(&http.Cookie{Name: s.sessionCookieName() + "_0", Value: token})
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
	sess := &Session{
		IDToken:      "expired",
		RefreshToken: "rt",
	}
	token, _ := s.sealJSON(sess)

	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Uri", "/some/page")
	req.AddCookie(&http.Cookie{Name: s.sessionCookieName() + "_0", Value: token})
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
	sess := &Session{IDToken: "expired"}
	token, _ := s.sealJSON(sess)

	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.AddCookie(&http.Cookie{Name: s.sessionCookieName() + "_0", Value: token})
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
	sess := &Session{
		IDToken: "valid",
		Email:   "mallory@evil.test",
	}
	token, _ := s.sealJSON(sess)

	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	req.AddCookie(&http.Cookie{Name: s.sessionCookieName() + "_0", Value: token})
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

func TestSessionEndpointVerifiesAndSealsCookie(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]any{
		"id_token":      "valid",
		"refresh_token": "rt",
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
	// Round-trip the Set-Cookie chunks back through readSession.
	next := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge == -1 {
			continue // skip cleanup-cookies for higher chunk indices
		}
		next.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	sess, err := s.readSession(next)
	if err != nil {
		t.Fatalf("readSession: %v", err)
	}
	if sess.IDToken != "valid" || sess.RefreshToken != "rt" || sess.Subject != "stub-sub" {
		t.Fatalf("unexpected session contents: %+v", sess)
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

func TestRefreshTokenEndpointReturnsToken(t *testing.T) {
	s := newTestServer(t)
	sess := &Session{RefreshToken: "rt-value", IDToken: "valid"}
	tok, _ := s.sealJSON(sess)

	req := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/oauth2/refresh_token", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.AddCookie(&http.Cookie{Name: s.sessionCookieName() + "_0", Value: tok})
	w := httptest.NewRecorder()

	s.handleRefreshToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["refresh_token"] != "rt-value" {
		t.Fatalf("refresh_token = %q", body["refresh_token"])
	}
	if body["client_id"] != "test-client" {
		t.Fatalf("client_id = %q", body["client_id"])
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

func TestSessionCookieChunksAndRoundTrips(t *testing.T) {
	s := newTestServer(t)
	// ~6KB ID token + ~1.5KB refresh token: forces multi-cookie split.
	sess := &Session{
		IDToken:      strings.Repeat("X", 6000),
		RefreshToken: strings.Repeat("Y", 1500),
		Email:        "alice@example.com",
		Subject:      "alice-sub",
	}

	w := httptest.NewRecorder()
	if err := s.writeSession(w, sess); err != nil {
		t.Fatalf("writeSession: %v", err)
	}

	var chunks int
	next := httptest.NewRequest(http.MethodGet, "http://oidc-proxy:8080/verify", nil)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge == -1 {
			continue
		}
		if len(c.Value) > 4000 {
			t.Errorf("chunk %q is %d bytes — exceeds per-cookie limit", c.Name, len(c.Value))
		}
		chunks++
		next.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	if chunks < 2 {
		t.Fatalf("expected >=2 chunks for an oversized payload, got %d", chunks)
	}

	got, err := s.readSession(next)
	if err != nil {
		t.Fatalf("readSession: %v", err)
	}
	if got.IDToken != sess.IDToken || got.RefreshToken != sess.RefreshToken ||
		got.Email != sess.Email || got.Subject != sess.Subject {
		t.Fatalf("round-trip mismatch")
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
		"test-client",                            // client_id injected
		"https://issuer.example.com/authorize",   // authorize endpoint injected
		"sessionStorage.setItem('oidc.verifier",  // PKCE bits present
		"code_challenge_method",                  // PKCE param wired
		"/page",                                  // redirect injected
	} {
		if !strings.Contains(body, want) {
			t.Errorf("start page missing %q\nbody:\n%s", want, body)
		}
	}
}
