package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/fedot/oidc-proxy/internal/mcpauth"
	"github.com/fedot/oidc-proxy/internal/token"
)

const (
	mcpHost     = "docs.hierarchy40.com"
	mcpIssuer   = "https://docs.hierarchy40.com"
	mcpResource = "https://docs.hierarchy40.com/mcp"
	clientCB    = "https://client.example.com/callback"
)

func testKeyPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// newMCPServer builds a Server with MCP enabled and a stub Entra verifier:
// cookie "valid" → user-1, "valid2" → user-2, anything else invalid.
func newMCPServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t)
	s.cfg.MCPEnabled = true
	s.verifyFn = func(_ context.Context, tok string) (*token.Verified, error) {
		switch tok {
		case "valid":
			return &token.Verified{Subject: "user-1", Email: "user@example.com"}, nil
		case "valid2":
			return &token.Verified{Subject: "user-2", Email: "user2@example.com"}, nil
		}
		return nil, errors.New("invalid id_token")
	}
	as, err := mcpauth.New(mcpauth.Options{
		Issuer:          mcpIssuer,
		Resource:        mcpResource,
		ScopesSupported: []string{"mcp"},
		SigningKeyPEM:   testKeyPEM(t),
	})
	if err != nil {
		t.Fatalf("mcpauth.New: %v", err)
	}
	s.as = as
	return s
}

func mcpReq(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, "https://"+mcpHost+target, body)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", mcpHost)
	return req
}

func pkcePair() (verifier, challenge string) {
	verifier = "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeQuery(clientID, redirectURI, challenge, resource, state, scope string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", resource)
	if scope != "" {
		q.Set("scope", scope)
	}
	if state != "" {
		q.Set("state", state)
	}
	return "/oauth2/authorize?" + q.Encode()
}

var (
	reAuthReq = regexp.MustCompile(`name="authreq" value="([^"]+)"`)
	reCSRF    = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
)

func extractConsent(t *testing.T, body string) (authreq, csrf string) {
	t.Helper()
	a := reAuthReq.FindStringSubmatch(body)
	c := reCSRF.FindStringSubmatch(body)
	if a == nil || c == nil {
		t.Fatalf("consent page missing authreq/csrf hidden fields:\n%s", body)
	}
	return a[1], c[1]
}

// mintClient registers a client via the AS and returns its client_id.
func mintClient(t *testing.T, s *Server, redirectURIs ...string) string {
	t.Helper()
	if len(redirectURIs) == 0 {
		redirectURIs = []string{clientCB}
	}
	cid, err := s.as.MintClientID(mcpauth.ClientRegistration{RedirectURIs: redirectURIs, ClientName: "Test App"})
	if err != nil {
		t.Fatalf("MintClientID: %v", err)
	}
	return cid
}

// ---- metadata ---------------------------------------------------------------

func TestMCPMetadataEndpoints(t *testing.T) {
	s := newMCPServer(t)

	t.Run("as-metadata", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, mcpReq(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		if w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("json: %v", err)
		}
		if m["issuer"] != mcpIssuer {
			t.Errorf("issuer = %v", m["issuer"])
		}
		if m["authorization_endpoint"] != mcpIssuer+"/oauth2/authorize" {
			t.Errorf("authorization_endpoint = %v", m["authorization_endpoint"])
		}
		if m["registration_endpoint"] != mcpIssuer+"/oauth2/register" {
			t.Errorf("registration_endpoint = %v", m["registration_endpoint"])
		}
		if scopes, _ := m["scopes_supported"].([]any); len(scopes) != 1 || scopes[0] != "mcp" {
			t.Errorf("scopes_supported = %v", m["scopes_supported"])
		}
		if _, ok := m["subject_types_supported"]; ok {
			t.Error("AS metadata should not carry OIDC-only subject_types_supported")
		}
	})

	t.Run("openid-configuration", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, mcpReq(http.MethodGet, "/.well-known/openid-configuration", nil))
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if sts, _ := m["subject_types_supported"].([]any); len(sts) != 1 || sts[0] != "public" {
			t.Errorf("subject_types_supported = %v", m["subject_types_supported"])
		}
		if algs, _ := m["id_token_signing_alg_values_supported"].([]any); len(algs) != 1 || algs[0] != "ES256" {
			t.Errorf("id_token_signing_alg_values_supported = %v", m["id_token_signing_alg_values_supported"])
		}
	})

	t.Run("prm-canonical-and-bare", func(t *testing.T) {
		for _, path := range []string{
			"/.well-known/oauth-protected-resource",
			"/.well-known/oauth-protected-resource/mcp",
		} {
			w := httptest.NewRecorder()
			s.Routes().ServeHTTP(w, mcpReq(http.MethodGet, path, nil))
			if w.Code != 200 {
				t.Fatalf("%s status %d", path, w.Code)
			}
			var m map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &m)
			if m["resource"] != mcpResource {
				t.Errorf("%s resource = %v", path, m["resource"])
			}
			if as, _ := m["authorization_servers"].([]any); len(as) != 1 || as[0] != mcpIssuer {
				t.Errorf("%s authorization_servers = %v", path, m["authorization_servers"])
			}
		}
	})

	t.Run("prm-wrong-suffix-404", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, mcpReq(http.MethodGet, "/.well-known/oauth-protected-resource/other", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, mcpReq(http.MethodGet, "/oauth2/jwks.json", nil))
		body := w.Body.String()
		for _, want := range []string{`"kid"`, `"use":"sig"`, `"alg":"ES256"`, `"crv":"P-256"`} {
			if !strings.Contains(body, want) {
				t.Errorf("jwks missing %s: %s", want, body)
			}
		}
		if strings.Contains(body, `"d":`) {
			t.Errorf("jwks leaks private material: %s", body)
		}
	})
}

// ---- DCR --------------------------------------------------------------------

func TestMCPRegister(t *testing.T) {
	cases := []struct {
		name       string
		body       map[string]any
		wantStatus int
		wantErr    string
	}{
		{"valid", map[string]any{"client_name": "A", "redirect_uris": []string{clientCB}}, 201, ""},
		{"omitted-auth-method-ok", map[string]any{"redirect_uris": []string{clientCB}}, 201, ""},
		{"loopback-ok", map[string]any{"redirect_uris": []string{"http://127.0.0.1:8976/cb", "http://localhost/cb"}}, 201, ""},
		{"explicit-none-ok", map[string]any{"redirect_uris": []string{clientCB}, "token_endpoint_auth_method": "none"}, 201, ""},
		{"explicit-basic-rejected", map[string]any{"redirect_uris": []string{clientCB}, "token_endpoint_auth_method": "client_secret_basic"}, 400, "invalid_client_metadata"},
		{"missing-redirect", map[string]any{"client_name": "A"}, 400, "invalid_redirect_uri"},
		{"http-non-loopback", map[string]any{"redirect_uris": []string{"http://evil.example/cb"}}, 400, "invalid_redirect_uri"},
		{"fragment", map[string]any{"redirect_uris": []string{"https://c.example/cb#x"}}, 400, "invalid_redirect_uri"},
		{"relative", map[string]any{"redirect_uris": []string{"/cb"}}, 400, "invalid_redirect_uri"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newMCPServer(t)
			b, _ := json.Marshal(c.body)
			req := mcpReq(http.MethodPost, "/oauth2/register", strings.NewReader(string(b)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.handleRegister(w, req)

			if w.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", w.Code, c.wantStatus, w.Body.String())
			}
			if c.wantErr != "" && !strings.Contains(w.Body.String(), c.wantErr) {
				t.Fatalf("body = %s, want error %q", w.Body.String(), c.wantErr)
			}
			if c.wantStatus == 201 {
				var resp map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &resp)
				if resp["token_endpoint_auth_method"] != "none" {
					t.Errorf("token_endpoint_auth_method = %v, want none", resp["token_endpoint_auth_method"])
				}
				cid, _ := resp["client_id"].(string)
				if _, err := s.as.VerifyClientID(cid); err != nil {
					t.Errorf("returned client_id does not verify: %v", err)
				}
			}
		})
	}
}

// ---- authorize GET ----------------------------------------------------------

func TestAuthorizeGETValidation(t *testing.T) {
	s := newMCPServer(t)
	cid := mintClient(t, s)
	_, challenge := pkcePair()

	t.Run("bad-client-id-400-html-no-redirect", func(t *testing.T) {
		req := mcpReq(http.MethodGet, authorizeQuery("garbage", clientCB, challenge, mcpResource, "", ""), nil)
		addTokenCookies(req, s, Tokens{IDToken: "valid"})
		w := httptest.NewRecorder()
		s.handleAuthorizeGET(w, req)
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("status=%d location=%q, want 400 HTML no redirect", w.Code, w.Header().Get("Location"))
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("Content-Type = %q", ct)
		}
	})

	t.Run("bad-redirect-uri-400-html", func(t *testing.T) {
		req := mcpReq(http.MethodGet, authorizeQuery(cid, "https://attacker.example/cb", challenge, mcpResource, "", ""), nil)
		addTokenCookies(req, s, Tokens{IDToken: "valid"})
		w := httptest.NewRecorder()
		s.handleAuthorizeGET(w, req)
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("status=%d location=%q, want 400 no redirect", w.Code, w.Header().Get("Location"))
		}
	})

	// From here errors redirect back to the validated redirect_uri.
	redirectErr := func(t *testing.T, target, wantErr string) {
		t.Helper()
		req := mcpReq(http.MethodGet, target, nil)
		addTokenCookies(req, s, Tokens{IDToken: "valid"})
		w := httptest.NewRecorder()
		s.handleAuthorizeGET(w, req)
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302 (body=%s)", w.Code, w.Body.String())
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		if !strings.HasPrefix(loc.Scheme+"://"+loc.Host+loc.Path, clientCB) {
			t.Fatalf("redirect not to client cb: %s", loc)
		}
		if got := loc.Query().Get("error"); got != wantErr {
			t.Fatalf("error = %q, want %q", got, wantErr)
		}
	}

	t.Run("bad-response-type", func(t *testing.T) {
		q := authorizeQuery(cid, clientCB, challenge, mcpResource, "", "")
		q = strings.Replace(q, "response_type=code", "response_type=token", 1)
		redirectErr(t, q, "unsupported_response_type")
	})
	t.Run("missing-pkce", func(t *testing.T) {
		u := url.Values{}
		u.Set("client_id", cid)
		u.Set("redirect_uri", clientCB)
		u.Set("response_type", "code")
		u.Set("resource", mcpResource)
		redirectErr(t, "/oauth2/authorize?"+u.Encode(), "invalid_request")
	})
	t.Run("plain-pkce-rejected", func(t *testing.T) {
		q := authorizeQuery(cid, clientCB, challenge, mcpResource, "", "")
		q = strings.Replace(q, "code_challenge_method=S256", "code_challenge_method=plain", 1)
		redirectErr(t, q, "invalid_request")
	})
	t.Run("missing-resource", func(t *testing.T) {
		q := authorizeQuery(cid, clientCB, challenge, "", "", "")
		redirectErr(t, q, "invalid_target")
	})
	t.Run("wrong-resource", func(t *testing.T) {
		q := authorizeQuery(cid, clientCB, challenge, "https://evil.example/mcp", "", "")
		redirectErr(t, q, "invalid_target")
	})
}

func TestAuthorizeGETAuthRedirects(t *testing.T) {
	s := newMCPServer(t)
	cid := mintClient(t, s)
	_, challenge := pkcePair()
	target := authorizeQuery(cid, clientCB, challenge, mcpResource, "st", "")

	t.Run("no-cookie-no-refresh-signin-relative-rd", func(t *testing.T) {
		req := mcpReq(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		s.handleAuthorizeGET(w, req)
		loc := w.Header().Get("Location")
		if !strings.HasPrefix(loc, mcpIssuer+"/oauth2/sign_in?rd=") {
			t.Fatalf("Location = %q, want sign_in", loc)
		}
		u, _ := url.Parse(loc)
		rd := u.Query().Get("rd")
		if !strings.HasPrefix(rd, "/oauth2/authorize") {
			t.Fatalf("rd = %q, want relative /oauth2/authorize path", rd)
		}
		if strings.Contains(rd, "://") {
			t.Fatalf("rd must be relative, got absolute: %q", rd)
		}
	})

	t.Run("invalid-cookie-with-refresh-goes-to-refresh", func(t *testing.T) {
		req := mcpReq(http.MethodGet, target, nil)
		addTokenCookies(req, s, Tokens{IDToken: "expired", RefreshToken: "rt"})
		w := httptest.NewRecorder()
		s.handleAuthorizeGET(w, req)
		loc := w.Header().Get("Location")
		if !strings.HasPrefix(loc, mcpIssuer+"/oauth2/refresh?rd=") {
			t.Fatalf("Location = %q, want refresh", loc)
		}
	})
}

func TestAuthorizeGETDisallowedEmail(t *testing.T) {
	s := newMCPServer(t)
	s.cfg.AllowedDomains = []string{"allowed.example"}
	cid := mintClient(t, s)
	_, challenge := pkcePair()
	req := mcpReq(http.MethodGet, authorizeQuery(cid, clientCB, challenge, mcpResource, "", ""), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"}) // user@example.com not allowed
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestAuthorizeGETHappyRendersConsent(t *testing.T) {
	s := newMCPServer(t)
	cid := mintClient(t, s)
	_, challenge := pkcePair()
	req := mcpReq(http.MethodGet, authorizeQuery(cid, clientCB, challenge, mcpResource, "st", "mcp"), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	authreq, csrf := extractConsent(t, body)
	if authreq == "" || csrf == "" {
		t.Fatal("empty authreq/csrf")
	}
	// Trust anchor: the redirect_uri host is shown; client_name marked unverified.
	if !strings.Contains(body, "client.example.com") {
		t.Error("consent page missing redirect_uri host as trust anchor")
	}
	if !strings.Contains(body, "unverified") {
		t.Error("consent page does not mark client_name unverified")
	}
	// No authorization code is ever produced by the GET.
	if strings.Contains(body, "code=") || w.Header().Get("Location") != "" {
		t.Error("GET authorize leaked a code / redirect")
	}
}

// ---- authorize POST ---------------------------------------------------------

// consentFor drives a GET to obtain a fresh (authreq, csrf) pair for POST tests.
func consentFor(t *testing.T, s *Server, cid, challenge, state string) (authreq, csrf string) {
	t.Helper()
	req := mcpReq(http.MethodGet, authorizeQuery(cid, clientCB, challenge, mcpResource, state, "mcp"), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != 200 {
		t.Fatalf("consent GET status = %d", w.Code)
	}
	return extractConsent(t, w.Body.String())
}

func postApprove(s *Server, authreq, csrf, action, origin, idToken string) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Set("authreq", authreq)
	form.Set("csrf", csrf)
	form.Set("action", action)
	req := mcpReq(http.MethodPost, "/oauth2/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if idToken != "" {
		addTokenCookies(req, s, Tokens{IDToken: idToken})
	}
	w := httptest.NewRecorder()
	s.handleAuthorizePOST(w, req)
	return w
}

// TestConsentReferrerPolicy guards a subtle browser regression: the consent
// page's Approve button is a plain top-level <form> POST, and under a
// Referrer-Policy of "no-referrer" a browser sends Origin: null on that POST,
// which handleAuthorizePOST's sameOrigin check rejects as "bad origin". The
// policy must be "same-origin" so the real Origin survives the same-origin POST.
func TestConsentReferrerPolicy(t *testing.T) {
	s := newMCPServer(t)
	cid := mintClient(t, s)
	_, challenge := pkcePair()
	req := mcpReq(http.MethodGet, authorizeQuery(cid, clientCB, challenge, mcpResource, "st", "mcp"), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("consent GET status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q, want same-origin (no-referrer forces Origin: null on the form POST)", got)
	}
}

func TestAuthorizePOST(t *testing.T) {
	_, challenge := pkcePair()

	t.Run("cross-origin-rejected", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		authreq, csrf := consentFor(t, s, cid, challenge, "st")
		w := postApprove(s, authreq, csrf, "approve", "https://attacker.example", "valid")
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
	})

	t.Run("missing-origin-rejected", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		authreq, csrf := consentFor(t, s, cid, challenge, "st")
		w := postApprove(s, authreq, csrf, "approve", "", "valid")
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
	})

	t.Run("csrf-mismatch-rejected", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		authreq, _ := consentFor(t, s, cid, challenge, "st")
		w := postApprove(s, authreq, "wrong-csrf", "approve", mcpIssuer, "valid")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("tampered-authreq-rejected", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		authreq, csrf := consentFor(t, s, cid, challenge, "st")
		w := postApprove(s, authreq+"x", csrf, "approve", mcpIssuer, "valid")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("sub-mismatch-goes-to-signin", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		authreq, csrf := consentFor(t, s, cid, challenge, "st")            // blob sub = user-1
		w := postApprove(s, authreq, csrf, "approve", mcpIssuer, "valid2") // cookie = user-2
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302 to sign-in (body=%s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Header().Get("Location"), "/oauth2/sign_in") {
			t.Fatalf("Location = %q, want sign_in", w.Header().Get("Location"))
		}
	})

	t.Run("happy-mints-code-preserves-state", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		authreq, csrf := consentFor(t, s, cid, challenge, "state-xyz")
		w := postApprove(s, authreq, csrf, "approve", mcpIssuer, "valid")
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302 (body=%s)", w.Code, w.Body.String())
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		if loc.Query().Get("code") == "" {
			t.Fatal("no code in redirect")
		}
		if loc.Query().Get("state") != "state-xyz" {
			t.Fatalf("state = %q, want state-xyz", loc.Query().Get("state"))
		}
		if w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Error("missing Referrer-Policy: no-referrer on code redirect")
		}
	})

	t.Run("deny-returns-access-denied", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		authreq, csrf := consentFor(t, s, cid, challenge, "st")
		w := postApprove(s, authreq, csrf, "deny", mcpIssuer, "valid")
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", w.Code)
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		if loc.Query().Get("error") != "access_denied" {
			t.Fatalf("error = %q, want access_denied", loc.Query().Get("error"))
		}
	})
}

// ---- token ------------------------------------------------------------------

// getCode runs GET → consent POST and returns a fresh authorization code.
func getCode(t *testing.T, s *Server, cid, challenge, state string) string {
	t.Helper()
	authreq, csrf := consentFor(t, s, cid, challenge, state)
	w := postApprove(s, authreq, csrf, "approve", mcpIssuer, "valid")
	if w.Code != http.StatusFound {
		t.Fatalf("approve status = %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code minted")
	}
	return code
}

func postToken(s *Server, form url.Values) *httptest.ResponseRecorder {
	req := mcpReq(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleToken(w, req)
	return w
}

func codeGrantForm(code, verifier, clientID, redirectURI string) url.Values {
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("code_verifier", verifier)
	f.Set("client_id", clientID)
	f.Set("redirect_uri", redirectURI)
	return f
}

func TestTokenAuthorizationCode(t *testing.T) {
	verifier, challenge := pkcePair()

	t.Run("happy", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		code := getCode(t, s, cid, challenge, "st")
		w := postToken(s, codeGrantForm(code, verifier, cid, clientCB))
		if w.Code != 200 {
			t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["access_token"] == nil || resp["refresh_token"] == nil {
			t.Fatalf("missing tokens: %v", resp)
		}
		if resp["token_type"] != "Bearer" {
			t.Errorf("token_type = %v", resp["token_type"])
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Error("missing Cache-Control: no-store")
		}
		// The access token must verify with the right audience.
		if _, err := s.as.VerifyAccessToken(resp["access_token"].(string)); err != nil {
			t.Errorf("issued access token does not verify: %v", err)
		}
	})

	t.Run("wrong-verifier", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		code := getCode(t, s, cid, challenge, "st")
		w := postToken(s, codeGrantForm(code, "wrong-verifier", cid, clientCB))
		assertTokenError(t, w, "invalid_grant")
	})

	t.Run("replayed-code", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		code := getCode(t, s, cid, challenge, "st")
		if w := postToken(s, codeGrantForm(code, verifier, cid, clientCB)); w.Code != 200 {
			t.Fatalf("first redemption status = %d", w.Code)
		}
		w := postToken(s, codeGrantForm(code, verifier, cid, clientCB))
		assertTokenError(t, w, "invalid_grant")
	})

	t.Run("mismatched-redirect-uri", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		code := getCode(t, s, cid, challenge, "st")
		w := postToken(s, codeGrantForm(code, verifier, cid, "https://other.example/cb"))
		assertTokenError(t, w, "invalid_grant")
	})

	t.Run("mismatched-client-id", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		other := mintClient(t, s, "https://c2.example/cb")
		code := getCode(t, s, cid, challenge, "st")
		w := postToken(s, codeGrantForm(code, verifier, other, clientCB))
		assertTokenError(t, w, "invalid_grant")
	})

	t.Run("unsupported-grant", func(t *testing.T) {
		s := newMCPServer(t)
		f := url.Values{}
		f.Set("grant_type", "password")
		w := postToken(s, f)
		assertTokenError(t, w, "unsupported_grant_type")
	})
}

func TestTokenRefreshRotation(t *testing.T) {
	verifier, challenge := pkcePair()
	s := newMCPServer(t)
	cid := mintClient(t, s)
	code := getCode(t, s, cid, challenge, "st")

	w := postToken(s, codeGrantForm(code, verifier, cid, clientCB))
	var first map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &first)
	rt1 := first["refresh_token"].(string)

	// Rotate.
	rf := url.Values{}
	rf.Set("grant_type", "refresh_token")
	rf.Set("refresh_token", rt1)
	rf.Set("client_id", cid)
	w2 := postToken(s, rf)
	if w2.Code != 200 {
		t.Fatalf("refresh status = %d (body=%s)", w2.Code, w2.Body.String())
	}
	var second map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &second)
	rt2 := second["refresh_token"].(string)
	if rt2 == "" || rt2 == rt1 {
		t.Fatalf("refresh not rotated: rt1=%s rt2=%s", rt1, rt2)
	}

	// Reuse of the rotated (old) refresh token is rejected.
	w3 := postToken(s, rf)
	assertTokenError(t, w3, "invalid_grant")

	// New access token still verifies.
	if _, err := s.as.VerifyAccessToken(second["access_token"].(string)); err != nil {
		t.Errorf("rotated access token does not verify: %v", err)
	}
}

func assertTokenError(t *testing.T, w *httptest.ResponseRecorder, wantErr string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != wantErr {
		t.Fatalf("error = %v, want %q", resp["error"], wantErr)
	}
}

// ---- mcp-verify (RS hot path) -----------------------------------------------

func validAccessToken(t *testing.T, s *Server) string {
	t.Helper()
	grant, err := s.as.IssueGrant(mcpauth.GrantInput{
		Sub: "user-1", Email: "user@example.com", ClientID: "c", Resource: mcpResource, Scope: "mcp",
	})
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}
	return grant.AccessToken
}

func mcpVerify(s *Server, authz string) *httptest.ResponseRecorder {
	req := mcpReq(http.MethodGet, "/mcp-verify", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	s.handleMCPVerify(w, req)
	return w
}

func TestMCPVerifyMatrix(t *testing.T) {
	s := newMCPServer(t)
	prm := "https://docs.hierarchy40.com/.well-known/oauth-protected-resource/mcp"

	t.Run("no-header-401-no-error", func(t *testing.T) {
		w := mcpVerify(s, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		wa := w.Header().Get("WWW-Authenticate")
		if !strings.Contains(wa, `resource_metadata="`+prm+`"`) {
			t.Fatalf("WWW-Authenticate = %q, want canonical resource_metadata", wa)
		}
		if strings.Contains(wa, "error=") {
			t.Fatalf("absent-credentials challenge must not carry error: %q", wa)
		}
	})

	t.Run("malformed-header-invalid_request", func(t *testing.T) {
		w := mcpVerify(s, "Basic abc")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_request"`) {
			t.Fatalf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("invalid-token-invalid_token", func(t *testing.T) {
		w := mcpVerify(s, "Bearer not-a-jwt")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("valid-200-headers", func(t *testing.T) {
		w := mcpVerify(s, "Bearer "+validAccessToken(t, s))
		if w.Code != 200 {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if w.Header().Get("X-Auth-Request-Email") != "user@example.com" {
			t.Errorf("X-Auth-Request-Email = %q", w.Header().Get("X-Auth-Request-Email"))
		}
		if w.Header().Get("X-Auth-Request-User") != "user-1" {
			t.Errorf("X-Auth-Request-User = %q", w.Header().Get("X-Auth-Request-User"))
		}
	})

	t.Run("never-redirects", func(t *testing.T) {
		for _, authz := range []string{"", "Bearer bad", "Basic x"} {
			if code := mcpVerify(s, authz).Code; code == http.StatusFound || code == http.StatusMovedPermanently {
				t.Fatalf("mcp-verify redirected (%d) for %q", code, authz)
			}
		}
	})
}

func TestMCPVerifyDisallowedEmail(t *testing.T) {
	s := newMCPServer(t)
	s.cfg.AllowedDomains = []string{"allowed.example"}
	w := mcpVerify(s, "Bearer "+validAccessToken(t, s)) // user@example.com not allowed
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// TestMCPVerifyRejectsCrossArtifacts pins that non-access artifacts, though
// signed/encrypted by the same key, are refused as bearer tokens.
func TestMCPVerifyRejectsCrossArtifacts(t *testing.T) {
	s := newMCPServer(t)
	cid := mintClient(t, s)
	blob, _, _ := s.as.MintAuthReq(mcpauth.AuthReqInput{ClientID: cid, RedirectURI: clientCB, Resource: mcpResource, Sub: "user-1"})
	authReq, _ := s.as.VerifyAuthReq(blob)
	code, _ := s.as.MintCode(authReq)
	grant, _ := s.as.IssueGrant(mcpauth.GrantInput{Sub: "user-1", ClientID: cid, Resource: mcpResource, Scope: "mcp"})

	for name, tok := range map[string]string{"client_id": cid, "authreq": blob, "code": code, "refresh": grant.RefreshToken} {
		w := mcpVerify(s, "Bearer "+tok)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s accepted at mcp-verify (status %d), want 401", name, w.Code)
		}
	}
}

func TestMCPVerifyRejectsAlgConfusion(t *testing.T) {
	s := newMCPServer(t)
	claims := map[string]any{"iss": mcpIssuer, "aud": mcpResource, "token_use": "access"}

	hsKey := make([]byte, 32)
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hsKey}, nil)
	hsTok, _ := jwt.Signed(sig).Claims(claims).Serialize()
	if w := mcpVerify(s, "Bearer "+hsTok); w.Code != http.StatusUnauthorized {
		t.Errorf("HS256 token accepted (status %d)", w.Code)
	}

	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"token_use":"access"}`))
	if w := mcpVerify(s, "Bearer "+hdr+"."+pl+"."); w.Code != http.StatusUnauthorized {
		t.Errorf("alg=none token accepted (status %d)", w.Code)
	}
}

// TestResourceCanonicalizationYieldsUsableToken pins that a case-variant
// resource host — which MatchesResource accepts — mints an access token whose
// aud is the canonical resource, so /mcp-verify (case-sensitive aud) accepts it.
func TestResourceCanonicalizationYieldsUsableToken(t *testing.T) {
	s := newMCPServer(t)
	cid := mintClient(t, s)
	verifier, challenge := pkcePair()

	variant := "https://DOCS.hierarchy40.com/mcp" // uppercase host
	req := mcpReq(http.MethodGet, authorizeQuery(cid, clientCB, challenge, variant, "st", "mcp"), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != 200 {
		t.Fatalf("authorize GET status = %d (body=%s)", w.Code, w.Body.String())
	}
	authreq, csrf := extractConsent(t, w.Body.String())
	aw := postApprove(s, authreq, csrf, "approve", mcpIssuer, "valid")
	if aw.Code != http.StatusFound {
		t.Fatalf("approve status = %d", aw.Code)
	}
	loc, _ := url.Parse(aw.Header().Get("Location"))
	tw := postToken(s, codeGrantForm(loc.Query().Get("code"), verifier, cid, clientCB))
	if tw.Code != 200 {
		t.Fatalf("token status = %d (body=%s)", tw.Code, tw.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(tw.Body.Bytes(), &tok)
	access := tok["access_token"].(string)

	if vw := mcpVerify(s, "Bearer "+access); vw.Code != 200 {
		t.Fatalf("mcp-verify status = %d, want 200 (token aud must be canonical)", vw.Code)
	}
	claims, err := s.as.VerifyAccessToken(access)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if !claims.Audience.Contains(mcpResource) {
		t.Fatalf("aud = %v, want canonical %q", claims.Audience, mcpResource)
	}
}

// ---- end to end -------------------------------------------------------------

func TestEndToEnd(t *testing.T) {
	s := newMCPServer(t)
	verifier, challenge := pkcePair()

	// 1. Register (via the real DCR endpoint).
	b, _ := json.Marshal(map[string]any{"client_name": "E2E", "redirect_uris": []string{clientCB}})
	req := mcpReq(http.MethodPost, "/oauth2/register", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	s.handleRegister(rw, req)
	if rw.Code != 201 {
		t.Fatalf("register status = %d", rw.Code)
	}
	var reg map[string]any
	_ = json.Unmarshal(rw.Body.Bytes(), &reg)
	cid := reg["client_id"].(string)

	// 2-3. Authorize GET → consent POST.
	code := getCode(t, s, cid, challenge, "e2e-state")

	// 4. Token.
	tw := postToken(s, codeGrantForm(code, verifier, cid, clientCB))
	if tw.Code != 200 {
		t.Fatalf("token status = %d (body=%s)", tw.Code, tw.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(tw.Body.Bytes(), &tok)
	access := tok["access_token"].(string)

	// 5. Authenticated MCP call.
	vw := mcpVerify(s, "Bearer "+access)
	if vw.Code != 200 {
		t.Fatalf("mcp-verify status = %d", vw.Code)
	}
	if vw.Header().Get("X-Auth-Request-Email") != "user@example.com" {
		t.Errorf("X-Auth-Request-Email = %q", vw.Header().Get("X-Auth-Request-Email"))
	}

	// Assert the access token carries the right aud/sub/email/token_use.
	claims, err := s.as.VerifyAccessToken(access)
	if err != nil {
		t.Fatalf("verify access: %v", err)
	}
	if !claims.Audience.Contains(mcpResource) || claims.Subject != "user-1" || claims.Email != "user@example.com" || claims.TokenUse != "access" {
		t.Fatalf("access claims wrong: %+v", claims)
	}
}
