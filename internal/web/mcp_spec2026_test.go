package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fedot/oidc-proxy/internal/mcpauth"
)

// Coverage for the MCP rev 2026-07-28 authorization deltas: Client ID Metadata
// Documents, RFC 9207 iss, scope grant/enforcement, and DCR application_type.

// reconfigureAS swaps in an AS built from opts, filling in the fixed
// issuer/resource/key the rest of the web tests assume.
func reconfigureAS(t *testing.T, s *Server, opts mcpauth.Options) {
	t.Helper()
	opts.Issuer, opts.Resource = mcpIssuer, mcpResource
	if opts.SigningKeyPEM == "" {
		opts.SigningKeyPEM = testKeyPEM(t)
	}
	as, err := mcpauth.New(opts)
	if err != nil {
		t.Fatalf("mcpauth.New: %v", err)
	}
	s.as = as
}

// cimdDoc starts a TLS server hosting a client metadata document and returns
// the client_id URL it is published at.
func cimdDoc(t *testing.T, s *Server, redirectURIs []string) string {
	t.Helper()
	var clientID string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     clientID,
			"client_name":   "Metadata Doc App",
			"redirect_uris": redirectURIs,
		})
	}))
	t.Cleanup(srv.Close)
	clientID = srv.URL + "/client.json"

	reconfigureAS(t, s, mcpauth.Options{
		ScopesSupported: []string{"mcp"},
		CIMD:            mcpauth.CIMDOptions{Enabled: true, HTTPClient: srv.Client()},
	})
	return clientID
}

func TestASMetadata2026Fields(t *testing.T) {
	s := newMCPServer(t)

	metadata := func() map[string]any {
		w := httptest.NewRecorder()
		s.handleASMetadata(w, mcpReq(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode metadata: %v", err)
		}
		return m
	}

	m := metadata()
	if m["authorization_response_iss_parameter_supported"] != true {
		t.Error("authorization_response_iss_parameter_supported must be advertised (RFC 9207)")
	}
	if m["client_id_metadata_document_supported"] != false {
		t.Errorf("client_id_metadata_document_supported = %v, want false when CIMD is off", m["client_id_metadata_document_supported"])
	}

	_ = cimdDoc(t, s, []string{clientCB})
	if m := metadata(); m["client_id_metadata_document_supported"] != true {
		t.Error("client_id_metadata_document_supported must be true when CIMD is enabled")
	}
}

// A path-bearing issuer is probed at /.well-known/<suffix>/<issuer path>
// first (RFC 8414 §3.1), so both routes must answer — and only for the
// issuer's own path.
func TestASMetadataPathSuffixedDiscovery(t *testing.T) {
	s := newMCPServer(t)
	as, err := mcpauth.New(mcpauth.Options{
		Issuer:        mcpIssuer + "/tenant1",
		Resource:      mcpResource,
		SigningKeyPEM: testKeyPEM(t),
	})
	if err != nil {
		t.Fatalf("mcpauth.New: %v", err)
	}
	s.as = as

	get := func(target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, mcpReq(http.MethodGet, target, nil))
		return w
	}

	for _, target := range []string{
		"/.well-known/oauth-authorization-server/tenant1",
		"/.well-known/openid-configuration/tenant1",
		"/.well-known/oauth-authorization-server",
	} {
		w := get(target)
		if w.Code != 200 {
			t.Errorf("GET %s = %d, want 200", target, w.Code)
			continue
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if m["issuer"] != mcpIssuer+"/tenant1" {
			t.Errorf("GET %s issuer = %v", target, m["issuer"])
		}
	}

	if w := get("/.well-known/oauth-authorization-server/other-tenant"); w.Code != 404 {
		t.Errorf("foreign issuer path = %d, want 404", w.Code)
	}
}

func TestAuthorizeWithClientIDMetadataDocument(t *testing.T) {
	s := newMCPServer(t)
	clientID := cimdDoc(t, s, []string{clientCB})
	verifier, challenge := pkcePair()

	req := mcpReq(http.MethodGet, authorizeQuery(clientID, clientCB, challenge, mcpResource, "st", "mcp"), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != 200 {
		t.Fatalf("consent GET status = %d (body=%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Metadata Doc App") {
		t.Error("consent page does not show the client_name from the metadata document")
	}
	if !strings.Contains(body, "Published by") {
		t.Error("consent page does not show the host that published the metadata document")
	}

	authreq, csrf := extractConsent(t, body)
	aw := postApprove(s, authreq, csrf, "approve", mcpIssuer, "valid")
	if aw.Code != http.StatusFound {
		t.Fatalf("approve status = %d", aw.Code)
	}
	loc, _ := url.Parse(aw.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code minted for a CIMD client")
	}

	// The URL client_id is what the token endpoint must be given.
	tw := postToken(s, codeGrantForm(code, verifier, clientID, clientCB))
	if tw.Code != 200 {
		t.Fatalf("token status = %d (body=%s)", tw.Code, tw.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(tw.Body.Bytes(), &tok)
	claims, err := s.as.VerifyAccessToken(tok["access_token"].(string))
	if err != nil {
		t.Fatalf("verify access: %v", err)
	}
	if claims.ClientID != clientID {
		t.Errorf("access token client_id = %q, want %q", claims.ClientID, clientID)
	}
}

func TestAuthorizeCIMDRedirectURIMustMatchDocument(t *testing.T) {
	s := newMCPServer(t)
	clientID := cimdDoc(t, s, []string{clientCB})
	_, challenge := pkcePair()

	req := mcpReq(http.MethodGet, authorizeQuery(clientID, "https://attacker.example/cb", challenge, mcpResource, "", "mcp"), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("status=%d location=%q, want 400 with no redirect", w.Code, w.Header().Get("Location"))
	}
}

// Claude Code publishes portless loopback redirect URIs and arrives on an
// ephemeral port, which RFC 8252 §7.3 requires the AS to accept. Byte-exact
// matching made every native CIMD client fail at the authorize step.
func TestAuthorizeCIMDLoopbackEphemeralPort(t *testing.T) {
	s := newMCPServer(t)
	clientID := cimdDoc(t, s, []string{"http://localhost/callback", "http://127.0.0.1/callback"})
	_, challenge := pkcePair()

	const ephemeral = "http://localhost:57351/callback"
	req := mcpReq(http.MethodGet, authorizeQuery(clientID, ephemeral, challenge, mcpResource, "st", "mcp"), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != 200 {
		t.Fatalf("consent GET status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	// The code must come back to the port that was actually requested.
	authreq, csrf := extractConsent(t, w.Body.String())
	aw := postApprove(s, authreq, csrf, "approve", mcpIssuer, "valid")
	loc, _ := url.Parse(aw.Header().Get("Location"))
	if loc.Host != "localhost:57351" || loc.Path != "/callback" {
		t.Fatalf("redirected to %s, want the requested ephemeral port", loc)
	}
}

func TestAuthorizeCIMDLoopbackWarning(t *testing.T) {
	s := newMCPServer(t)
	const loopback = "http://127.0.0.1:3000/callback"
	clientID := cimdDoc(t, s, []string{loopback})
	_, challenge := pkcePair()

	req := mcpReq(http.MethodGet, authorizeQuery(clientID, loopback, challenge, mcpResource, "", "mcp"), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != 200 {
		t.Fatalf("consent GET status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "this device") {
		t.Error("consent page omits the loopback-only warning")
	}
}

func TestAuthorizeRejectsURLClientIDWhenCIMDDisabled(t *testing.T) {
	s := newMCPServer(t) // CIMD off
	_, challenge := pkcePair()

	req := mcpReq(http.MethodGet, authorizeQuery("https://app.example.com/client.json", clientCB, challenge, mcpResource, "", ""), nil)
	addTokenCookies(req, s, Tokens{IDToken: "valid"})
	w := httptest.NewRecorder()
	s.handleAuthorizeGET(w, req)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestAuthorizeResponseCarriesIssuer(t *testing.T) {
	s := newMCPServer(t)
	cid := mintClient(t, s)
	_, challenge := pkcePair()

	t.Run("success", func(t *testing.T) {
		authreq, csrf := consentFor(t, s, cid, challenge, "st")
		w := postApprove(s, authreq, csrf, "approve", mcpIssuer, "valid")
		loc, _ := url.Parse(w.Header().Get("Location"))
		if got := loc.Query().Get("iss"); got != mcpIssuer {
			t.Fatalf("iss = %q, want %q", got, mcpIssuer)
		}
	})

	t.Run("error", func(t *testing.T) {
		authreq, csrf := consentFor(t, s, cid, challenge, "st")
		w := postApprove(s, authreq, csrf, "deny", mcpIssuer, "valid")
		loc, _ := url.Parse(w.Header().Get("Location"))
		if loc.Query().Get("error") != "access_denied" {
			t.Fatalf("error = %q", loc.Query().Get("error"))
		}
		if got := loc.Query().Get("iss"); got != mcpIssuer {
			t.Fatalf("iss = %q, want %q on an error response", got, mcpIssuer)
		}
	})
}

func TestAuthorizeScopeHandling(t *testing.T) {
	verifier, challenge := pkcePair()

	t.Run("unsupported-scope-rejected", func(t *testing.T) {
		s := newMCPServer(t)
		cid := mintClient(t, s)
		req := mcpReq(http.MethodGet, authorizeQuery(cid, clientCB, challenge, mcpResource, "", "mcp admin"), nil)
		addTokenCookies(req, s, Tokens{IDToken: "valid"})
		w := httptest.NewRecorder()
		s.handleAuthorizeGET(w, req)
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", w.Code)
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		if got := loc.Query().Get("error"); got != "invalid_scope" {
			t.Fatalf("error = %q, want invalid_scope", got)
		}
	})

	// An omitted scope grants everything advertised, which is exactly what the
	// consent page shows — the token must not come back empty.
	t.Run("omitted-scope-grants-supported", func(t *testing.T) {
		s := newMCPServer(t)
		reconfigureAS(t, s, mcpauth.Options{ScopesSupported: []string{"mcp", "mcp:write"}})
		cid := mintClient(t, s)

		req := mcpReq(http.MethodGet, authorizeQuery(cid, clientCB, challenge, mcpResource, "", ""), nil)
		addTokenCookies(req, s, Tokens{IDToken: "valid"})
		w := httptest.NewRecorder()
		s.handleAuthorizeGET(w, req)
		if w.Code != 200 {
			t.Fatalf("consent GET status = %d", w.Code)
		}
		authreq, csrf := extractConsent(t, w.Body.String())
		aw := postApprove(s, authreq, csrf, "approve", mcpIssuer, "valid")
		loc, _ := url.Parse(aw.Header().Get("Location"))

		tw := postToken(s, codeGrantForm(loc.Query().Get("code"), verifier, cid, clientCB))
		var tok map[string]any
		_ = json.Unmarshal(tw.Body.Bytes(), &tok)
		if tok["scope"] != "mcp mcp:write" {
			t.Fatalf("granted scope = %v, want %q", tok["scope"], "mcp mcp:write")
		}
	})
}

func TestMCPVerifyInsufficientScope(t *testing.T) {
	s := newMCPServer(t)
	reconfigureAS(t, s, mcpauth.Options{
		ScopesSupported: []string{"mcp", "mcp:write"},
		RequiredScopes:  []string{"mcp:write"},
	})

	grant := func(scope string) string {
		t.Helper()
		g, err := s.as.IssueGrant(mcpauth.GrantInput{
			Sub: "user-1", Email: "user@example.com",
			ClientID: "cid", Resource: mcpResource, Scope: scope,
		})
		if err != nil {
			t.Fatalf("IssueGrant: %v", err)
		}
		return g.AccessToken
	}

	t.Run("missing-scope-403", func(t *testing.T) {
		w := mcpVerify(s, "Bearer "+grant("mcp"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		wa := w.Header().Get("WWW-Authenticate")
		if !strings.Contains(wa, `error="insufficient_scope"`) || !strings.Contains(wa, `scope="mcp:write"`) {
			t.Fatalf("WWW-Authenticate = %q", wa)
		}
	})

	t.Run("sufficient-scope-200", func(t *testing.T) {
		if w := mcpVerify(s, "Bearer "+grant("mcp mcp:write")); w.Code != 200 {
			t.Fatalf("status = %d, want 200", w.Code)
		}
	})

	// The unauthenticated challenge advertises the same scope, so a client can
	// ask for it on the first authorization rather than after a 403.
	t.Run("401-challenge-carries-scope", func(t *testing.T) {
		w := mcpVerify(s, "")
		if !strings.Contains(w.Header().Get("WWW-Authenticate"), `scope="mcp:write"`) {
			t.Fatalf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
		}
	})
}

func TestMCPVerifyNoScopeEnforcementByDefault(t *testing.T) {
	s := newMCPServer(t) // no RequiredScopes
	g, err := s.as.IssueGrant(mcpauth.GrantInput{
		Sub: "user-1", Email: "user@example.com", ClientID: "cid", Resource: mcpResource,
	})
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}
	if w := mcpVerify(s, "Bearer "+g.AccessToken); w.Code != 200 {
		t.Fatalf("status = %d, want 200 when no scopes are required", w.Code)
	}
	if strings.Contains(s.wwwAuthenticate(""), "scope=") {
		t.Error("challenge must omit scope when nothing is required")
	}
}

func TestRegisterApplicationType(t *testing.T) {
	register := func(t *testing.T, body map[string]any) map[string]any {
		t.Helper()
		s := newMCPServer(t)
		b, _ := json.Marshal(body)
		req := mcpReq(http.MethodPost, "/oauth2/register", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.handleRegister(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return resp
	}

	native := register(t, map[string]any{
		"redirect_uris":    []string{"http://127.0.0.1:3000/callback"},
		"application_type": "native",
	})
	if native["application_type"] != "native" {
		t.Errorf("application_type = %v, want native", native["application_type"])
	}

	omitted := register(t, map[string]any{"redirect_uris": []string{clientCB}})
	if omitted["application_type"] != "web" {
		t.Errorf("application_type = %v, want the OIDC default \"web\"", omitted["application_type"])
	}
}
