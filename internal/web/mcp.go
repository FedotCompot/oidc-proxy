package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/fedot/oidc-proxy/internal/mcpauth"
	"github.com/fedot/oidc-proxy/internal/utils"
)

// maxMCPBody caps request bodies on the MCP endpoints, mirroring handleSession.
const maxMCPBody = 64 << 10

// ---- discovery / metadata ---------------------------------------------------

// handleASMetadata and handleOIDCConfig serve AS metadata at both the bare
// well-known path and the path-suffixed form clients probe first when the
// issuer carries a path (RFC 8414 §3.1). The suffix must match the issuer's.
func (s *Server) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.issuerSuffixMatches(r) {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.as.ASMetadata(false))
}

func (s *Server) handleOIDCConfig(w http.ResponseWriter, r *http.Request) {
	if !s.issuerSuffixMatches(r) {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.as.ASMetadata(true))
}

func (s *Server) issuerSuffixMatches(r *http.Request) bool {
	suffix := r.PathValue("suffix")
	return suffix == "" || suffix == s.as.IssuerSuffix()
}

// handlePRM serves RFC 9728 protected-resource metadata at both the bare path
// and the canonical path-suffixed location. The trailing wildcard captures the
// resource path; it must match the configured resource's suffix.
func (s *Server) handlePRM(w http.ResponseWriter, r *http.Request) {
	if suffix := r.PathValue("suffix"); suffix != "" && suffix != s.as.ResourceSuffix() {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.as.PRMetadata())
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.as.PublicJWKS())
}

// ---- dynamic client registration (RFC 7591) ---------------------------------

// DCR is deprecated as of MCP 2026-07-28 (superseded by Client ID Metadata
// Documents) but retained for clients that predate it.
type dcrRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
	Scope                   string   `json:"scope"`
}

type dcrResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.regLimiter.allow(utils.ClientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "temporarily_unavailable", "registration rate limit exceeded")
		return
	}

	var req dcrRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMCPBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid JSON")
		return
	}

	// Public-client only: a missing/empty auth method means "none"; anything
	// explicitly other than "none" is rejected (RFC 7591's default is
	// client_secret_basic, but this AS issues no secrets).
	if m := req.TokenEndpointAuthMethod; m != "" && m != "none" {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata",
			"token_endpoint_auth_method must be \"none\"")
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_redirect_uri", "at least one redirect_uri is required")
		return
	}
	for _, uri := range req.RedirectURIs {
		if err := mcpauth.ValidateRedirectURI(uri); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	// application_type is echoed, not enforced: this AS applies the same
	// redirect-URI rules (https or loopback http) to native and web clients.
	appType := req.ApplicationType
	if appType == "" {
		appType = "web" // OIDC Dynamic Client Registration default
	}

	clientID, err := s.as.MintClientID(mcpauth.ClientRegistration{
		RedirectURIs: req.RedirectURIs,
		ClientName:   req.ClientName,
	})
	if err != nil {
		log.Printf("mcp: mint client_id: %v", err)
		writeError(w, http.StatusInternalServerError, "server_error", "could not register client")
		return
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	log.Printf("mcp: registered client name=%q redirect_hosts=%v", req.ClientName, redirectHosts(req.RedirectURIs))
	writeJSON(w, http.StatusCreated, dcrResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        time.Now().Unix(),
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: "none",
		ApplicationType:         appType,
		ClientName:              req.ClientName,
		Scope:                   req.Scope,
	})
}

// ---- authorization endpoint -------------------------------------------------

// handleAuthorizeGET validates the request, authenticates the browser via the
// Entra cookie, and renders the consent page. It NEVER mints a code (see §2.1
// confused-deputy mitigation): a code is only minted by the guarded POST.
func (s *Server) handleAuthorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")

	// 1. client_id must resolve to a client: either an AS-issued (DCR) client_id
	// or a Client ID Metadata Document URL we fetch and validate. The CIMD path
	// makes an outbound request, so it is rate limited per IP.
	if mcpauth.IsURLClientID(clientID) && !s.cimdLimiter.allow(utils.ClientIP(r)) {
		s.renderAuthzError(w, http.StatusTooManyRequests, "Too many requests",
			"Too many authorization requests. Please try again in a minute.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	client, err := s.as.ResolveClient(ctx, clientID)
	if err != nil {
		log.Printf("mcp: resolve client_id: %v", err)
		s.renderAuthzError(w, http.StatusBadRequest, "Invalid request",
			"The client_id is missing or invalid. Re-register the client and try again.")
		return
	}

	// 2. redirect_uri must exactly match a registered URI (never redirect to an
	// unvalidated URI). All later errors go back to this redirect_uri.
	redirectURI := q.Get("redirect_uri")
	if !exactMatch(client.RedirectURIs, redirectURI) {
		s.renderAuthzError(w, http.StatusBadRequest, "Invalid request",
			"The redirect_uri does not match any registered URI for this client.")
		return
	}

	state := q.Get("state")

	// 3. response_type=code.
	if q.Get("response_type") != "code" {
		s.authorizeRedirectError(w, r, redirectURI, "unsupported_response_type",
			"only response_type=code is supported", state)
		return
	}

	// 4. PKCE S256 mandatory (reject plain / missing).
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		s.authorizeRedirectError(w, r, redirectURI, "invalid_request",
			"code_challenge with code_challenge_method=S256 is required", state)
		return
	}

	// 5. resource required and must equal the configured resource (RFC 8707).
	// MatchesResource accepts case variants of scheme/host, so from here on we
	// use the canonical MCP_RESOURCE — that is exactly the value /mcp-verify
	// enforces as the token audience, so the token we mint is always usable.
	if !s.as.MatchesResource(q.Get("resource")) {
		s.authorizeRedirectError(w, r, redirectURI, "invalid_target",
			"resource must equal the canonical MCP resource URI", state)
		return
	}
	resource := s.as.Resource

	// 6. Resolve the granted scope up front so consent shows exactly what the
	// token will carry.
	scope, err := s.as.GrantScope(q.Get("scope"))
	if err != nil {
		s.authorizeRedirectError(w, r, redirectURI, "invalid_scope", err.Error(), state)
		return
	}

	// 7. Authenticate via the Entra session cookie (mirrors handleVerify).
	idTok, ok := s.authenticateBrowser(w, r)
	if !ok {
		return // authenticateBrowser issued the sign-in/refresh redirect
	}

	// 8. Allowlist.
	if !s.userAllowed(idTok.Email) {
		s.renderAuthzError(w, http.StatusForbidden, "Access denied",
			"Your account is not permitted to access this resource.")
		return
	}

	// 9. Seal the consent-request blob and render consent. The code is minted
	// only when the user approves via the same-origin POST.
	blob, csrf, err := s.as.MintAuthReq(mcpauth.AuthReqInput{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: challenge,
		Resource:      resource,
		Scope:         scope,
		State:         state,
		Sub:           idTok.Subject,
		Email:         idTok.Email,
	})
	if err != nil {
		log.Printf("mcp: mint authreq: %v", err)
		s.renderAuthzError(w, http.StatusInternalServerError, "Server error",
			"Could not start the authorization flow. Please try again.")
		return
	}

	s.renderConsent(w, &consentData{
		RedirectHost:   hostOf(redirectURI),
		RedirectOrigin: utils.OriginOf(redirectURI),
		ClientName:     client.ClientName,
		ClientHost:     cimdHost(client),
		LoopbackOnly:   client.LocalhostOnly(),
		Resource:       s.as.Resource,
		Scopes:         strings.Fields(scope),
		AuthReq:        blob,
		CSRF:           csrf,
		BrandColor:     s.cfg.BrandColor,
	})
}

// handleAuthorizePOST is the guarded code-minting step. It requires a
// same-origin POST carrying the CSRF nonce bound to the signed authreq blob,
// and re-verifies the Entra cookie's sub against the blob's sub.
func (s *Server) handleAuthorizePOST(w http.ResponseWriter, r *http.Request) {
	// 1. Same-origin (the Entra cookie is SameSite=Lax, so it is not sent on a
	// cross-site POST; the Origin check + CSRF nonce close the confused deputy).
	if !s.sameOrigin(r) {
		http.Error(w, "bad origin", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMCPBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	// 2. Decrypt + validate the authreq blob.
	authReq, err := s.as.VerifyAuthReq(r.PostForm.Get("authreq"))
	if err != nil {
		s.renderAuthzError(w, http.StatusBadRequest, "Request expired",
			"This authorization request is invalid or has expired. Please start again.")
		return
	}

	// 3. CSRF nonce must match the one sealed in the blob.
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(authReq.CSRF)) != 1 {
		s.renderAuthzError(w, http.StatusBadRequest, "Invalid request",
			"The request could not be verified. Please start again.")
		return
	}

	// Deny → return access_denied to the client.
	if r.PostForm.Get("action") != "approve" {
		s.authorizeRedirectError(w, r, authReq.RedirectURI, "access_denied",
			"the user denied the request", authReq.State)
		return
	}

	// 4. Re-read the Entra cookie; the approver must be the identity the blob
	// was minted for.
	idTok, ok := s.reauthenticate(w, r, authReq)
	if !ok {
		return
	}
	if !s.userAllowed(idTok.Email) {
		s.renderAuthzError(w, http.StatusForbidden, "Access denied",
			"Your account is not permitted to access this resource.")
		return
	}

	// 5. Mint the code from the verified blob only (never from loose fields).
	code, err := s.as.MintCode(authReq)
	if err != nil {
		log.Printf("mcp: mint code: %v", err)
		s.renderAuthzError(w, http.StatusInternalServerError, "Server error",
			"Could not complete the authorization. Please try again.")
		return
	}

	// 6. Deliver the code. iss lets the client detect a mix-up attack before it
	// redeems the code (RFC 9207, required by MCP 2026-07-28).
	u, _ := url.Parse(authReq.RedirectURI)
	qq := u.Query()
	qq.Set("code", code)
	qq.Set("iss", s.as.Issuer)
	if authReq.State != "" {
		qq.Set("state", authReq.State)
	}
	u.RawQuery = qq.Encode()
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---- token endpoint ---------------------------------------------------------

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if !s.tokenLimiter.allow(utils.ClientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "temporarily_unavailable", "token rate limit exceeded")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMCPBody)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.tokenAuthorizationCode(w, r)
	case "refresh_token":
		s.tokenRefresh(w, r)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Server) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	code, err := s.as.VerifyCode(f.Get("code"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", "code is invalid or expired")
		return
	}
	// Single-use (best-effort, per-replica): burn the code on first use.
	if s.as.Guard.SeenBefore(code.ID, s.as.CodeTTL) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "code already used")
		return
	}
	if subtle.ConstantTimeCompare([]byte(f.Get("client_id")), []byte(code.ClientID)) != 1 {
		writeError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	if f.Get("redirect_uri") != code.RedirectURI {
		writeError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !mcpauth.VerifyPKCE(f.Get("code_verifier"), code.CodeChallenge) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	grant, err := s.as.IssueGrant(mcpauth.GrantInput{
		Sub:      code.Subject,
		Email:    code.Email,
		ClientID: code.ClientID,
		Resource: code.Resource,
		Scope:    code.Scope,
	})
	if err != nil {
		log.Printf("mcp: issue grant: %v", err)
		writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	writeTokenGrant(w, grant)
}

func (s *Server) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	refresh, err := s.as.VerifyRefreshToken(f.Get("refresh_token"))
	if err != nil {
		// Log a fixed classification, never the error: a rejected refresh forces
		// a full browser re-auth, and "expired" (raise MCP_REFRESH_TOKEN_TTL)
		// vs "invalid" is the only thing an operator needs to tell them apart.
		reason := "invalid"
		if errors.Is(err, mcpauth.ErrExpired) {
			reason = "expired"
		}
		log.Printf("mcp: refresh rejected (%s)", reason)
		writeError(w, http.StatusBadRequest, "invalid_grant", "refresh_token is invalid or expired")
		return
	}
	// Public clients send client_id; when present it must bind to the token.
	if cid := f.Get("client_id"); cid != "" && subtle.ConstantTimeCompare([]byte(cid), []byte(refresh.ClientID)) != 1 {
		log.Printf("mcp: refresh rejected (client_id mismatch) jti=%s", refresh.ID)
		writeError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	// Rotation: burn the presented token; a reused (already-rotated) token is
	// rejected (best-effort per-replica — see mcpauth.ReplayGuard).
	if s.as.Guard.SeenBefore(refresh.ID, s.as.RefreshTTL) {
		// Same jti twice in quick succession is a retried or concurrent refresh,
		// not theft; family ties the rotation lineage together across both.
		log.Printf("mcp: refresh rejected (already used) jti=%s family=%s", refresh.ID, refresh.Family)
		writeError(w, http.StatusBadRequest, "invalid_grant", "refresh_token already used")
		return
	}

	grant, err := s.as.IssueGrant(mcpauth.GrantInput{
		Sub:      refresh.Subject,
		Email:    refresh.Email,
		ClientID: refresh.ClientID,
		Resource: refresh.Resource,
		Scope:    refresh.Scope, // never widen scope
		Family:   refresh.Family,
	})
	if err != nil {
		log.Printf("mcp: refresh grant: %v", err)
		writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	writeTokenGrant(w, grant)
}

// ---- resource-server verify (forwardAuth hot path) --------------------------

// handleMCPVerify is the RS token check Traefik calls for every /mcp request.
// It never redirects (agents are not browsers): only 200 / 401 / 403.
func (s *Server) handleMCPVerify(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		// No credentials: 401 with no error param (RFC 6750 §3.1).
		w.Header().Set("WWW-Authenticate", s.wwwAuthenticate(""))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	const prefix = "Bearer "
	if len(authz) <= len(prefix) || !strings.EqualFold(authz[:len(prefix)], prefix) {
		w.Header().Set("WWW-Authenticate", s.wwwAuthenticate("invalid_request"))
		http.Error(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimSpace(authz[len(prefix):])

	claims, err := s.as.VerifyAccessToken(tokenStr)
	if err != nil {
		w.Header().Set("WWW-Authenticate", s.wwwAuthenticate("invalid_token"))
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	if !s.userAllowed(claims.Email) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Insufficient scope is 403 + a challenge naming what the operation needs,
	// so the client can run a step-up authorization (RFC 6750 §3.1).
	if !s.as.HasRequiredScopes(claims.Scope) {
		w.Header().Set("WWW-Authenticate", s.wwwAuthenticate("insufficient_scope"))
		http.Error(w, "insufficient scope", http.StatusForbidden)
		return
	}

	if claims.Email != "" {
		w.Header().Set("X-Auth-Request-Email", claims.Email)
	}
	if claims.Subject != "" {
		w.Header().Set("X-Auth-Request-User", claims.Subject)
	}
	w.WriteHeader(http.StatusOK)
}

// ---- authentication helpers -------------------------------------------------

// authenticateBrowser verifies the Entra id_token cookie for GET /authorize.
// On failure it issues the sign-in (or refresh) redirect with a RELATIVE rd
// pointing back at this authorize request, and returns ok=false.
func (s *Server) authenticateBrowser(w http.ResponseWriter, r *http.Request) (*verifiedID, bool) {
	rd := "/oauth2/authorize"
	if r.URL.RawQuery != "" {
		rd += "?" + r.URL.RawQuery
	}
	return s.verifyEntraCookie(w, r, rd)
}

// reauthenticate re-verifies the Entra cookie for POST /authorize and requires
// the subject to equal the blob's subject. On failure it redirects to sign-in
// with an rd reconstructed from the blob.
func (s *Server) reauthenticate(w http.ResponseWriter, r *http.Request, authReq *mcpauth.AuthReqClaims) (*verifiedID, bool) {
	rd := reconstructAuthorizeURL(authReq)
	idTok, ok := s.verifyEntraCookie(w, r, rd)
	if !ok {
		return nil, false
	}
	if idTok.Subject != authReq.Subject {
		// A different identity approved than the blob was minted for: send them
		// back through sign-in rather than issuing a code for the wrong user.
		s.redirectToSignInWith(w, r, rd)
		return nil, false
	}
	return idTok, true
}

// verifiedID is the minimal identity carried out of a cookie verification.
type verifiedID struct {
	Subject string
	Email   string
}

// verifyEntraCookie verifies the id_token cookie, mirroring handleVerify's
// branches: valid → identity; otherwise, a present refresh cookie → refresh
// page, else → sign-in. rd (relative) is preserved across the redirect.
func (s *Server) verifyEntraCookie(w http.ResponseWriter, r *http.Request, rd string) (*verifiedID, bool) {
	tokens := s.readTokens(r)
	if tokens.IDToken != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if idTok, err := s.verifyFn(ctx, tokens.IDToken); err == nil {
			return &verifiedID{Subject: idTok.Subject, Email: idTok.Email}, true
		}
	}
	// id_token missing or no longer valid: fall back to the browser flow,
	// preferring an in-browser refresh when a refresh cookie is present.
	if tokens.RefreshToken != "" {
		u := s.expectedOrigin(r) + "/oauth2/refresh?rd=" + url.QueryEscape(rd)
		http.Redirect(w, r, u, http.StatusFound)
		return nil, false
	}
	s.redirectToSignInWith(w, r, rd)
	return nil, false
}

// ---- small response/helper functions ----------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("mcp: encode response: %v", err)
	}
}

// writeError emits an OAuth/DCR style error object.
func writeError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeTokenGrant(w http.ResponseWriter, g mcpauth.TokenGrant) {
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  g.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    g.ExpiresIn,
		"refresh_token": g.RefreshToken,
		"scope":         g.Scope,
	})
}

// wwwAuthenticate builds the RFC 6750 challenge. resource_metadata (canonical,
// from MCP_RESOURCE) is always present; errCode and the required-scope hint are
// added only when non-empty. Clients treat the challenged scope as
// authoritative for the current operation (MCP 2026-07-28 scope selection).
func (s *Server) wwwAuthenticate(errCode string) string {
	v := `Bearer resource_metadata="` + s.as.PRMURL() + `"`
	if errCode != "" {
		v += `, error="` + errCode + `"`
	}
	if scope := s.as.RequiredScope(); scope != "" {
		v += `, scope="` + scope + `"`
	}
	return v
}

// authorizeRedirectError sends an OAuth error back to a *validated* redirect_uri.
func (s *Server) authorizeRedirectError(w http.ResponseWriter, r *http.Request, redirectURI, code, desc, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.renderAuthzError(w, http.StatusBadRequest, "Invalid request", "The redirect_uri is invalid.")
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("iss", s.as.Issuer) // RFC 9207 applies to error responses too
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// exactMatch reports whether candidate is byte-for-byte one of the registered
// URIs (redirect URIs are matched exactly, never by prefix/normalization).
func exactMatch(registered []string, candidate string) bool {
	return candidate != "" && slices.Contains(registered, candidate)
}

// reconstructAuthorizeURL rebuilds the relative /oauth2/authorize URL from a
// verified blob, so a POST that lost its session can resume after sign-in.
func reconstructAuthorizeURL(a *mcpauth.AuthReqClaims) string {
	q := url.Values{}
	q.Set("client_id", a.ClientID)
	q.Set("redirect_uri", a.RedirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", a.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", a.Resource)
	if a.Scope != "" {
		q.Set("scope", a.Scope)
	}
	if a.State != "" {
		q.Set("state", a.State)
	}
	return "/oauth2/authorize?" + q.Encode()
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}

func redirectHosts(uris []string) []string {
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		out = append(out, hostOf(u))
	}
	return out
}

// cimdHost is the host that vouches for a CIMD client's metadata — the one
// piece of the client's identity the AS actually verified. Empty for DCR
// clients, whose metadata is wholly self-asserted.
func cimdHost(c *mcpauth.ClientMetadata) string {
	if !c.CIMD {
		return ""
	}
	return hostOf(c.ClientID)
}
