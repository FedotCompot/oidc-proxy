// Package mcpauth implements a resource-agnostic OAuth 2.1 Authorization
// Server facade for MCP clients (MCP spec rev 2026-07-28). It mints and
// verifies its own stateless, key-signed/encrypted artifacts — it never
// redeems codes or forwards tokens to the upstream IdP. The HTTP wiring lives
// in internal/web; this package holds the types, key material, and the
// mint/verify logic that enforces the threat model.
package mcpauth

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// defaultReplayGuardSize bounds the in-memory jti set. Codes (60s) and refresh
// tokens (hours) are the only guarded artifacts, so a few thousand entries far
// exceeds a realistic in-flight population.
const defaultReplayGuardSize = 8192

// Options configures a new AS. It is populated from config.Config in main.go
// so this package stays decoupled from envconfig.
type Options struct {
	Issuer          string
	Resource        string
	ResourceDocs    string
	ScopesSupported []string

	// RequiredScopes are the scopes the resource server demands. Empty means no
	// scope enforcement; when set they must be a subset of ScopesSupported.
	RequiredScopes []string

	SigningKeyPEM string
	SigningKID    string
	EncKeyB64     string

	AccessTTL  time.Duration
	RefreshTTL time.Duration
	CodeTTL    time.Duration
	AuthReqTTL time.Duration

	// CIMD configures Client ID Metadata Document resolution (MCP 2026-07-28).
	CIMD CIMDOptions

	// Guard is optional; a per-process MemoryReplayGuard is used when nil.
	Guard ReplayGuard
}

// AS is the Authorization Server. It is safe for concurrent use: all fields are
// set at construction and never mutated (the ReplayGuard has its own locking).
type AS struct {
	Issuer          string
	Resource        string
	ResourceDocs    string
	ScopesSupported []string
	RequiredScopes  []string

	AccessTTL  time.Duration
	RefreshTTL time.Duration
	CodeTTL    time.Duration
	AuthReqTTL time.Duration

	Guard ReplayGuard

	keys              *keyMaterial
	cimd              *cimdResolver // nil when CIMD is disabled
	canonicalResource string        // normalized MCP_RESOURCE (lower scheme/host)
	prmURL            string        // canonical RFC 9728 §3.1 PRM URL
	resourceSuffix    string        // resource path minus leading slash (routing key)
	issuerSuffix      string        // issuer path minus leading slash (routing key)

	nowFn func() time.Time
}

// New builds an AS from Options, parsing the signing key and precomputing the
// canonical resource/PRM values. It returns an error (fail fast) on any
// malformed input so a half-configured AS never boots.
func New(opts Options) (*AS, error) {
	issuer, err := requireHTTPSURL("MCP_ISSUER", opts.Issuer)
	if err != nil {
		return nil, err
	}
	resource, err := requireHTTPSURL("MCP_RESOURCE", opts.Resource)
	if err != nil {
		return nil, err
	}

	keys, err := loadKeys(opts.SigningKeyPEM, opts.SigningKID, opts.EncKeyB64)
	if err != nil {
		return nil, err
	}

	scopes := opts.ScopesSupported
	if len(scopes) == 0 {
		scopes = []string{"mcp"}
	}

	for _, s := range opts.RequiredScopes {
		if !slices.Contains(scopes, s) {
			return nil, fmt.Errorf("MCP_REQUIRED_SCOPES: %q is not in MCP_SCOPES_SUPPORTED", s)
		}
	}

	guard := opts.Guard
	if guard == nil {
		guard = NewMemoryReplayGuard(defaultReplayGuardSize)
	}

	var cimd *cimdResolver
	if opts.CIMD.Enabled {
		cimd = newCIMDResolver(opts.CIMD)
	}

	as := &AS{
		Issuer:            strings.TrimRight(issuer.String(), "/"),
		Resource:          resource.String(),
		ResourceDocs:      opts.ResourceDocs,
		ScopesSupported:   scopes,
		RequiredScopes:    opts.RequiredScopes,
		cimd:              cimd,
		AccessTTL:         orDefault(opts.AccessTTL, 15*time.Minute),
		RefreshTTL:        orDefault(opts.RefreshTTL, 8*time.Hour),
		CodeTTL:           orDefault(opts.CodeTTL, 60*time.Second),
		AuthReqTTL:        orDefault(opts.AuthReqTTL, 5*time.Minute),
		Guard:             guard,
		keys:              keys,
		canonicalResource: normalizeResource(resource),
		prmURL:            derivePRMURL(resource),
		resourceSuffix:    strings.Trim(resource.Path, "/"),
		issuerSuffix:      strings.Trim(issuer.Path, "/"),
		nowFn:             time.Now,
	}
	return as, nil
}

func (as *AS) now() time.Time { return as.nowFn() }

// KID is the current signing key id (exposed for tests/diagnostics).
func (as *AS) KID() string { return as.keys.kid }

// PublicJWKS returns the public signing keys for jwks_uri. Public material only.
func (as *AS) PublicJWKS() jose.JSONWebKeySet { return as.keys.public }

// PRMURL is the canonical RFC 9728 §3.1 Protected Resource Metadata URL derived
// from MCP_RESOURCE. It is the value placed in WWW-Authenticate:resource_metadata.
func (as *AS) PRMURL() string { return as.prmURL }

// ResourceSuffix is the resource path without its leading slash, used to route
// the path-suffixed PRM endpoint (e.g. "mcp" for https://host/mcp).
func (as *AS) ResourceSuffix() string { return as.resourceSuffix }

// IssuerSuffix is the issuer path without its leading slash. Clients probing a
// path-bearing issuer insert that path after the well-known suffix (RFC 8414
// §3.1), so the metadata endpoints are routed on it too.
func (as *AS) IssuerSuffix() string { return as.issuerSuffix }

// CIMDEnabled reports whether Client ID Metadata Documents are accepted.
func (as *AS) CIMDEnabled() bool { return as.cimd != nil }

// ResolveClient turns a client_id into the client identity behind it. An https
// client_id is resolved as a Client ID Metadata Document (fetched, validated,
// cached); anything else must be an AS-issued DCR client_id.
func (as *AS) ResolveClient(ctx context.Context, clientID string) (*ClientMetadata, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if IsURLClientID(clientID) {
		if as.cimd == nil {
			return nil, fmt.Errorf("client ID metadata documents are not enabled")
		}
		return as.cimd.resolve(ctx, clientID)
	}
	c, err := as.VerifyClientID(clientID)
	if err != nil {
		return nil, err
	}
	return &ClientMetadata{
		ClientID:     clientID,
		ClientName:   c.ClientName,
		RedirectURIs: c.RedirectURIs,
	}, nil
}

// ---- scopes -----------------------------------------------------------------

// GrantScope normalizes a requested scope string into the set that will be
// granted. An empty request grants everything advertised in scopes_supported —
// which is what the consent screen shows — and any unsupported scope is an
// error (OAuth 2.1 invalid_scope) rather than being silently dropped.
func (as *AS) GrantScope(requested string) (string, error) {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		return strings.Join(as.ScopesSupported, " "), nil
	}
	granted := make([]string, 0, len(fields))
	for _, f := range fields {
		if !slices.Contains(as.ScopesSupported, f) {
			return "", fmt.Errorf("scope %q is not supported", f)
		}
		if !slices.Contains(granted, f) {
			granted = append(granted, f)
		}
	}
	return strings.Join(granted, " "), nil
}

// RequiredScope is the space-delimited scope set the RS demands, for the
// WWW-Authenticate `scope` parameter. Empty when enforcement is off.
func (as *AS) RequiredScope() string { return strings.Join(as.RequiredScopes, " ") }

// HasRequiredScopes reports whether a token's scope covers every required one.
func (as *AS) HasRequiredScopes(tokenScope string) bool {
	if len(as.RequiredScopes) == 0 {
		return true
	}
	held := strings.Fields(tokenScope)
	for _, want := range as.RequiredScopes {
		if !slices.Contains(held, want) {
			return false
		}
	}
	return true
}

// MatchesResource reports whether got equals the configured resource, comparing
// scheme/host case-insensitively and rejecting any fragment (RFC 8707).
func (as *AS) MatchesResource(got string) bool {
	if got == "" {
		return false
	}
	u, err := url.Parse(got)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
		return false
	}
	return normalizeResource(u) == as.canonicalResource
}

// ---- endpoint URLs (all absolute, from the static issuer) -------------------

func (as *AS) authorizationEndpoint() string { return as.Issuer + "/oauth2/authorize" }
func (as *AS) tokenEndpoint() string         { return as.Issuer + "/oauth2/token" }
func (as *AS) registrationEndpoint() string  { return as.Issuer + "/oauth2/register" }
func (as *AS) jwksURI() string               { return as.Issuer + "/oauth2/jwks.json" }

// ---- metadata documents -----------------------------------------------------

// ASMetadata is the RFC 8414 authorization-server metadata document. When oidc
// is true the OIDC-required probe fields are added (for openid-configuration).
type ASMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`

	// MCP 2026-07-28: clients look for these two to pick a registration
	// mechanism (CIMD preferred) and to decide how to validate the
	// authorization response (RFC 9207).
	ClientIDMetadataDocumentSupported          bool `json:"client_id_metadata_document_supported"`
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`

	SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

// ASMetadata builds the AS metadata document. oidc adds the extra fields some
// clients require when they probe /.well-known/openid-configuration.
func (as *AS) ASMetadata(oidc bool) ASMetadata {
	m := ASMetadata{
		Issuer:                            as.Issuer,
		AuthorizationEndpoint:             as.authorizationEndpoint(),
		TokenEndpoint:                     as.tokenEndpoint(),
		RegistrationEndpoint:              as.registrationEndpoint(),
		JWKSURI:                           as.jwksURI(),
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   as.ScopesSupported,

		ClientIDMetadataDocumentSupported:          as.CIMDEnabled(),
		AuthorizationResponseIssParameterSupported: true,
	}
	if oidc {
		m.SubjectTypesSupported = []string{"public"}
		m.IDTokenSigningAlgValuesSupported = []string{"ES256"}
	}
	return m
}

// PRMetadata is the RFC 9728 protected-resource metadata document.
type PRMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// PRMetadata builds the protected-resource metadata for the configured resource.
func (as *AS) PRMetadata() PRMetadata {
	return PRMetadata{
		Resource:               as.Resource,
		AuthorizationServers:   []string{as.Issuer},
		ScopesSupported:        as.ScopesSupported,
		BearerMethodsSupported: []string{"header"},
		ResourceDocumentation:  as.ResourceDocs,
	}
}

// ---- helpers ----------------------------------------------------------------

func requireHTTPSURL(name, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%s must be an https:// URL, got %q", name, raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s must include a host, got %q", name, raw)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("%s must not contain a fragment", name)
	}
	return u, nil
}

// normalizeResource canonicalizes a resource URI: lowercase scheme and host,
// path preserved, query preserved, no fragment.
func normalizeResource(u *url.URL) string {
	out := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// derivePRMURL implements RFC 9728 §3.1: insert /.well-known/oauth-protected-
// resource between the resource's host and path.
func derivePRMURL(u *url.URL) string {
	base := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	path := strings.TrimRight(u.Path, "/")
	if path == "" {
		return base + "/.well-known/oauth-protected-resource"
	}
	return base + "/.well-known/oauth-protected-resource" + path
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}
