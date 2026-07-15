package config

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

const defaultBrandColor = "#2563eb"

type Config struct {
	Issuer          string   `envconfig:"OIDC_ISSUER" required:"true"`
	ClientID        string   `envconfig:"OIDC_CLIENT_ID" required:"true"`
	Scopes          string   `envconfig:"OIDC_SCOPES" default:"openid profile email"`
	AllowedEmails   []string `envconfig:"ALLOWED_EMAILS"`
	AllowedDomains  []string `envconfig:"ALLOWED_DOMAINS"`
	CookiePrefix    string   `envconfig:"COOKIE_NAME_PREFIX" default:"_oidc_proxy"`
	CookieDomain    string   `envconfig:"COOKIE_DOMAIN"`
	CookieSecure    bool     `envconfig:"COOKIE_SECURE" default:"true"`
	VerifyCacheSize int      `envconfig:"VERIFY_CACHE_SIZE" default:"1024"`
	ListenAddr      string   `envconfig:"LISTEN_ADDR" default:":8080"`
	SignInTitle     string   `envconfig:"SIGN_IN_TITLE" default:"Sign in"`
	SignInSubtitle  string   `envconfig:"SIGN_IN_SUBTITLE"`
	SignInButton    string   `envconfig:"SIGN_IN_BUTTON" default:"Sign in with SSO"`
	BrandColor      string   `envconfig:"BRAND_COLOR" default:"#2563eb"`

	// MCP OAuth 2.1 Authorization Server facade. All of this is inert unless
	// MCPEnabled is true; see internal/mcpauth and the "MCP authorization"
	// section of the README.
	MCPEnabled         bool          `envconfig:"MCP_ENABLED" default:"false"`
	MCPIssuer          string        `envconfig:"MCP_ISSUER"`
	MCPResource        string        `envconfig:"MCP_RESOURCE"`
	MCPResourceDocs    string        `envconfig:"MCP_RESOURCE_DOCS"`
	MCPSigningKey      string        `envconfig:"MCP_SIGNING_KEY"`
	MCPSigningKeyFile  string        `envconfig:"MCP_SIGNING_KEY_FILE"`
	MCPSigningKID      string        `envconfig:"MCP_SIGNING_KID"`
	MCPEncKey          string        `envconfig:"MCP_ENC_KEY"`
	MCPAccessTokenTTL  time.Duration `envconfig:"MCP_ACCESS_TOKEN_TTL" default:"15m"`
	MCPRefreshTokenTTL time.Duration `envconfig:"MCP_REFRESH_TOKEN_TTL" default:"8h"`
	MCPCodeTTL         time.Duration `envconfig:"MCP_CODE_TTL" default:"60s"`
	MCPAuthReqTTL      time.Duration `envconfig:"MCP_AUTHREQ_TTL" default:"5m"`
	MCPScopesSupported []string      `envconfig:"MCP_SCOPES_SUPPORTED" default:"mcp"`
}

// brandColorRe accepts CSS hex colors (#rgb, #rgba, #rrggbb, #rrggbbaa).
// Anything else falls back to the default to avoid leaking arbitrary
// strings into the rendered <style> block.
var brandColorRe = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)

func Load() (Config, error) {
	var c Config
	if err := envconfig.Process("", &c); err != nil {
		return c, err
	}
	// `openid` is mandatory per OIDC spec; auto-add if the user dropped it.
	if !slices.Contains(strings.Fields(c.Scopes), "openid") {
		c.Scopes = "openid " + strings.TrimSpace(c.Scopes)
	}
	// Normalize allowlists for case-insensitive comparison.
	for i, e := range c.AllowedEmails {
		c.AllowedEmails[i] = strings.ToLower(strings.TrimSpace(e))
	}
	for i, d := range c.AllowedDomains {
		c.AllowedDomains[i] = strings.ToLower(strings.TrimSpace(d))
	}
	if !brandColorRe.MatchString(c.BrandColor) {
		c.BrandColor = defaultBrandColor
	}
	// Normalize advertised MCP scopes; drop blanks so metadata/PRM/tokens agree.
	c.MCPScopesSupported = normalizeScopes(c.MCPScopesSupported)
	if err := c.validateMCP(); err != nil {
		return c, err
	}
	return c, nil
}

func normalizeScopes(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// validateMCP fails fast on an incomplete MCP configuration. When the feature
// is enabled the issuer, resource, and a signing key are load-bearing security
// boundaries (see internal/mcpauth); a half-configured AS must not boot.
func (c *Config) validateMCP() error {
	if !c.MCPEnabled {
		return nil
	}
	if c.MCPIssuer == "" {
		return fmt.Errorf("MCP_ENABLED=true requires MCP_ISSUER")
	}
	if c.MCPResource == "" {
		return fmt.Errorf("MCP_ENABLED=true requires MCP_RESOURCE")
	}
	if c.MCPSigningKey == "" && c.MCPSigningKeyFile == "" {
		return fmt.Errorf("MCP_ENABLED=true requires MCP_SIGNING_KEY or MCP_SIGNING_KEY_FILE")
	}
	if len(c.MCPScopesSupported) == 0 {
		return fmt.Errorf("MCP_SCOPES_SUPPORTED must list at least one scope")
	}
	return nil
}
