package config

import (
	"regexp"
	"slices"
	"strings"

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
	return c, nil
}
