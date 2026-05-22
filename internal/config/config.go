package config

import (
	"slices"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

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
	SignInButton    string   `envconfig:"SIGN_IN_BUTTON" default:"Sign in with SSO"`
}

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
	return c, nil
}
