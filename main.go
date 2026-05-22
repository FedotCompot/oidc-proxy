package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
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

// VerifiedToken carries the claims extracted from a verified ID token. The
// struct is small on purpose: it isolates the handlers from go-oidc and lets
// tests build a stub verifier without going through real JWT parsing.
type VerifiedToken struct {
	Subject string
	Email   string
	Nonce   string
	Expiry  time.Time
}

func wrapVerifier(v *oidc.IDTokenVerifier) func(context.Context, string) (*VerifiedToken, error) {
	return func(ctx context.Context, token string) (*VerifiedToken, error) {
		idTok, err := v.Verify(ctx, token)
		if err != nil {
			return nil, err
		}
		var claims struct {
			Email string `json:"email"`
		}
		_ = idTok.Claims(&claims)
		return &VerifiedToken{
			Subject: idTok.Subject,
			Email:   claims.Email,
			Nonce:   idTok.Nonce,
			Expiry:  idTok.Expiry,
		}, nil
	}
}

type Server struct {
	cfg      Config
	provider *oidc.Provider
	verifyFn func(ctx context.Context, token string) (*VerifiedToken, error)
}

func loadConfig() (Config, error) {
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

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		log.Fatalf("oidc discovery (%s): %v", cfg.Issuer, err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	cache := newTokenCache(cfg.VerifyCacheSize)
	s := &Server{
		cfg:      cfg,
		provider: provider,
		verifyFn: withCache(wrapVerifier(verifier), cache),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/oauth2/sign_in", s.handleSignIn)
	mux.HandleFunc("/oauth2/start", s.handleStart)
	mux.HandleFunc("/oauth2/callback", s.handleCallback)
	mux.HandleFunc("/oauth2/refresh", s.handleRefresh)
	mux.HandleFunc("/oauth2/session", s.handleSession)
	mux.HandleFunc("/oauth2/sign_out", s.handleSignOut)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("oidc-proxy listening on %s (issuer=%s, client_id=%s)", cfg.ListenAddr, cfg.Issuer, cfg.ClientID)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}
