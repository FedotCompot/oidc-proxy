package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	Issuer         string
	ClientID       string
	Scopes         []string
	AllowedEmails  map[string]bool
	AllowedDomains map[string]bool
	CookiePrefix   string
	CookieDomain   string
	CookieSecure   bool
	ListenAddr     string
	SignInTitle    string
	SignInButton   string
}

// VerifiedToken carries the claims extracted from a verified ID token. The
// struct is small on purpose: it isolates the handlers from go-oidc and lets
// tests build a stub verifier without going through real JWT parsing.
type VerifiedToken struct {
	Subject string
	Email   string
	Nonce   string
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
		}, nil
	}
}

type Server struct {
	cfg       Config
	provider  *oidc.Provider
	verifyFn  func(ctx context.Context, token string) (*VerifiedToken, error)
	endpoints oauth2.Endpoint
}

func loadConfig() (Config, error) {
	c := Config{
		Issuer:       os.Getenv("OIDC_ISSUER"),
		ClientID:     os.Getenv("OIDC_CLIENT_ID"),
		CookiePrefix: getenv("COOKIE_NAME_PREFIX", "_oidc_proxy"),
		CookieDomain: os.Getenv("COOKIE_DOMAIN"),
		CookieSecure: getenvBool("COOKIE_SECURE", true),
		ListenAddr:   getenv("LISTEN_ADDR", ":8080"),
		SignInTitle:  getenv("SIGN_IN_TITLE", "Sign in"),
		SignInButton: getenv("SIGN_IN_BUTTON", "Sign in with SSO"),
	}
	if c.Issuer == "" {
		return c, errors.New("OIDC_ISSUER is required")
	}
	if c.ClientID == "" {
		return c, errors.New("OIDC_CLIENT_ID is required")
	}

	scopes := getenv("OIDC_SCOPES", "openid profile email")
	c.Scopes = strings.Fields(scopes)
	hasOpenid := false
	for _, s := range c.Scopes {
		if s == "openid" {
			hasOpenid = true
			break
		}
	}
	if !hasOpenid {
		c.Scopes = append([]string{"openid"}, c.Scopes...)
	}

	c.AllowedEmails = parseSet(os.Getenv("ALLOWED_EMAILS"))
	c.AllowedDomains = parseSet(os.Getenv("ALLOWED_DOMAINS"))

	return c, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}

func parseSet(s string) map[string]bool {
	if s == "" {
		return nil
	}
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out[p] = true
		}
	}
	return out
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
	s := &Server{
		cfg:       cfg,
		provider:  provider,
		verifyFn:  wrapVerifier(verifier),
		endpoints: provider.Endpoint(),
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
