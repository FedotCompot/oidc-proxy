package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	Issuer        string
	ClientID      string
	Scopes        []string
	AllowedEmails map[string]bool
	AllowedDomains map[string]bool
	CookiePrefix  string
	CookieDomain  string
	CookieSecure  bool
	CookieKey     []byte
	ListenAddr    string
	SignInTitle   string
	SignInButton  string
}

type Server struct {
	cfg       Config
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
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

	if secret := os.Getenv("COOKIE_SECRET"); secret != "" {
		key, err := decodeKey(secret)
		if err != nil {
			return c, fmt.Errorf("COOKIE_SECRET: %w", err)
		}
		c.CookieKey = key
	} else {
		c.CookieKey = make([]byte, 32)
		if _, err := rand.Read(c.CookieKey); err != nil {
			return c, fmt.Errorf("generate cookie key: %w", err)
		}
		log.Printf("warning: COOKIE_SECRET not set; using ephemeral key (sessions invalidated on restart)")
	}

	return c, nil
}

func decodeKey(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if k, err := dec(s); err == nil && (len(k) == 16 || len(k) == 24 || len(k) == 32) {
			return k, nil
		}
	}
	h := sha256.Sum256([]byte(s))
	return h[:], nil
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

	s := &Server{
		cfg:       cfg,
		provider:  provider,
		verifier:  provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		endpoints: provider.Endpoint(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/oauth2/sign_in", s.handleSignIn)
	mux.HandleFunc("/oauth2/start", s.handleStart)
	mux.HandleFunc("/oauth2/callback", s.handleCallback)
	mux.HandleFunc("/oauth2/refresh", s.handleRefresh)
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
