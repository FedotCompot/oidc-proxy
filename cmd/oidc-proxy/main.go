package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/fedot/oidc-proxy/internal/cache"
	"github.com/fedot/oidc-proxy/internal/config"
	"github.com/fedot/oidc-proxy/internal/token"
	"github.com/fedot/oidc-proxy/internal/web"
)

func main() {
	cfg, err := config.Load()
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
	verifyFn := cache.Wrap(token.Wrap(verifier), cache.New(cfg.VerifyCacheSize))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           web.NewServer(cfg, provider, verifyFn).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("oidc-proxy listening on %s (issuer=%s, client_id=%s)", cfg.ListenAddr, cfg.Issuer, cfg.ClientID)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}
