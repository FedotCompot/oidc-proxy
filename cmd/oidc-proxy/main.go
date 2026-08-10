package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/fedot/oidc-proxy/internal/cache"
	"github.com/fedot/oidc-proxy/internal/config"
	"github.com/fedot/oidc-proxy/internal/mcpauth"
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

	as, err := buildAS(cfg)
	if err != nil {
		log.Fatalf("mcp: %v", err)
	}
	if as != nil {
		log.Printf("mcp AS enabled (issuer=%s, resource=%s, kid=%s, cimd=%t)",
			as.Issuer, as.Resource, as.KID(), as.CIMDEnabled())
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           web.NewServer(cfg, provider, verifyFn, as).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("oidc-proxy listening on %s (issuer=%s, client_id=%s)", cfg.ListenAddr, cfg.Issuer, cfg.ClientID)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}

// buildAS constructs the MCP Authorization Server from config, or returns
// (nil, nil) when the feature is disabled. The signing key is read from
// MCP_SIGNING_KEY (inline PEM) or MCP_SIGNING_KEY_FILE; config.Load already
// guaranteed one of them is set when enabled.
func buildAS(cfg config.Config) (*mcpauth.AS, error) {
	if !cfg.MCPEnabled {
		return nil, nil
	}
	signingPEM := cfg.MCPSigningKey
	if signingPEM == "" && cfg.MCPSigningKeyFile != "" {
		b, err := os.ReadFile(cfg.MCPSigningKeyFile)
		if err != nil {
			return nil, err
		}
		signingPEM = string(b)
	}
	return mcpauth.New(mcpauth.Options{
		Issuer:          cfg.MCPIssuer,
		Resource:        cfg.MCPResource,
		ResourceDocs:    cfg.MCPResourceDocs,
		ScopesSupported: cfg.MCPScopesSupported,
		RequiredScopes:  cfg.MCPRequiredScopes,
		SigningKeyPEM:   signingPEM,
		SigningKID:      cfg.MCPSigningKID,
		EncKeyB64:       cfg.MCPEncKey,
		AccessTTL:       cfg.MCPAccessTokenTTL,
		RefreshTTL:      cfg.MCPRefreshTokenTTL,
		CodeTTL:         cfg.MCPCodeTTL,
		AuthReqTTL:      cfg.MCPAuthReqTTL,
		CIMD: mcpauth.CIMDOptions{
			Enabled:           cfg.MCPCIMDEnabled,
			AllowedHosts:      cfg.MCPCIMDAllowedHosts,
			AllowPrivateHosts: cfg.MCPCIMDAllowPrivate,
			CacheTTL:          cfg.MCPCIMDCacheTTL,
			CacheSize:         cfg.MCPCIMDCacheSize,
			Timeout:           cfg.MCPCIMDTimeout,
		},
	})
}
