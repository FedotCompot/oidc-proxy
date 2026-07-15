// Package web wires the HTTP-facing pieces of the proxy: routes, handlers,
// session cookies, and the templates used by the browser-side OIDC flow.
package web

import (
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/fedot/oidc-proxy/internal/config"
	"github.com/fedot/oidc-proxy/internal/mcpauth"
	"github.com/fedot/oidc-proxy/internal/token"
)

// Per-IP rate limits for the unauthenticated MCP endpoints.
const (
	registerRateLimit = 20 // per window
	tokenRateLimit    = 120
	rateLimitWindow   = time.Minute
)

type Server struct {
	cfg      config.Config
	provider *oidc.Provider
	verifyFn token.VerifyFunc

	// as is nil unless MCP_ENABLED; MCP routes are only registered when set.
	as           *mcpauth.AS
	regLimiter   *rateLimiter
	tokenLimiter *rateLimiter
}

func NewServer(cfg config.Config, provider *oidc.Provider, verifyFn token.VerifyFunc, as *mcpauth.AS) *Server {
	s := &Server{cfg: cfg, provider: provider, verifyFn: verifyFn, as: as}
	if as != nil {
		s.regLimiter = newRateLimiter(registerRateLimit, rateLimitWindow)
		s.tokenLimiter = newRateLimiter(tokenRateLimit, rateLimitWindow)
	}
	return s
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/oauth2/sign_in", s.handleSignIn)
	mux.HandleFunc("/oauth2/start", s.handleStart)
	mux.HandleFunc("/oauth2/callback", s.handleCallback)
	mux.HandleFunc("/oauth2/refresh", s.handleRefresh)
	mux.HandleFunc("/oauth2/session", s.handleSession)
	mux.HandleFunc("/oauth2/sign_out", s.handleSignOut)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	if s.cfg.MCPEnabled && s.as != nil {
		s.registerMCPRoutes(mux)
	}
	return mux
}

// registerMCPRoutes wires the MCP OAuth 2.1 AS + RS endpoints. The interactive
// endpoints live under /oauth2 (already routed to the proxy by Traefik); only
// the /.well-known discovery paths need a new public route rule (see README).
func (s *Server) registerMCPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleASMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleOIDCConfig)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handlePRM)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{suffix...}", s.handlePRM)
	mux.HandleFunc("GET /oauth2/jwks.json", s.handleJWKS)
	mux.HandleFunc("POST /oauth2/register", s.handleRegister)
	mux.HandleFunc("GET /oauth2/authorize", s.handleAuthorizeGET)
	mux.HandleFunc("POST /oauth2/authorize", s.handleAuthorizePOST)
	mux.HandleFunc("POST /oauth2/token", s.handleToken)
	mux.HandleFunc("/mcp-verify", s.handleMCPVerify)
}
