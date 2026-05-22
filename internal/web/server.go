// Package web wires the HTTP-facing pieces of the proxy: routes, handlers,
// session cookies, and the templates used by the browser-side OIDC flow.
package web

import (
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/fedot/oidc-proxy/internal/config"
	"github.com/fedot/oidc-proxy/internal/token"
)

type Server struct {
	cfg      config.Config
	provider *oidc.Provider
	verifyFn token.VerifyFunc
}

func NewServer(cfg config.Config, provider *oidc.Provider, verifyFn token.VerifyFunc) *Server {
	return &Server{cfg: cfg, provider: provider, verifyFn: verifyFn}
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
	return mux
}
