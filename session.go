package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Session is the encrypted payload stored in the session cookie.
type Session struct {
	AccessToken  string    `json:"a,omitempty"`
	IDToken      string    `json:"i,omitempty"`
	RefreshToken string    `json:"r,omitempty"`
	Expiry       time.Time `json:"e,omitempty"`
	Email        string    `json:"m,omitempty"`
	Subject      string    `json:"s,omitempty"`
}

// flowState is the short-lived payload stored during the OIDC redirect dance.
type flowState struct {
	State        string `json:"s"`
	CodeVerifier string `json:"v"`
	Nonce        string `json:"n"`
	Redirect     string `json:"r"`
	RedirectURI  string `json:"u"`
}

const (
	sessionCookieSuffix = "_session"
	flowCookieSuffix    = "_flow"
)

func (s *Server) sessionCookieName() string { return s.cfg.CookiePrefix + sessionCookieSuffix }
func (s *Server) flowCookieName() string    { return s.cfg.CookiePrefix + flowCookieSuffix }

func (s *Server) sealJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.cfg.CookieKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, raw, nil)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func (s *Server) openJSON(token string, v any) error {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(s.cfg.CookieKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(data) < gcm.NonceSize() {
		return errors.New("ciphertext too short")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	raw, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (s *Server) readSession(r *http.Request) (*Session, error) {
	c, err := r.Cookie(s.sessionCookieName())
	if err != nil {
		return nil, err
	}
	var sess Session
	if err := s.openJSON(c.Value, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Server) writeSession(w http.ResponseWriter, sess *Session) error {
	token, err := s.sealJSON(sess)
	if err != nil {
		return err
	}
	// Long-lived: the cookie is encrypted and the access token's own expiry is
	// what gates access. Bound to ~30 days to keep cookies from living forever.
	exp := time.Now().Add(30 * 24 * time.Hour)
	http.SetCookie(w, s.makeCookie(s.sessionCookieName(), token, exp, "/"))
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, s.makeCookie(s.sessionCookieName(), "", time.Unix(0, 0), "/"))
}

func (s *Server) writeFlow(w http.ResponseWriter, f *flowState) error {
	token, err := s.sealJSON(f)
	if err != nil {
		return err
	}
	exp := time.Now().Add(10 * time.Minute)
	http.SetCookie(w, s.makeCookie(s.flowCookieName(), token, exp, "/oauth2"))
	return nil
}

func (s *Server) readFlow(r *http.Request) (*flowState, error) {
	c, err := r.Cookie(s.flowCookieName())
	if err != nil {
		return nil, err
	}
	var f flowState
	if err := s.openJSON(c.Value, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (s *Server) clearFlow(w http.ResponseWriter) {
	http.SetCookie(w, s.makeCookie(s.flowCookieName(), "", time.Unix(0, 0), "/oauth2"))
}

func (s *Server) makeCookie(name, value string, expires time.Time, path string) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   s.cfg.CookieDomain,
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	if value == "" {
		c.MaxAge = -1
	}
	return c
}

func randURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

