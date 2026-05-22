package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// Session is the encrypted payload stored in the session cookie.
//
// The access token isn't kept: oidc-proxy doesn't proxy upstream requests,
// so nothing reads it. Dropping it saves ~2KB on Entra and keeps the cookie
// under the 4KB browser limit in most cases.
type Session struct {
	IDToken      string `json:"i,omitempty"`
	RefreshToken string `json:"r,omitempty"`
	Email        string `json:"m,omitempty"`
	Subject      string `json:"s,omitempty"`
}

const (
	sessionCookieSuffix = "_session"
	// cookieChunkSize caps each cookie's value below the 4KB-per-cookie limit
	// most browsers enforce, leaving headroom for the name and attributes.
	cookieChunkSize = 3800
	// maxCookieChunks bounds the loop that reads/clears chunks. 8 chunks of
	// 3800 bytes is ~30KB sealed, which is far more than any sane token set.
	maxCookieChunks = 8
)

func (s *Server) sessionCookieName() string { return s.cfg.CookiePrefix + sessionCookieSuffix }

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

// readSession reassembles the sealed token from one or more chunk cookies
// (`<prefix>_session_0`, `<prefix>_session_1`, …) and decrypts it.
func (s *Server) readSession(r *http.Request) (*Session, error) {
	base := s.sessionCookieName()
	var token string
	for i := 0; i < maxCookieChunks; i++ {
		c, err := r.Cookie(base + "_" + strconv.Itoa(i))
		if err != nil {
			break
		}
		token += c.Value
	}
	if token == "" {
		return nil, http.ErrNoCookie
	}
	var sess Session
	if err := s.openJSON(token, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

// writeSession seals the payload and splits it across `<prefix>_session_N`
// cookies so each stays under the 4KB per-cookie browser limit. It also
// issues delete cookies for any higher-index chunks left over from a larger
// prior session.
func (s *Server) writeSession(w http.ResponseWriter, sess *Session) error {
	token, err := s.sealJSON(sess)
	if err != nil {
		return err
	}
	base := s.sessionCookieName()
	exp := time.Now().Add(30 * 24 * time.Hour)

	chunks := chunkString(token, cookieChunkSize)
	for i, c := range chunks {
		http.SetCookie(w, s.makeCookie(base+"_"+strconv.Itoa(i), c, exp, "/"))
	}
	// Best-effort cleanup of leftover chunks from any prior, larger session.
	for i := len(chunks); i < maxCookieChunks; i++ {
		http.SetCookie(w, s.makeCookie(base+"_"+strconv.Itoa(i), "", time.Unix(0, 0), "/"))
	}
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter) {
	base := s.sessionCookieName()
	for i := 0; i < maxCookieChunks; i++ {
		http.SetCookie(w, s.makeCookie(base+"_"+strconv.Itoa(i), "", time.Unix(0, 0), "/"))
	}
}

func chunkString(s string, n int) []string {
	if len(s) <= n {
		return []string{s}
	}
	out := make([]string, 0, (len(s)+n-1)/n)
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
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
