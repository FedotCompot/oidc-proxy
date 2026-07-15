package mcpauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// randToken returns nBytes of cryptographic randomness as a URL-safe,
// unpadded base64 string. Used for jti, csrf, and refresh-family identifiers.
func randToken(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// VerifyPKCE reports whether verifier matches the stored S256 challenge, i.e.
// BASE64URL(SHA256(verifier)) == challenge. The compare is constant-time. Only
// S256 is ever accepted; the plain method is rejected before we get here.
func VerifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}
