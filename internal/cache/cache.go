package cache

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/jellydator/ttlcache/v3"

	"github.com/fedot/oidc-proxy/internal/token"
)

// Cache is the type alias used by the verifier-caching layer; exposed so
// callers can construct one with New() and pass it to Wrap().
type Cache = ttlcache.Cache[string, *token.Verified]

// New returns a TTL cache keyed by the SHA-256 of the raw JWT, holding the
// verifier's result. Capacity-bounded with LRU eviction; per-entry TTL is
// set to the JWT's own `exp` so an entry can never outlive the token it
// caches. DisableTouchOnHit keeps the expiry absolute — we don't want a busy
// session to extend a cached verification past the token's real lifetime.
func New(maxSize int) *Cache {
	return ttlcache.New(
		ttlcache.WithCapacity[string, *token.Verified](uint64(maxSize)),
		ttlcache.WithDisableTouchOnHit[string, *token.Verified](),
	)
}

// key hashes the raw JWT so we don't keep a copy of the (2–3 KB) token in
// cache memory. SHA-256 collisions on valid JWTs would require breaking
// SHA-256, so we treat the digest as identity.
func key(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Wrap returns a verifier that short-circuits repeated calls with the same
// JWT. Errors aren't cached — that lets transient failures (JWKS fetch
// hiccups, key rotation in flight) recover on the next call, and avoids
// remembering bad tokens longer than necessary.
func Wrap(inner token.VerifyFunc, c *Cache) token.VerifyFunc {
	return func(ctx context.Context, tok string) (*token.Verified, error) {
		k := key(tok)
		if item := c.Get(k); item != nil && !item.IsExpired() {
			return item.Value(), nil
		}
		v, err := inner(ctx, tok)
		if err != nil {
			return nil, err
		}
		if ttl := time.Until(v.Expiry); ttl > 0 {
			c.Set(k, v, ttl)
		}
		return v, nil
	}
}
