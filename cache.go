package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// newTokenCache returns a TTL cache keyed by the SHA-256 of the raw JWT,
// holding the verifier's result. Capacity-bounded with LRU eviction;
// per-entry TTL is set to the JWT's own `exp` so an entry can never outlive
// the token it caches. DisableTouchOnHit keeps the expiry absolute — we
// don't want a busy session to extend a cached verification past the
// token's real lifetime.
func newTokenCache(maxSize int) *ttlcache.Cache[string, *VerifiedToken] {
	return ttlcache.New(
		ttlcache.WithCapacity[string, *VerifiedToken](uint64(maxSize)),
		ttlcache.WithDisableTouchOnHit[string, *VerifiedToken](),
	)
}

// cacheKey hashes the raw JWT so we don't keep a copy of the (2–3 KB) token
// in cache memory. SHA-256 collisions on valid JWTs would require breaking
// SHA-256, so we treat the digest as identity.
func cacheKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// withCache wraps a verifier so repeated calls with the same JWT skip
// re-verification. Errors aren't cached — that lets transient failures
// (JWKS fetch hiccups, key rotation in flight) recover on the next call,
// and avoids remembering bad tokens longer than necessary.
func withCache(inner func(context.Context, string) (*VerifiedToken, error), c *ttlcache.Cache[string, *VerifiedToken]) func(context.Context, string) (*VerifiedToken, error) {
	return func(ctx context.Context, token string) (*VerifiedToken, error) {
		key := cacheKey(token)
		if item := c.Get(key); item != nil && !item.IsExpired() {
			return item.Value(), nil
		}
		v, err := inner(ctx, token)
		if err != nil {
			return nil, err
		}
		if ttl := time.Until(v.Expiry); ttl > 0 {
			c.Set(key, v, ttl)
		}
		return v, nil
	}
}
