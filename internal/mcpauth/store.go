package mcpauth

import (
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// ReplayGuard records artifact identifiers (jti) that have been consumed so a
// single-use artifact (authorization code, rotated refresh token) can be
// rejected on a second presentation.
//
// The default implementation is per-process (see MemoryReplayGuard): it is
// best-effort across a multi-replica Deployment and is NOT a theft defense —
// a code or refresh token replayed against a *different* replica than the one
// that first saw it will not be caught. Strict single-use and refresh-reuse
// theft detection require a shared store (e.g. Redis) behind this interface;
// that is a documented follow-up. The real code-replay defenses are PKCE, the
// exact redirect_uri match, and the short code TTL.
type ReplayGuard interface {
	// SeenBefore records jti (retained for ttl) and reports whether it was
	// already present. The first call for a given jti returns false; any
	// subsequent call within the TTL returns true.
	SeenBefore(jti string, ttl time.Duration) bool
}

// MemoryReplayGuard is an in-process ReplayGuard backed by a TTL cache. It
// mirrors the eviction discipline of internal/cache: entries expire on their
// own TTL and never outlive the artifact they guard.
type MemoryReplayGuard struct {
	c *ttlcache.Cache[string, struct{}]
}

// NewMemoryReplayGuard returns a ReplayGuard that remembers up to maxSize jtis
// with LRU eviction. maxSize should comfortably exceed the number of codes and
// refresh tokens issued within their (short) lifetimes.
//
// Like internal/cache, this deliberately runs no background janitor goroutine:
// capacity-bounded LRU caps memory, and SeenBefore treats an expired-but-not-
// yet-evicted entry as absent via IsExpired().
func NewMemoryReplayGuard(maxSize int) *MemoryReplayGuard {
	c := ttlcache.New(
		ttlcache.WithCapacity[string, struct{}](uint64(maxSize)),
		ttlcache.WithDisableTouchOnHit[string, struct{}](),
	)
	return &MemoryReplayGuard{c: c}
}

// SeenBefore is safe for concurrent use: ttlcache guards its own map, and the
// get-then-set race only widens the window in which two concurrent redemptions
// of the same jti could both observe "not seen" — acceptable for a best-effort
// guard whose real backstops are PKCE and short TTLs.
func (g *MemoryReplayGuard) SeenBefore(jti string, ttl time.Duration) bool {
	if item := g.c.Get(jti); item != nil && !item.IsExpired() {
		return true
	}
	g.c.Set(jti, struct{}{}, ttl)
	return false
}
