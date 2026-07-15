package web

import (
	"sync/atomic"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// rateLimiterMaxKeys bounds the number of tracked client keys. LRU eviction
// caps memory regardless of how many distinct (and spoofable) client IPs show
// up, so a flood of fresh keys can never grow the map without bound.
const rateLimiterMaxKeys = 16384

// rateLimiter is a coarse, fixed-window per-key limiter used to slow abuse of
// the unauthenticated MCP endpoints (/oauth2/register, /oauth2/token). It is a
// speed bump, not a security control: keys are client IPs (utils.ClientIP),
// which are spoofable behind a proxy that appends X-Forwarded-For.
//
// Backed by a capacity-bounded TTL cache (same discipline as internal/cache):
// each key maps to a request counter that lives for one window. Lookups and
// updates are O(1); there is no background goroutine and no full-map scan.
type rateLimiter struct {
	c      *ttlcache.Cache[string, *atomic.Int64]
	limit  int64
	window time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		c: ttlcache.New(
			ttlcache.WithCapacity[string, *atomic.Int64](rateLimiterMaxKeys),
			ttlcache.WithDisableTouchOnHit[string, *atomic.Int64](),
		),
		limit:  int64(limit),
		window: window,
	}
}

// allow records a hit for key and reports whether it is within the limit for
// the current window. A nil receiver always allows (feature disabled).
//
// The window is fixed: the counter's TTL is set once, on the first hit, and is
// not extended by later hits (DisableTouchOnHit), so a sustained flood is
// blocked for the rest of the window rather than resetting it. A rare race
// between two first-hits on the same fresh key can reset the counter to 1 —
// acceptable for a best-effort limiter.
func (rl *rateLimiter) allow(key string) bool {
	if rl == nil {
		return true
	}
	if item := rl.c.Get(key); item != nil && !item.IsExpired() {
		return item.Value().Add(1) <= rl.limit
	}
	n := &atomic.Int64{}
	n.Store(1)
	rl.c.Set(key, n, rl.window)
	return true
}
