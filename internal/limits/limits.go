// Package limits provides the abuse-control primitives for a public doublethink
// instance (docs/DESIGN-M2.md decisions 4-6): token-bucket rate limiters keyed by
// an arbitrary string (IP, account, channel), a concurrent-connection counter, and
// the resolution of an effective limit as "per-row override, else default".
//
// It is deliberately dependency-free (stdlib only) and transport-side: it does not
// touch the store or the broker. Time is injected so behaviour is testable without
// real sleeps.
package limits

import (
	"sync"
	"time"
)

// Defaults are the conservative public starting limits (DESIGN-M2.md decision 5).
// All are overridable per channel/account by the admin key; these are the floor a
// caller falls back to when no override exists.
type Defaults struct {
	MaxMessageBytes      int64
	RetainedMsgsPerChan  int
	RetentionTTL         time.Duration
	RetentionTTLMax      time.Duration
	BytesPerChannel      int64
	BytesPerAccount      int64
	ChannelsPerAccount   int
	CreatePerIPPerHour   int
	ConnectionsPerIP     int
	PublishPerChanPerMin int
	PublishPerAcctPerMin int
}

// DefaultLimits returns the documented public defaults.
func DefaultLimits() Defaults {
	return Defaults{
		MaxMessageBytes:      256 * 1024,
		RetainedMsgsPerChan:  1000,
		RetentionTTL:         24 * time.Hour,
		RetentionTTLMax:      7 * 24 * time.Hour,
		BytesPerChannel:      32 * 1024 * 1024,
		BytesPerAccount:      256 * 1024 * 1024,
		ChannelsPerAccount:   100,
		// Channel creation: generous enough for a public instance that hosts a
		// click-to-run demo and serves browsers/PWAs behind shared NAT IPs. Abuse
		// is bounded by the connection cap, message-size cap, and per-account
		// storage quotas, not by a draconian create rate. A tight 10/hour would
		// rate-limit honest reconnects and repeated demo runs (especially when many
		// users share one IP), so the bucket is larger with a bigger burst.
		CreatePerIPPerHour:   120,
		ConnectionsPerIP:     40,
		PublishPerChanPerMin: 60,
		PublishPerAcctPerMin: 600,
	}
}

// now is the clock, overridable in tests.
var now = time.Now

// tokenBucket is a classic token bucket: capacity tokens, refilling at rate per
// second, each Allow consuming one token.
type tokenBucket struct {
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	last       time.Time
}

func (b *tokenBucket) allow(t time.Time) bool {
	// Refill based on elapsed time since last check.
	if b.last.IsZero() {
		b.last = t
	}
	elapsed := t.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.refillRate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = t
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// RateLimiter holds token buckets keyed by an arbitrary string. One limiter
// instance encodes one policy (capacity + refill); callers keep separate limiters
// for create-per-IP, publish-per-channel, etc.
type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*tokenBucket
	capacity   float64
	refillRate float64
}

// NewRateLimiter builds a limiter allowing `burst` immediate events and refilling
// at `perSecond` tokens per second.
func NewRateLimiter(burst int, perSecond float64) *RateLimiter {
	return &RateLimiter{
		buckets:    make(map[string]*tokenBucket),
		capacity:   float64(burst),
		refillRate: perSecond,
	}
}

// NewPerMinute builds a limiter for "n events per minute" with a burst allowance.
func NewPerMinute(perMinute, burst int) *RateLimiter {
	return NewRateLimiter(burst, float64(perMinute)/60.0)
}

// NewPerHour builds a limiter for "n events per hour" with a burst allowance.
func NewPerHour(perHour, burst int) *RateLimiter {
	return NewRateLimiter(burst, float64(perHour)/3600.0)
}

// Allow reports whether an event for `key` is permitted now, consuming a token.
func (r *RateLimiter) Allow(key string) bool {
	t := now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[key]
	if b == nil {
		b = &tokenBucket{capacity: r.capacity, tokens: r.capacity, refillRate: r.refillRate, last: t}
		r.buckets[key] = b
	}
	return b.allow(t)
}

// gc drops buckets that are full again (idle), bounding memory. Callers may invoke
// it periodically; not required for correctness.
func (r *RateLimiter) gc() {
	t := now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, b := range r.buckets {
		// refill to current, then drop if at capacity and idle
		elapsed := t.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.refillRate
			if b.tokens >= b.capacity {
				delete(r.buckets, k)
			}
		}
	}
}

// ConnCounter bounds concurrent connections per key (e.g. per IP).
type ConnCounter struct {
	mu    sync.Mutex
	max   int
	count map[string]int
}

// NewConnCounter caps each key at `max` concurrent connections.
func NewConnCounter(max int) *ConnCounter {
	return &ConnCounter{max: max, count: make(map[string]int)}
}

// Acquire registers a new connection for key, returning false (and registering
// nothing) if the key is already at its cap. On true, the caller MUST call Release.
func (c *ConnCounter) Acquire(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count[key] >= c.max {
		return false
	}
	c.count[key]++
	return true
}

// Release frees one connection for key.
func (c *ConnCounter) Release(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count[key] > 0 {
		c.count[key]--
		if c.count[key] == 0 {
			delete(c.count, key)
		}
	}
}
