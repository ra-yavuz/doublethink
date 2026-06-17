package limits

import (
	"testing"
	"time"
)

// withClock runs fn with a controllable clock and restores the real one after.
func withClock(t *testing.T, fn func(advance func(time.Duration))) {
	t.Helper()
	base := time.Unix(1_000_000, 0)
	cur := base
	now = func() time.Time { return cur }
	defer func() { now = time.Now }()
	fn(func(d time.Duration) { cur = cur.Add(d) })
}

// Burst is allowed up to capacity, then denied until refill.
func TestRateLimiterBurstThenDeny(t *testing.T) {
	withClock(t, func(advance func(time.Duration)) {
		// 60/min, burst 3.
		r := NewPerMinute(60, 3)
		// 3 immediate allowed.
		for i := 0; i < 3; i++ {
			if !r.Allow("ip1") {
				t.Fatalf("burst event %d denied, should be allowed", i)
			}
		}
		// 4th denied (bucket empty).
		if r.Allow("ip1") {
			t.Fatal("4th event allowed past burst; should be denied")
		}
		// 60/min = 1/sec; after 1s, one token back.
		advance(time.Second)
		if !r.Allow("ip1") {
			t.Fatal("event after 1s refill denied; one token should have refilled")
		}
		if r.Allow("ip1") {
			t.Fatal("second event after only 1s refill allowed; should be denied")
		}
	})
}

// Different keys have independent buckets.
func TestRateLimiterPerKey(t *testing.T) {
	withClock(t, func(advance func(time.Duration)) {
		r := NewPerMinute(60, 1)
		if !r.Allow("a") {
			t.Fatal("first for a denied")
		}
		if !r.Allow("b") {
			t.Fatal("first for b denied; keys must be independent")
		}
		if r.Allow("a") {
			t.Fatal("second for a allowed; a's bucket should be empty")
		}
	})
}

// Per-hour limiter refills slowly.
func TestPerHour(t *testing.T) {
	withClock(t, func(advance func(time.Duration)) {
		r := NewPerHour(10, 3) // 10/hour, burst 3
		for i := 0; i < 3; i++ {
			if !r.Allow("ip") {
				t.Fatalf("burst %d denied", i)
			}
		}
		if r.Allow("ip") {
			t.Fatal("past burst allowed")
		}
		// 10/hour = 1 per 360s. After 360s, one token.
		advance(360 * time.Second)
		if !r.Allow("ip") {
			t.Fatal("after 360s no refill; expected one token")
		}
	})
}

// Connection counter caps concurrent connections and releases.
func TestConnCounter(t *testing.T) {
	c := NewConnCounter(2)
	if !c.Acquire("ip") {
		t.Fatal("1st acquire denied")
	}
	if !c.Acquire("ip") {
		t.Fatal("2nd acquire denied")
	}
	if c.Acquire("ip") {
		t.Fatal("3rd acquire allowed past cap of 2")
	}
	c.Release("ip")
	if !c.Acquire("ip") {
		t.Fatal("acquire after release denied; a slot should have freed")
	}
	// A different IP is independent.
	if !c.Acquire("other") {
		t.Fatal("different IP denied; keys must be independent")
	}
}

// Releasing more than acquired does not underflow / panic.
func TestConnCounterReleaseUnderflow(t *testing.T) {
	c := NewConnCounter(1)
	c.Release("never-acquired") // must not panic or go negative
	if !c.Acquire("never-acquired") {
		t.Fatal("acquire after spurious release denied")
	}
}

func TestDefaultLimitsSane(t *testing.T) {
	d := DefaultLimits()
	if d.MaxMessageBytes <= 0 || d.RetentionTTL <= 0 || d.RetentionTTLMax < d.RetentionTTL {
		t.Fatalf("default limits look wrong: %+v", d)
	}
}
