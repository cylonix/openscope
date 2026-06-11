// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"sync"
	"time"
)

// rateLimiter is a per-key token bucket (key = token prefix, falling back
// to remote IP). Stdlib-only on purpose — the core module stays
// dependency-free. The bucket map is capped; idle entries are evicted so a
// scanner cycling keys can't grow it without bound.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	rate    float64 // tokens added per second
	burst   float64 // bucket capacity
	maxKeys int

	now func() time.Time // injectable for tests
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

func newRateLimiter(ratePerSec, burst float64) *rateLimiter {
	return &rateLimiter{
		buckets: map[string]*bucket{},
		rate:    ratePerSec,
		burst:   burst,
		maxKeys: 4096,
		now:     time.Now,
	}
}

// allow reports whether one request for key fits the budget.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b, ok := rl.buckets[key]
	if !ok {
		if len(rl.buckets) >= rl.maxKeys {
			rl.evictIdle(now)
		}
		b = &bucket{tokens: rl.burst}
		rl.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		b.tokens = min(rl.burst, b.tokens+elapsed*rl.rate)
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictIdle drops buckets idle long enough to be full again (they carry no
// state worth keeping). Called with the lock held.
func (rl *rateLimiter) evictIdle(now time.Time) {
	idle := time.Duration(rl.burst/rl.rate*float64(time.Second)) + time.Minute
	for k, b := range rl.buckets {
		if now.Sub(b.lastSeen) > idle {
			delete(rl.buckets, k)
		}
	}
	// Pathological case: everything is hot. Drop the map rather than grow
	// without bound — brief over-admission beats unbounded memory.
	if len(rl.buckets) >= rl.maxKeys {
		rl.buckets = map[string]*bucket{}
	}
}
