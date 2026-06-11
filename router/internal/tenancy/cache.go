package tenancy

import (
	"sync"
	"time"
)

// cache is a simple in-memory TTL map for token→Principal. Lookups are O(1).
// Expired entries are removed lazily on next get (no background sweeper —
// the demo's traffic is low enough that lazy cleanup is sufficient).
type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	p       Principal
	expires time.Time
}

func newCache() *cache {
	return &cache{entries: make(map[string]cacheEntry)}
}

func (c *cache) get(token string) (Principal, bool) {
	c.mu.RLock()
	e, ok := c.entries[token]
	c.mu.RUnlock()
	if !ok {
		return Principal{}, false
	}
	if time.Now().After(e.expires) {
		// Lazy eviction.
		c.mu.Lock()
		// Re-check under write lock to avoid racing with another goroutine
		// that may have inserted a fresh entry in between.
		if cur, still := c.entries[token]; still && time.Now().After(cur.expires) {
			delete(c.entries, token)
		}
		c.mu.Unlock()
		return Principal{}, false
	}
	return e.p, true
}

func (c *cache) set(token string, p Principal, expires time.Time) {
	c.mu.Lock()
	c.entries[token] = cacheEntry{p: p, expires: expires}
	c.mu.Unlock()
}
