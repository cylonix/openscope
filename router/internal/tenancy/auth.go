// Package tenancy resolves API tokens to {tenant_id, role} principals.
//
// Token shape:  osk_<role>_<22-char-url-safe-base64-of-16-bytes>
// Storage:      app.api_keys.key_hash = HMAC-SHA256(pepper, token)
// Lookup:       prefix-indexed (first 12 chars), constant-time hmac.Equal
// Cache:        60s in-memory TTL keyed by full token (see cache.go)
//
// The token format and hash scheme live in the shared
// github.com/openscope/openscope/authtoken package so router API keys,
// broker agent tokens, and control-plane deployment tokens are one scheme.
package tenancy

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/openscope/openscope/authtoken"
	"github.com/openscope/openscope/router/internal/store"
)

// PrefixLen is the indexable prefix size — first 12 chars of an osk_* token.
// Stored verbatim in app.api_keys.key_prefix; (tenant_id, key_prefix) is the
// hot-path lookup index.
const PrefixLen = authtoken.PrefixLen

type Principal struct {
	KeyID    uuid.UUID
	TenantID uuid.UUID
	Role     string
}

// KeyStore is the subset of store.Store this package needs. *store.Store
// satisfies it. Importing store directly (rather than an adapter) keeps
// the wiring simple; tenancy → store is the one-way dependency, no cycle.
type KeyStore interface {
	LookupAPIKeyByPrefix(ctx context.Context, prefix string) ([]*store.APIKeyRow, error)
	TouchAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error
}

var (
	ErrInvalidKey = errors.New("invalid api key")
	ErrBadPepper  = errors.New("auth pepper must be non-empty")
)

type Resolver struct {
	store    KeyStore
	pepper   []byte
	cache    *cache
	cacheTTL time.Duration
}

func New(store KeyStore, pepper []byte, ttl time.Duration) (*Resolver, error) {
	if len(pepper) == 0 {
		return nil, ErrBadPepper
	}
	return &Resolver{
		store:    store,
		pepper:   pepper,
		cache:    newCache(),
		cacheTTL: ttl,
	}, nil
}

// Resolve parses an Authorization header (`Bearer osk_<role>_<suffix>`) and
// returns the Principal. Returns ErrInvalidKey for any failure: malformed
// token, unknown prefix, hash mismatch, expired, revoked.
func (r *Resolver) Resolve(ctx context.Context, authHeader string) (Principal, error) {
	token, ok := authtoken.ParseBearer(authHeader)
	if !ok {
		return Principal{}, ErrInvalidKey
	}

	// Cache hit avoids both DB lookup and HMAC computation.
	if p, ok := r.cache.get(token); ok {
		return p, nil
	}

	if len(token) < PrefixLen {
		return Principal{}, ErrInvalidKey
	}
	prefix := token[:PrefixLen]
	rows, err := r.store.LookupAPIKeyByPrefix(ctx, prefix)
	if err != nil {
		return Principal{}, ErrInvalidKey
	}

	// Multiple rows can share a prefix because PrefixLen=12 catches everything
	// up to "osk_develope" / "osk_engineer" etc. HMAC-compare every candidate;
	// the first match wins. Walking the full list keeps the timing oblivious
	// across the {match-on-1st, match-on-Nth, no-match} cases.
	expected := r.computeHash(token)
	var matched *store.APIKeyRow
	for _, row := range rows {
		if hmac.Equal(expected, row.KeyHash) && matched == nil {
			matched = row
		}
	}
	if matched == nil {
		return Principal{}, ErrInvalidKey
	}

	p := Principal{KeyID: matched.ID, TenantID: matched.TenantID, Role: matched.Role}
	r.cache.set(token, p, time.Now().Add(r.cacheTTL))

	// Best-effort last_used_at update — never blocks the request path.
	go func(id uuid.UUID) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.store.TouchAPIKeyLastUsed(ctx, id)
	}(matched.ID)

	return p, nil
}

func (r *Resolver) computeHash(token string) []byte {
	return authtoken.HashToken(token, r.pepper)
}

// ValidRoles is enforced both at mint time (Mint refuses unknown values)
// and at DB-schema time (app.api_keys.role CHECK constraint).
var ValidRoles = map[string]bool{
	"developer": true,
	"it":        true,
	"engineer":  true,
	"admin":     true,
}

// Mint generates a new token for the given role, computing its prefix and
// HMAC hash with the given pepper. Returns the full token (show once to
// recipient), the prefix (stored in DB for indexed lookup), and the hash.
//
// Suffix is 22 url-safe-base64 chars carrying 128 bits of entropy from 16
// random bytes. With role and "osk_" prefix the full token is ~32-34 chars.
func Mint(role string, pepper []byte) (token, prefix string, hash []byte, err error) {
	if !ValidRoles[role] {
		return "", "", nil, fmt.Errorf("invalid role %q (want developer|it|engineer|admin)", role)
	}
	return authtoken.Mint(role, pepper)
}
