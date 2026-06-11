package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

type APIKeyRow struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	Role       string
	KeyPrefix  string
	KeyHash    []byte
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

var ErrKeyNotFound = errors.New("api key not found")

// LookupAPIKeyByPrefix returns the active (non-revoked, non-expired) key rows
// matching prefix. Multiple matches are possible: tenancy.PrefixLen is 12,
// so every token of the same role shares the same prefix (e.g., "osk_develope"
// for developer). The caller iterates and constant-time HMAC-compares each
// row's KeyHash. Returns an empty slice and ErrKeyNotFound when nothing matches.
//
// Hard cap of 16 rows is defensive — exceeding that means too many active
// keys share a prefix and we should widen PrefixLen anyway.
func (s *Store) LookupAPIKeyByPrefix(ctx context.Context, prefix string) ([]*APIKeyRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, role, key_prefix, key_hash, expires_at, revoked_at, last_used_at
		FROM app.api_keys
		WHERE key_prefix = $1
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > now())
		ORDER BY created_at DESC
		LIMIT 16`, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*APIKeyRow, 0, 4)
	for rows.Next() {
		var k APIKeyRow
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Role, &k.KeyPrefix, &k.KeyHash, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, &k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrKeyNotFound
	}
	return out, nil
}

// TouchAPIKeyLastUsed bumps last_used_at to now(). Best-effort; called from
// a goroutine in pkg/tenancy after a cache miss resolves.
func (s *Store) TouchAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE app.api_keys SET last_used_at = now() WHERE id = $1`, id)
	return err
}

// InsertAPIKey is used by the seed script (and Stage 7's admin endpoint).
// Requires connecting as openscope_admin or app_rw with INSERT privilege.
func (s *Store) InsertAPIKey(ctx context.Context, tenantID uuid.UUID, role, recipientEmail, keyPrefix string, keyHash []byte) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO app.api_keys (tenant_id, role, recipient_email, key_prefix, key_hash)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5)
		RETURNING id`,
		tenantID, role, recipientEmail, keyPrefix, keyHash).Scan(&id)
	return id, err
}

// UpsertTenantBySlug returns an existing tenant ID for the given slug or
// creates a new one. Used by the seed script.
func (s *Store) UpsertTenantBySlug(ctx context.Context, slug, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO app.tenants (slug, name) VALUES ($1, $2)
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, slug, name).Scan(&id)
	return id, err
}
