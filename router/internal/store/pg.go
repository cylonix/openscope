// Package store is the Postgres data layer for openscope-router and
// openscope-console. Connection-pool management lives here; each typed
// query lives in its own file (api_keys.go, router_events.go, etc.).
//
// The router connects as app_rw (BYPASSRLS, INSERT/SELECT on app.* and
// sensitive.*). The console connects as tenant_reader (RLS-scoped) or
// vendor_reader (no GRANT on sensitive.*) depending on the request's role.
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

// New opens a Postgres connection pool against the given DSN, pings it
// once to fail fast on bad config, and returns the Store.
func New(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	// MVP defaults; tune for production.
	cfg.MaxConns = 10
	cfg.MinConns = 2

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func (s *Store) Close() { s.pool.Close() }
