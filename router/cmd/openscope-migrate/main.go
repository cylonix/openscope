// openscope-migrate — applies the embedded SQL migrations to Postgres.
//
// Tracks applied versions in app.schema_migrations and applies pending
// files in lexical order. The migration files are idempotent (IF NOT
// EXISTS), so adopting the version table on an already-migrated database
// is safe — every file simply runs once more, changing nothing, and is
// then recorded.
//
//	OPENSCOPE_ADMIN_DSN (or OPENSCOPE_DATABASE_URL) — connection string
//	--set-dev-passwords — set the local-dev role passwords (NEVER in prod;
//	                      production uses IAM auth / managed secrets)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/openscope/openscope/router/db/migrations"
)

func main() {
	setDevPasswords := flag.Bool("set-dev-passwords", false, "set local-dev passwords for app_rw/tenant_reader/vendor_reader (dev only)")
	flag.Parse()

	dsn := os.Getenv("OPENSCOPE_ADMIN_DSN")
	if dsn == "" {
		dsn = os.Getenv("OPENSCOPE_DATABASE_URL")
	}
	if dsn == "" {
		log.Fatal("OPENSCOPE_ADMIN_DSN or OPENSCOPE_DATABASE_URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		log.Fatalf("parse DSN: %v", err)
	}
	// Simple protocol: migration files contain multiple statements (and
	// their own BEGIN/COMMIT).
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, `
		CREATE SCHEMA IF NOT EXISTS app;
		CREATE TABLE IF NOT EXISTS app.schema_migrations (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		log.Fatalf("ensure schema_migrations: %v", err)
	}

	applied := map[string]bool{}
	rows, err := conn.Query(ctx, `SELECT version FROM app.schema_migrations`)
	if err != nil {
		log.Fatalf("read schema_migrations: %v", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			log.Fatalf("scan: %v", err)
		}
		applied[v] = true
	}
	if rows.Err() != nil {
		log.Fatalf("read schema_migrations: %v", rows.Err())
	}

	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		log.Fatalf("read embedded migrations: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	ran := 0
	for _, name := range names {
		if applied[name] {
			continue
		}
		sql, err := migrations.FS.ReadFile(name)
		if err != nil {
			log.Fatalf("read %s: %v", name, err)
		}
		log.Printf("applying %s", name)
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			log.Fatalf("apply %s: %v", name, err)
		}
		if _, err := conn.Exec(ctx,
			`INSERT INTO app.schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, name); err != nil {
			log.Fatalf("record %s: %v", name, err)
		}
		ran++
	}

	if *setDevPasswords {
		log.Printf("setting LOCAL-DEV role passwords (never use in production)")
		if _, err := conn.Exec(ctx, `
			ALTER ROLE app_rw        WITH PASSWORD 'dev_app_rw_password';
			ALTER ROLE tenant_reader WITH PASSWORD 'dev_tenant_reader_password';
			ALTER ROLE vendor_reader WITH PASSWORD 'dev_vendor_reader_password'`); err != nil {
			log.Fatalf("set dev passwords: %v", err)
		}
	}

	fmt.Printf("migrations up to date (%d applied this run, %d total)\n", ran, len(names))
}
