package console

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ReadStore is the console's database client. It holds three pgxpools,
// one per Postgres role:
//
//   - TenantPool (tenant_reader): RLS-scoped queries for developer + IT
//   - VendorPool (vendor_reader): cross-tenant queries for OpenScope engineer
//     — has ZERO GRANT on sensitive.* schema
//   - AdminPool  (openscope_admin): used by /admin/* for key minting
//
// The privacy boundary is enforced at the DB level: any query attempted on
// the VendorPool against sensitive.* returns "permission denied for schema
// sensitive" from Postgres, regardless of what the Go code tried to do.
type ReadStore struct {
	TenantPool *pgxpool.Pool
	VendorPool *pgxpool.Pool
	AdminPool  *pgxpool.Pool
}

// PoolConfig holds the three DSNs.
type PoolConfig struct {
	TenantDSN string // postgres://tenant_reader:...@.../openscope
	VendorDSN string // postgres://vendor_reader:...@.../openscope
	AdminDSN  string // postgres://openscope_admin:...@.../openscope
}

func NewReadStore(ctx context.Context, cfg PoolConfig) (*ReadStore, error) {
	open := func(label, dsn string) (*pgxpool.Pool, error) {
		pcfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			return nil, fmt.Errorf("%s parse: %w", label, err)
		}
		pcfg.MaxConns = 8
		pcfg.MinConns = 1
		p, err := pgxpool.NewWithConfig(ctx, pcfg)
		if err != nil {
			return nil, fmt.Errorf("%s open: %w", label, err)
		}
		if err := p.Ping(ctx); err != nil {
			p.Close()
			return nil, fmt.Errorf("%s ping: %w", label, err)
		}
		return p, nil
	}
	tp, err := open("tenant_reader", cfg.TenantDSN)
	if err != nil {
		return nil, err
	}
	vp, err := open("vendor_reader", cfg.VendorDSN)
	if err != nil {
		tp.Close()
		return nil, err
	}
	ap, err := open("admin", cfg.AdminDSN)
	if err != nil {
		tp.Close()
		vp.Close()
		return nil, err
	}
	return &ReadStore{TenantPool: tp, VendorPool: vp, AdminPool: ap}, nil
}

// DemoCodeRow is what LookupDemoCode returns when a code resolves.
type DemoCodeRow struct {
	Code           string
	TenantID       uuid.UUID
	Role           string
	APIKeyID       uuid.UUID
	PlaintextToken string
}

// LookupDemoCode returns the row for an active (not revoked, not expired)
// demo code, or (nil, nil) if no match. Best-effort touches last_used_at
// when the lookup succeeds.
func (s *ReadStore) LookupDemoCode(ctx context.Context, code string) (*DemoCodeRow, error) {
	var d DemoCodeRow
	err := s.AdminPool.QueryRow(ctx, `
		SELECT code, tenant_id, role, api_key_id, plaintext_token
		FROM app.demo_codes
		WHERE code = $1
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > now())`, code).
		Scan(&d.Code, &d.TenantID, &d.Role, &d.APIKeyID, &d.PlaintextToken)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	_, _ = s.AdminPool.Exec(ctx, `UPDATE app.demo_codes SET last_used_at = now() WHERE code = $1`, code)
	return &d, nil
}

func (s *ReadStore) Close() {
	if s.TenantPool != nil {
		s.TenantPool.Close()
	}
	if s.VendorPool != nil {
		s.VendorPool.Close()
	}
	if s.AdminPool != nil {
		s.AdminPool.Close()
	}
}

// asTenant runs fn inside a transaction with `app.tenant_id` set to
// tenantID via `set_config(..., is_local=true)`. RLS policies on the
// tenanted tables then scope every SELECT inside fn to that tenant.
//
// Why set_config and not `SET LOCAL`: Postgres rejects parameterized
// placeholders in SET — only literals. set_config(setting_name, value,
// is_local) is the parameterizable equivalent and acts identically to
// SET LOCAL when is_local=true. (Without this, we'd have to string-format
// the UUID into the SET LOCAL statement, which Postgres-injection-wise
// is safe but vexing.)
func (s *ReadStore) asTenant(ctx context.Context, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
	tx, err := s.TenantPool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID.String()); err != nil {
		return err
	}
	return fn(tx)
}

// --- Tenanted reads (RLS-scoped via tenant_reader + app.tenant_id) ---

type RouterEventRow struct {
	TS         string   `json:"ts"`
	RequestID  string   `json:"request_id"`
	Role       string   `json:"role"`
	Endpoint   string   `json:"endpoint"`
	Model      string   `json:"model,omitempty"`
	ModelLabel string   `json:"model_label,omitempty"` // derived: human label, e.g. "Claude Haiku 4.5"
	Provider   string   `json:"provider,omitempty"`    // derived: "AWS Bedrock"
	Region     string   `json:"region,omitempty"`      // derived: serving region, e.g. "us-west-2"
	Decision   string   `json:"decision"`
	Result     string   `json:"result"`
	Reason     string   `json:"reason,omitempty"`
	DLPRuleIDs []string `json:"dlp_rule_ids,omitempty"`
	BytesIn    int      `json:"bytes_in"`
	BytesOut   int      `json:"bytes_out"`
}

func (s *ReadStore) ListRouterEventsForTenant(ctx context.Context, tenantID uuid.UUID, limit int) ([]RouterEventRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var rows []RouterEventRow
	err := s.asTenant(ctx, tenantID, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `
			SELECT ts::text, request_id::text, role, endpoint, COALESCE(model,''),
			       decision, result, COALESCE(reason,''),
			       COALESCE(dlp_rule_ids, ARRAY[]::text[]),
			       COALESCE(bytes_in,0), COALESCE(bytes_out,0)
			FROM app.router_events
			ORDER BY ts DESC
			LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var e RouterEventRow
			if err := r.Scan(&e.TS, &e.RequestID, &e.Role, &e.Endpoint, &e.Model,
				&e.Decision, &e.Result, &e.Reason, &e.DLPRuleIDs,
				&e.BytesIn, &e.BytesOut); err != nil {
				return err
			}
			rows = append(rows, e)
		}
		return r.Err()
	})
	return rows, err
}

type UsageSummaryRow struct {
	Calls         int     `json:"calls"`
	InputTokens   int64   `json:"input_tokens"`
	OutputTokens  int64   `json:"output_tokens"`
	TotalCostUSD  float64 `json:"total_cost_usd"`
	MonthlyCapUSD float64 `json:"monthly_cap_usd"`
}

// MonthlyUsageForTenant returns the aggregated usage for the current
// calendar month. Used by the IT dashboard's spend display.
func (s *ReadStore) MonthlyUsageForTenant(ctx context.Context, tenantID uuid.UUID, cap float64) (*UsageSummaryRow, error) {
	out := &UsageSummaryRow{MonthlyCapUSD: cap}
	err := s.asTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT COUNT(*),
			       COALESCE(SUM(input_tokens),0),
			       COALESCE(SUM(output_tokens),0),
			       COALESCE(SUM(total_cost_usd),0)::float8
			FROM app.usage_metrics
			WHERE ts >= date_trunc('month', now())`).
			Scan(&out.Calls, &out.InputTokens, &out.OutputTokens, &out.TotalCostUSD)
	})
	return out, err
}

// TenantBudget returns the tenant's monthly_budget_usd override, or nil
// when the tenant uses the deployment default.
func (s *ReadStore) TenantBudget(ctx context.Context, tenantID uuid.UUID) (*float64, error) {
	var budget *float64
	err := s.asTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT monthly_budget_usd::float8 FROM app.tenants WHERE id = $1`,
			tenantID).Scan(&budget)
	})
	return budget, err
}

// ModelUsageRow is per-model usage for the current calendar month. Powers
// the dashboards' per-model breakdown (tokens + cost by model, not one flat
// number). Tenants is set only on the cross-tenant (vendor) aggregate.
type ModelUsageRow struct {
	Model        string  `json:"model"`
	Calls        int     `json:"calls"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	Tenants      int     `json:"tenants,omitempty"`
}

// PerModelUsageForTenant returns this month's usage grouped by model for one
// tenant (RLS-scoped via tenant_reader). Models with no calls don't appear —
// the handler zero-fills them from the catalog.
func (s *ReadStore) PerModelUsageForTenant(ctx context.Context, tenantID uuid.UUID) ([]ModelUsageRow, error) {
	var rows []ModelUsageRow
	err := s.asTenant(ctx, tenantID, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `
			SELECT COALESCE(model,''), COUNT(*),
			       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
			       COALESCE(SUM(total_cost_usd),0)::float8
			FROM app.usage_metrics
			WHERE ts >= date_trunc('month', now())
			GROUP BY model`)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var m ModelUsageRow
			if err := r.Scan(&m.Model, &m.Calls, &m.InputTokens, &m.OutputTokens, &m.TotalCostUSD); err != nil {
				return err
			}
			rows = append(rows, m)
		}
		return r.Err()
	})
	return rows, err
}

// PerModelUsageAllTenants returns this month's usage grouped by model across
// ALL tenants (vendor_reader pool — cross-tenant RLS policy USING(true) on
// app.usage_metrics, zero GRANT on sensitive.*). For the OpenScope Ops view:
// per-model metering, never prompt content.
func (s *ReadStore) PerModelUsageAllTenants(ctx context.Context) ([]ModelUsageRow, error) {
	r, err := s.VendorPool.Query(ctx, `
		SELECT COALESCE(model,''), COUNT(*),
		       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
		       COALESCE(SUM(total_cost_usd),0)::float8,
		       COUNT(DISTINCT tenant_id)
		FROM app.usage_metrics
		WHERE ts >= date_trunc('month', now())
		GROUP BY model`)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var rows []ModelUsageRow
	for r.Next() {
		var m ModelUsageRow
		if err := r.Scan(&m.Model, &m.Calls, &m.InputTokens, &m.OutputTokens, &m.TotalCostUSD, &m.Tenants); err != nil {
			return nil, err
		}
		rows = append(rows, m)
	}
	return rows, r.Err()
}

type PromptRow struct {
	TS         string   `json:"ts"`
	RequestID  string   `json:"request_id"`
	PromptText string   `json:"prompt_text"`
	DLPRuleIDs []string `json:"dlp_rule_ids,omitempty"`
}

// ListPromptsForTenant returns prompt bodies for IT review. Reads from
// sensitive.prompt_records — tenant_reader has SELECT GRANT here; the
// vendor_reader pool would error if accidentally used.
func (s *ReadStore) ListPromptsForTenant(ctx context.Context, tenantID uuid.UUID, limit int) ([]PromptRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows []PromptRow
	err := s.asTenant(ctx, tenantID, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `
			SELECT p.ts::text, p.request_id::text, p.prompt_text,
			       COALESCE((SELECT dlp_rule_ids FROM app.router_events WHERE request_id = p.request_id ORDER BY ts DESC LIMIT 1), ARRAY[]::text[])
			FROM sensitive.prompt_records p
			ORDER BY p.ts DESC
			LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var p PromptRow
			if err := r.Scan(&p.TS, &p.RequestID, &p.PromptText, &p.DLPRuleIDs); err != nil {
				return err
			}
			rows = append(rows, p)
		}
		return r.Err()
	})
	return rows, err
}

type ReceiptRow struct {
	TS          string `json:"ts"`
	RequestID   string `json:"request_id"`
	PayloadJSON string `json:"payload"`
	Signature   string `json:"signature"` // base64
	PublicKeyID string `json:"public_key_id"`
}

func (s *ReadStore) ListReceiptsForTenant(ctx context.Context, tenantID uuid.UUID, limit int) ([]ReceiptRow, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var rows []ReceiptRow
	err := s.asTenant(ctx, tenantID, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `
			SELECT ts::text, request_id::text,
			       payload::text,
			       encode(signature, 'base64'),
			       public_key_id
			FROM app.receipts
			ORDER BY ts DESC
			LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var rc ReceiptRow
			if err := r.Scan(&rc.TS, &rc.RequestID, &rc.PayloadJSON, &rc.Signature, &rc.PublicKeyID); err != nil {
				return err
			}
			rows = append(rows, rc)
		}
		return r.Err()
	})
	return rows, err
}

// --- Vendor (cross-tenant) reads via vendor_reader pool ---

type TenantUsageRow struct {
	TenantSlug   string  `json:"tenant_slug"`
	Day          string  `json:"day"`
	Requests     int     `json:"requests"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalCostUSD float64 `json:"total_cost_usd"`
}

// ListVendorDailyUsage reads vendor.tenant_usage_daily — the materialized
// view that the engineer dashboard surfaces. NO prompt or response content
// is in this view (or accessible via the vendor_reader pool, period).
//
// This method demonstrates the privacy boundary: even though the Go code
// "could" attempt to read sensitive.* using vendor_reader, Postgres would
// return permission denied.
func (s *ReadStore) ListVendorDailyUsage(ctx context.Context, limit int) ([]TenantUsageRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	r, err := s.VendorPool.Query(ctx, `
		SELECT tenant_slug, day::text, requests, input_tokens, output_tokens, total_cost_usd::float8
		FROM vendor.tenant_usage_daily
		ORDER BY day DESC, tenant_slug
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var rows []TenantUsageRow
	for r.Next() {
		var u TenantUsageRow
		if err := r.Scan(&u.TenantSlug, &u.Day, &u.Requests, &u.InputTokens, &u.OutputTokens, &u.TotalCostUSD); err != nil {
			return nil, err
		}
		rows = append(rows, u)
	}
	return rows, r.Err()
}

// VerifyVendorCantReadPrompts is the engineer dashboard's "Verify our
// access" proof: tries to SELECT from sensitive.prompt_records using the
// vendor_reader pool. Expected outcome: Postgres returns "permission
// denied for schema sensitive" — the database engine refuses the query.
//
// Returns (nil, nil) if the query unexpectedly succeeded (boundary broken).
// Returns (errString, nil) with the deny message if it correctly failed.
func (s *ReadStore) VerifyVendorCantReadPrompts(ctx context.Context) (string, error) {
	var dummy string
	err := s.VendorPool.QueryRow(ctx, `SELECT prompt_text FROM sensitive.prompt_records LIMIT 1`).Scan(&dummy)
	if err == nil {
		return "", fmt.Errorf("UNEXPECTED: vendor_reader could read sensitive.prompt_records (privacy boundary broken)")
	}
	return err.Error(), nil
}

// PurgeExpiredBodies deletes prompt/response/upload bodies older than the TTL
// from sensitive.*, using the admin pool (openscope_admin holds DELETE;
// app_rw is SELECT/INSERT/UPDATE only). Demo hygiene: content bodies are
// ephemeral, while the metadata audit trail (app.router_events, app.receipts,
// app.usage_metrics) is retained — so the SOC feed, receipts, and per-model
// breakdown keep their history while no tester's prompt/code/env lingers.
// Returns the number of rows removed across the three tables.
func (s *ReadStore) PurgeExpiredBodies(ctx context.Context, olderThan time.Duration) (int64, error) {
	interval := fmt.Sprintf("%d seconds", int(olderThan.Seconds()))
	var total int64

	// response_records has a FK to prompt_records, so delete children first:
	// any response that's itself expired OR whose parent prompt is expired
	// (their ts are written together, so this just guards the boundary case).
	ct, err := s.AdminPool.Exec(ctx, `
		DELETE FROM sensitive.response_records
		WHERE ts < now() - $1::interval
		   OR request_id IN (SELECT request_id FROM sensitive.prompt_records WHERE ts < now() - $1::interval)`,
		interval)
	if err != nil {
		return total, fmt.Errorf("purge response_records: %w", err)
	}
	total += ct.RowsAffected()

	// prompt_records (now unreferenced) + uploaded_documents (independent).
	for _, tbl := range []string{"sensitive.prompt_records", "sensitive.uploaded_documents"} {
		ct, err := s.AdminPool.Exec(ctx,
			"DELETE FROM "+tbl+" WHERE ts < now() - $1::interval", interval)
		if err != nil {
			return total, fmt.Errorf("purge %s: %w", tbl, err)
		}
		total += ct.RowsAffected()
	}
	return total, nil
}

// PurgeAllBodies wipes every prompt/response/upload body immediately (ignores
// TTL). Used once at boot to clear anything captured before retention was in
// place, so the demo starts from a clean slate.
func (s *ReadStore) PurgeAllBodies(ctx context.Context) (int64, error) {
	return s.PurgeExpiredBodies(ctx, 0)
}

// RefreshVendorView refreshes the tenant_usage_daily materialized view.
// Called periodically (every 5 min) by a scheduled task; can also be
// triggered manually for demos via the engineer dashboard.
func (s *ReadStore) RefreshVendorView(ctx context.Context) error {
	_, err := s.AdminPool.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY vendor.tenant_usage_daily")
	if err != nil {
		// Concurrent refresh needs the unique index + at least one prior
		// non-concurrent refresh. Fall back to a plain refresh on first call.
		_, err = s.AdminPool.Exec(ctx, "REFRESH MATERIALIZED VIEW vendor.tenant_usage_daily")
	}
	return err
}
