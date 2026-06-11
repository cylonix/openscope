package console

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/openscope/openscope/router/internal/tenancy"
)

// AdminToken authenticates the founder's admin endpoints. Static bearer
// token loaded from OPENSCOPE_ADMIN_TOKEN. Separate auth path from the
// role-scoped session cookies — admins don't get cookies.
type AdminToken string

func (t AdminToken) check(r *http.Request) bool {
	if t == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	got := strings.TrimPrefix(auth, "Bearer ")
	return got == string(t)
}

// AdminServer wires the /api/v1/admin/* endpoints. Mounted on the same
// http.ServeMux as the regular console routes.
type AdminServer struct {
	Token      AdminToken
	Read       *ReadStore // uses AdminPool for inserts
	AuthPepper []byte     // for minting tokens via tenancy.Mint
}

func (a *AdminServer) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/admin/keys", a.handleMintKey)
	mux.HandleFunc("GET  /api/v1/admin/keys", a.handleListKeys)
	mux.HandleFunc("POST /api/v1/admin/keys/revoke", a.handleRevokeKey)
	mux.HandleFunc("POST /api/v1/admin/tenants", a.handleCreateTenant)
	mux.HandleFunc("GET  /api/v1/admin/tenants", a.handleListTenants)
	mux.HandleFunc("PATCH /api/v1/admin/tenants/{id}/budget", a.handleSetTenantBudget)
	mux.HandleFunc("GET  /api/v1/admin/usage", a.handleAdminUsage)
	mux.HandleFunc("POST /api/v1/admin/demo_codes", a.handleMintDemoCode)
	mux.HandleFunc("GET  /api/v1/admin/demo_codes", a.handleListDemoCodes)
	mux.HandleFunc("POST /api/v1/admin/demo_codes/revoke", a.handleRevokeDemoCode)
}

type mintKeyRequest struct {
	TenantSlug     string `json:"tenant_slug"`
	TenantName     string `json:"tenant_name,omitempty"` // optional, used when tenant doesn't exist yet
	Role           string `json:"role"`                  // developer | it | engineer | admin
	RecipientEmail string `json:"recipient_email,omitempty"`
}

type mintKeyResponse struct {
	TenantID       string `json:"tenant_id"`
	TenantSlug     string `json:"tenant_slug"`
	Role           string `json:"role"`
	KeyID          string `json:"key_id"`
	Token          string `json:"token"` // shown ONCE
	KeyPrefix      string `json:"key_prefix"`
	RecipientEmail string `json:"recipient_email,omitempty"`
}

// handleMintKey: idempotent on the (tenant_slug, recipient_email) front —
// always creates a NEW key (rotation), revoking nothing automatically.
// The admin can revoke separately via a future endpoint.
func (a *AdminServer) handleMintKey(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	var req mintKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if req.TenantSlug == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "tenant_slug and role required")
		return
	}
	if !tenancy.ValidRoles[req.Role] {
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be developer|it|engineer|admin")
		return
	}

	ctx := r.Context()
	pool := a.Read.AdminPool

	// Upsert tenant by slug.
	var tenantID uuid.UUID
	name := req.TenantName
	if name == "" {
		name = req.TenantSlug
	}
	err := pool.QueryRow(ctx, `
		INSERT INTO app.tenants (slug, name) VALUES ($1, $2)
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, req.TenantSlug, name).Scan(&tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "tenant_upsert_failed", err.Error())
		return
	}

	// Mint token + insert.
	token, prefix, hash, err := tenancy.Mint(req.Role, a.AuthPepper)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "mint_failed", err.Error())
		return
	}
	// Revoke any prior active key for the same (tenant, role). PrefixLen=12 means
	// all developer tokens share key_prefix "osk_develope"; the resolver now
	// HMAC-walks every match so cross-tenant collisions don't break auth, but
	// keeping one active key per (tenant, role) is still a useful invariant.
	if _, err := pool.Exec(ctx, `
		UPDATE app.api_keys SET revoked_at = now()
		WHERE tenant_id = $1 AND role = $2 AND revoked_at IS NULL`,
		tenantID, req.Role); err != nil {
		writeError(w, http.StatusInternalServerError, "prior_revoke_failed", err.Error())
		return
	}
	var keyID uuid.UUID
	err = pool.QueryRow(ctx, `
		INSERT INTO app.api_keys (tenant_id, role, recipient_email, key_prefix, key_hash)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5)
		RETURNING id`,
		tenantID, req.Role, req.RecipientEmail, prefix, hash).Scan(&keyID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key_insert_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, mintKeyResponse{
		TenantID:       tenantID.String(),
		TenantSlug:     req.TenantSlug,
		Role:           req.Role,
		KeyID:          keyID.String(),
		Token:          token,
		KeyPrefix:      prefix,
		RecipientEmail: req.RecipientEmail,
	})
}

type createTenantRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

func (a *AdminServer) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	var req createTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if req.Slug == "" {
		writeError(w, http.StatusBadRequest, "missing_slug", "slug required")
		return
	}
	if req.Name == "" {
		req.Name = req.Slug
	}
	var id uuid.UUID
	err := a.Read.AdminPool.QueryRow(r.Context(), `
		INSERT INTO app.tenants (slug, name) VALUES ($1, $2)
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, req.Slug, req.Name).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "upsert_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant_id": id.String(), "slug": req.Slug, "name": req.Name})
}

// handleSetTenantBudget sets or clears (monthly_budget_usd: null) the
// tenant's monthly soft-cap override. NULL means the router falls back to
// its deployment-wide OPENSCOPE_DEFAULT_MONTHLY_BUDGET_USD.
func (a *AdminServer) handleSetTenantBudget(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	tenantID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_tenant_id", "tenant id must be a UUID")
		return
	}
	var req struct {
		MonthlyBudgetUSD *float64 `json:"monthly_budget_usd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if req.MonthlyBudgetUSD != nil && *req.MonthlyBudgetUSD < 0 {
		writeError(w, http.StatusBadRequest, "bad_budget", "monthly_budget_usd must be >= 0 (or null to clear)")
		return
	}
	tag, err := a.Read.AdminPool.Exec(r.Context(), `
		UPDATE app.tenants SET monthly_budget_usd = $2 WHERE id = $1`,
		tenantID, req.MonthlyBudgetUSD)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "tenant_not_found", "no tenant with that id")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":          tenantID.String(),
		"monthly_budget_usd": req.MonthlyBudgetUSD,
	})
}

type tenantSummary struct {
	ID         string `json:"id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	ActiveKeys int    `json:"active_keys"`
}

func (a *AdminServer) handleListTenants(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	rows, err := a.Read.AdminPool.Query(r.Context(), `
		SELECT t.id::text, t.slug, t.name,
		       (SELECT COUNT(*) FROM app.api_keys k WHERE k.tenant_id = t.id AND k.revoked_at IS NULL)::int
		FROM app.tenants t
		ORDER BY t.created_at`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	defer rows.Close()
	var out []tenantSummary
	for rows.Next() {
		var t tenantSummary
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.ActiveKeys); err != nil {
			writeError(w, http.StatusInternalServerError, "scan_failed", err.Error())
			return
		}
		out = append(out, t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
}

// ---------------------------------------------------------------------------
// GET /api/v1/admin/keys — list every key across every tenant.
// Includes revoked keys so an operator can see history; sorted active-first
// then most-recent-first within each group.

type adminKeyRow struct {
	ID             string  `json:"id"`
	TenantID       string  `json:"tenant_id"`
	TenantSlug     string  `json:"tenant_slug"`
	Role           string  `json:"role"`
	KeyPrefix      string  `json:"key_prefix"`
	RecipientEmail *string `json:"recipient_email,omitempty"`
	CreatedAt      string  `json:"created_at"`
	LastUsedAt     *string `json:"last_used_at,omitempty"`
	RevokedAt      *string `json:"revoked_at,omitempty"`
}

func (a *AdminServer) handleListKeys(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	rows, err := a.Read.AdminPool.Query(r.Context(), `
		SELECT k.id::text, k.tenant_id::text, t.slug, k.role, k.key_prefix,
		       k.recipient_email,
		       k.created_at::text,
		       k.last_used_at::text,
		       k.revoked_at::text
		FROM app.api_keys k
		JOIN app.tenants t ON t.id = k.tenant_id
		ORDER BY (k.revoked_at IS NULL) DESC, k.created_at DESC
		LIMIT 200`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_keys_failed", err.Error())
		return
	}
	defer rows.Close()
	out := make([]adminKeyRow, 0, 32)
	for rows.Next() {
		var k adminKeyRow
		if err := rows.Scan(&k.ID, &k.TenantID, &k.TenantSlug, &k.Role, &k.KeyPrefix,
			&k.RecipientEmail, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan_failed", err.Error())
			return
		}
		out = append(out, k)
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// ---------------------------------------------------------------------------
// POST /api/v1/admin/keys/revoke — revoke a key by id (body: {"id":"..."}).
// Idempotent: revoking an already-revoked key is a no-op.

type revokeKeyRequest struct {
	ID string `json:"id"`
}

func (a *AdminServer) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	var req revokeKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	keyID, err := uuid.Parse(req.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_uuid", err.Error())
		return
	}
	tag, err := a.Read.AdminPool.Exec(r.Context(), `
		UPDATE app.api_keys SET revoked_at = COALESCE(revoked_at, now())
		WHERE id = $1`, keyID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": tag.RowsAffected() > 0, "id": req.ID})
}

// ---------------------------------------------------------------------------
// GET /api/v1/admin/usage — cross-tenant rollup over the last 7 days.
// Returns one row per (tenant, day) plus a totals block. Aggregates from
// vendor.tenant_usage_daily so it matches what the engineer dashboard sees.

type adminUsageDay struct {
	TenantSlug   string  `json:"tenant_slug"`
	Day          string  `json:"day"`
	Requests     int     `json:"requests"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalCostUSD float64 `json:"total_cost_usd"`
}

type adminUsageTotals struct {
	Tenants      int     `json:"tenants_active_7d"`
	Requests     int     `json:"requests"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalCostUSD float64 `json:"total_cost_usd"`
}

func (a *AdminServer) handleAdminUsage(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	rows, err := a.Read.AdminPool.Query(r.Context(), `
		SELECT tenant_slug, day::text, requests, input_tokens, output_tokens, total_cost_usd::float8
		FROM vendor.tenant_usage_daily
		WHERE day >= (CURRENT_DATE - INTERVAL '7 days')
		ORDER BY day DESC, tenant_slug`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "usage_query_failed", err.Error())
		return
	}
	defer rows.Close()
	out := make([]adminUsageDay, 0, 32)
	totals := adminUsageTotals{}
	seen := map[string]struct{}{}
	for rows.Next() {
		var d adminUsageDay
		if err := rows.Scan(&d.TenantSlug, &d.Day, &d.Requests, &d.InputTokens, &d.OutputTokens, &d.TotalCostUSD); err != nil {
			writeError(w, http.StatusInternalServerError, "scan_failed", err.Error())
			return
		}
		out = append(out, d)
		seen[d.TenantSlug] = struct{}{}
		totals.Requests += d.Requests
		totals.InputTokens += d.InputTokens
		totals.OutputTokens += d.OutputTokens
		totals.TotalCostUSD += d.TotalCostUSD
	}
	totals.Tenants = len(seen)
	writeJSON(w, http.StatusOK, map[string]any{"daily": out, "totals": totals})
}

// ---------------------------------------------------------------------------
// Demo codes — short 8-char tokens that resolve to a real api_key. Prospects
// type these at /login instead of the long osk_… string. See migration 0003.
//
// Crockford base32 alphabet — no I/L/O/U so codes are unambiguous on a
// projector. NormalizeDemoCode maps common misreads back (O→0, I/L→1, U→V).

const demoCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
const demoCodeLen = 8

// NormalizeDemoCode uppercases and remaps visually-similar characters so a
// prospect copying a code from a slide gets through despite OCR glitches.
func NormalizeDemoCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.NewReplacer("O", "0", "I", "1", "L", "1", "U", "V").Replace(s)
	return s
}

// LooksLikeDemoCode reports whether s is in the demo-code alphabet at the
// expected length. Call NormalizeDemoCode first.
func LooksLikeDemoCode(s string) bool {
	if len(s) != demoCodeLen {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune(demoCodeAlphabet, r) {
			return false
		}
	}
	return true
}

func generateDemoCode() (string, error) {
	var raw [demoCodeLen]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	var out [demoCodeLen]byte
	for i, b := range raw {
		out[i] = demoCodeAlphabet[int(b)%len(demoCodeAlphabet)]
	}
	return string(out[:]), nil
}

type mintDemoCodeRequest struct {
	TenantSlug     string `json:"tenant_slug"`
	TenantName     string `json:"tenant_name,omitempty"`
	Role           string `json:"role"`
	RecipientEmail string `json:"recipient_email,omitempty"`
	Label          string `json:"label,omitempty"`
}

type mintDemoCodeResponse struct {
	Code           string `json:"code"`
	TenantID       string `json:"tenant_id"`
	TenantSlug     string `json:"tenant_slug"`
	Role           string `json:"role"`
	KeyID          string `json:"key_id"`
	Token          string `json:"token"` // operator records; not needed by prospect
	KeyPrefix      string `json:"key_prefix"`
	Label          string `json:"label,omitempty"`
	RecipientEmail string `json:"recipient_email,omitempty"`
}

// handleMintDemoCode mints a fresh api_key and binds an 8-char code to it.
// Revokes prior active demo codes for the same (tenant, role) so each role
// has exactly one active code at any time — matches the api_keys
// auto-revoke behavior in handleMintKey.
func (a *AdminServer) handleMintDemoCode(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	var req mintDemoCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if req.TenantSlug == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "tenant_slug and role required")
		return
	}
	if !tenancy.ValidRoles[req.Role] {
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be developer|it|engineer|admin")
		return
	}

	ctx := r.Context()
	pool := a.Read.AdminPool

	var tenantID uuid.UUID
	name := req.TenantName
	if name == "" {
		name = req.TenantSlug
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO app.tenants (slug, name) VALUES ($1, $2)
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, req.TenantSlug, name).Scan(&tenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "tenant_upsert_failed", err.Error())
		return
	}

	token, prefix, hash, err := tenancy.Mint(req.Role, a.AuthPepper)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "mint_failed", err.Error())
		return
	}

	if _, err := pool.Exec(ctx, `
		UPDATE app.api_keys SET revoked_at = now()
		WHERE tenant_id = $1 AND role = $2 AND revoked_at IS NULL`,
		tenantID, req.Role); err != nil {
		writeError(w, http.StatusInternalServerError, "prior_key_revoke_failed", err.Error())
		return
	}
	if _, err := pool.Exec(ctx, `
		UPDATE app.demo_codes SET revoked_at = now()
		WHERE tenant_id = $1 AND role = $2 AND revoked_at IS NULL`,
		tenantID, req.Role); err != nil {
		writeError(w, http.StatusInternalServerError, "prior_code_revoke_failed", err.Error())
		return
	}

	var keyID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO app.api_keys (tenant_id, role, recipient_email, key_prefix, key_hash)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5)
		RETURNING id`,
		tenantID, req.Role, req.RecipientEmail, prefix, hash).Scan(&keyID); err != nil {
		writeError(w, http.StatusInternalServerError, "key_insert_failed", err.Error())
		return
	}

	// Generate a fresh code, retry on PK collision (extremely unlikely).
	var code string
	for attempt := 0; attempt < 5; attempt++ {
		c, err := generateDemoCode()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "code_gen_failed", err.Error())
			return
		}
		_, err = pool.Exec(ctx, `
			INSERT INTO app.demo_codes (code, tenant_id, role, api_key_id, plaintext_token, label)
			VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''))`,
			c, tenantID, req.Role, keyID, token, req.Label)
		if err == nil {
			code = c
			break
		}
		if !strings.Contains(err.Error(), "demo_codes_pkey") {
			writeError(w, http.StatusInternalServerError, "code_insert_failed", err.Error())
			return
		}
	}
	if code == "" {
		writeError(w, http.StatusInternalServerError, "code_collision", "could not allocate a unique demo code")
		return
	}

	writeJSON(w, http.StatusOK, mintDemoCodeResponse{
		Code:           code,
		TenantID:       tenantID.String(),
		TenantSlug:     req.TenantSlug,
		Role:           req.Role,
		KeyID:          keyID.String(),
		Token:          token,
		KeyPrefix:      prefix,
		Label:          req.Label,
		RecipientEmail: req.RecipientEmail,
	})
}

type demoCodeRow struct {
	Code       string  `json:"code"`
	TenantID   string  `json:"tenant_id"`
	TenantSlug string  `json:"tenant_slug"`
	Role       string  `json:"role"`
	APIKeyID   string  `json:"api_key_id"`
	Label      *string `json:"label,omitempty"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	RevokedAt  *string `json:"revoked_at,omitempty"`
}

func (a *AdminServer) handleListDemoCodes(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	rows, err := a.Read.AdminPool.Query(r.Context(), `
		SELECT dc.code, dc.tenant_id::text, t.slug, dc.role, dc.api_key_id::text,
		       dc.label, dc.created_at::text, dc.last_used_at::text, dc.revoked_at::text
		FROM app.demo_codes dc
		JOIN app.tenants t ON t.id = dc.tenant_id
		ORDER BY (dc.revoked_at IS NULL) DESC, dc.created_at DESC
		LIMIT 200`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	defer rows.Close()
	out := make([]demoCodeRow, 0, 16)
	for rows.Next() {
		var d demoCodeRow
		if err := rows.Scan(&d.Code, &d.TenantID, &d.TenantSlug, &d.Role, &d.APIKeyID,
			&d.Label, &d.CreatedAt, &d.LastUsedAt, &d.RevokedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan_failed", err.Error())
			return
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"codes": out})
}

type revokeDemoCodeRequest struct {
	Code string `json:"code"`
}

func (a *AdminServer) handleRevokeDemoCode(w http.ResponseWriter, r *http.Request) {
	if !a.Token.check(r) {
		writeError(w, http.StatusUnauthorized, "admin_token_required", "missing or invalid admin bearer token")
		return
	}
	var req revokeDemoCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	code := NormalizeDemoCode(req.Code)
	if !LooksLikeDemoCode(code) {
		writeError(w, http.StatusBadRequest, "bad_code", "code must be 8 chars from the Crockford base32 alphabet")
		return
	}
	tag, err := a.Read.AdminPool.Exec(r.Context(), `
		UPDATE app.demo_codes SET revoked_at = COALESCE(revoked_at, now())
		WHERE code = $1`, code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": tag.RowsAffected() > 0, "code": code})
}

// Avoid an unused-imports complaint if pgx becomes unreferenced; the
// AdminPool already pulls it transitively.
var _ = errors.New
var _ = context.Background
var _ = pgx.ErrNoRows
