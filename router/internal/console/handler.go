package console

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openscope/openscope/router/internal/billing"
	"github.com/openscope/openscope/router/internal/store"
	"github.com/openscope/openscope/router/internal/tenancy"
)

// Server wires the console API. Mount via Server.Routes() on a net/http mux.
type Server struct {
	Resolver    *tenancy.Resolver // re-uses the router's token resolver
	Sessions    *Manager
	Read        *ReadStore
	DevInsecure bool // local-dev mode: don't set Secure on cookies

	// Region is the Bedrock serving region (e.g. "us-west-2"). Stamped onto
	// event rows so the dashboards can show "served by AWS Bedrock · us-west-2"
	// next to each call. Mirrors the router's OPENSCOPE_BEDROCK_REGION.
	Region string

	// EnabledModels is the customer admin's model allowlist (mirrors the
	// router's OPENSCOPE_ENABLED_MODELS). Used to mark catalog models
	// enabled/disabled in the model-usage breakdown. Nil → DefaultEnabledSet.
	EnabledModels map[string]bool

	// DefaultMonthlyBudgetUSD mirrors the router's
	// OPENSCOPE_DEFAULT_MONTHLY_BUDGET_USD — the soft cap shown for tenants
	// with no per-tenant override. 0 → billing.DefaultMonthlyBudgetUSD.
	DefaultMonthlyBudgetUSD float64
}

func (s *Server) modelEnabled(id string) bool {
	if s.EnabledModels == nil {
		return billing.DefaultEnabledSet()[id]
	}
	return s.EnabledModels[id]
}

// modelInfo is one row of the per-model breakdown: catalog metadata (label,
// provider, tier, unit price) + admin enablement + this month's usage.
type modelInfo struct {
	ID            string  `json:"id"`
	DisplayName   string  `json:"display_name"`
	Provider      string  `json:"provider"`
	Region        string  `json:"region"`
	Tier          string  `json:"tier"`
	InputPerMTok  float64 `json:"input_per_mtok"`
	OutputPerMTok float64 `json:"output_per_mtok"`
	Enabled       bool    `json:"enabled"`
	Calls         int     `json:"calls"`
	InputTokens   int64   `json:"input_tokens"`
	OutputTokens  int64   `json:"output_tokens"`
	TotalCostUSD  float64 `json:"total_cost_usd"`
	Tenants       int     `json:"tenants,omitempty"`
}

// buildModelList merges the full catalog (so every entitled model shows, even
// with zero usage) with the period's usage and the admin enablement flag.
func (s *Server) buildModelList(usage []ModelUsageRow) []modelInfo {
	by := make(map[string]ModelUsageRow, len(usage))
	for _, u := range usage {
		by[u.Model] = u
	}
	region := s.region()
	out := make([]modelInfo, 0, len(billing.Catalog))
	seen := map[string]bool{}
	for _, m := range billing.Catalog {
		seen[m.ID] = true
		u := by[m.ID]
		out = append(out, modelInfo{
			ID: m.ID, DisplayName: m.DisplayName, Provider: m.Provider, Region: region,
			Tier:         string(m.Tier),
			InputPerMTok: m.InputUSDPerToken * 1e6, OutputPerMTok: m.OutputUSDPerToken * 1e6,
			Enabled: s.modelEnabled(m.ID),
			Calls:   u.Calls, InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
			TotalCostUSD: u.TotalCostUSD, Tenants: u.Tenants,
		})
	}
	// Defensive: a model with usage that's no longer in the catalog (retired
	// id) still shows so cost reconciles.
	for _, u := range usage {
		if u.Model == "" || seen[u.Model] {
			continue
		}
		out = append(out, modelInfo{
			ID: u.Model, DisplayName: billing.DisplayName(u.Model), Provider: "AWS Bedrock",
			Region: region, Tier: "—", Enabled: s.modelEnabled(u.Model),
			Calls: u.Calls, InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
			TotalCostUSD: u.TotalCostUSD, Tenants: u.Tenants,
		})
	}
	return out
}

// eventProvider is the serving platform shown alongside each event's model.
const eventProvider = "AWS Bedrock"

func (s *Server) region() string {
	if s.Region != "" {
		return s.Region
	}
	return "us-west-2"
}

// --- Routes ---------------------------------------------------------------

func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/session", s.handleLogin)
	mux.HandleFunc("POST /api/v1/session/switch", s.requireSession(s.handleSwitchRole))
	mux.HandleFunc("POST /api/v1/logout", s.handleLogout)
	mux.HandleFunc("GET  /api/v1/me", s.requireSession(s.handleMe))
	mux.HandleFunc("GET  /api/v1/events", s.requireSession(s.handleEvents))
	mux.HandleFunc("GET  /api/v1/usage", s.requireSession(s.handleUsage))
	mux.HandleFunc("GET  /api/v1/models", s.requireSession(s.handleModels))
	mux.HandleFunc("GET  /api/v1/vendor/models", s.requireRole(s.handleVendorModels, "engineer"))
	mux.HandleFunc("GET  /api/v1/prompts", s.requireRole(s.handlePrompts, "developer", "it"))
	mux.HandleFunc("GET  /api/v1/receipts", s.requireSession(s.handleReceipts))
	mux.HandleFunc("GET  /api/v1/vendor/usage", s.requireRole(s.handleVendorUsage, "engineer"))
	mux.HandleFunc("POST /api/v1/vendor/verify_no_prompt_access", s.requireRole(s.handleVerifyNoPromptAccess, "engineer"))
	mux.HandleFunc("GET  /api/v1/health", s.handleHealth)
}

// --- Middleware -----------------------------------------------------------

type ctxKey int

const sessionKey ctxKey = 1

func (s *Server) requireSession(next func(http.ResponseWriter, *http.Request, Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "no_session", "no session cookie")
			return
		}
		sess, err := s.Sessions.Verify(c.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "bad_session", err.Error())
			return
		}
		// Sliding expiration: re-issue the cookie with a fresh window on every
		// authenticated request. An open dashboard polls (events/usage every
		// few seconds; the layout pings /me), so an actively-watched session
		// never dies mid-demo. A truly idle tab — no requests — still expires
		// after SessionMaxAge, then the next click lands cleanly on /login.
		renewed := sess
		renewed.Exp = time.Now().Add(SessionMaxAge).Unix()
		if cookie, err := s.Sessions.Sign(renewed); err == nil {
			s.Sessions.SetCookie(w, cookie, s.DevInsecure)
		}
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		next(w, r.WithContext(ctx), sess)
	}
}

func (s *Server) requireRole(next func(http.ResponseWriter, *http.Request, Session), roles ...string) http.HandlerFunc {
	allowed := map[string]bool{}
	for _, r := range roles {
		allowed[r] = true
	}
	return s.requireSession(func(w http.ResponseWriter, r *http.Request, sess Session) {
		if !allowed[sess.Role] {
			writeError(w, http.StatusForbidden, "role_not_allowed",
				"this endpoint requires role(s): "+joinRoles(roles))
			return
		}
		next(w, r, sess)
	})
}

// --- Handlers -------------------------------------------------------------

type loginRequest struct {
	Token string `json:"token"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "missing_token", `field "token" required`)
		return
	}

	// Demo-code path: an 8-char Crockford-base32 code resolves to the real
	// osk_… token stored in app.demo_codes. We swap req.Token for the
	// plaintext so Resolver.Resolve sees a normal token, and return the
	// plaintext to the client so it can be stashed for router calls.
	resolvedToken := req.Token
	fromCode := false
	if s.Read != nil && !strings.HasPrefix(req.Token, "osk_") {
		norm := NormalizeDemoCode(req.Token)
		if LooksLikeDemoCode(norm) {
			row, err := s.Read.LookupDemoCode(r.Context(), norm)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "demo_code_lookup_failed", err.Error())
				return
			}
			if row != nil {
				resolvedToken = row.PlaintextToken
				fromCode = true
			}
			// If the code didn't match, fall through to Resolver.Resolve,
			// which returns the same invalid_token error as a bad long token.
		}
	}

	p, err := s.Resolver.Resolve(r.Context(), "Bearer "+resolvedToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	sess := Session{
		TenantID: p.TenantID,
		Role:     p.Role,
		KeyID:    p.KeyID,
		Exp:      time.Now().Add(SessionMaxAge).Unix(),
	}
	cookie, err := s.Sessions.Sign(sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign_failed", err.Error())
		return
	}
	s.Sessions.SetCookie(w, cookie, s.DevInsecure)
	resp := map[string]any{
		"tenant_id": sess.TenantID.String(),
		"role":      sess.Role,
		"exp":       sess.Exp,
	}
	if fromCode {
		// Frontend stores this in sessionStorage so /v1/scan and /v1/chat
		// (which the router authenticates directly) keep working.
		resp["resolved_token"] = resolvedToken
	}
	writeJSON(w, http.StatusOK, resp)
}

type switchRequest struct {
	Role string `json:"role"`
}

// handleSwitchRole re-issues the session for the SAME tenant under a different
// role. This is a DEMO convenience: it lets a presenter flip between the three
// role views (developer / it / engineer) without re-entering each role's code.
//
// Safety: it reuses the current session's TenantID — it cannot cross tenants,
// only change the role lens within the already-authenticated tenant. The demo
// runs a single throwaway tenant where all three role codes are already shared
// (the runbook lists them), so this grants no access the holder couldn't get by
// logging in with the other code. Disable in any multi-tenant deployment.
func (s *Server) handleSwitchRole(w http.ResponseWriter, r *http.Request, sess Session) {
	var req switchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if !tenancy.ValidRoles[req.Role] {
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be developer|it|engineer|admin")
		return
	}
	next := Session{
		TenantID: sess.TenantID,
		Role:     req.Role,
		KeyID:    sess.KeyID,
		Exp:      time.Now().Add(SessionMaxAge).Unix(),
	}
	cookie, err := s.Sessions.Sign(next)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign_failed", err.Error())
		return
	}
	s.Sessions.SetCookie(w, cookie, s.DevInsecure)
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": next.TenantID.String(),
		"role":      next.Role,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.Sessions.ClearCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, sess Session) {
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": sess.TenantID.String(),
		"role":      sess.Role,
		"key_id":    sess.KeyID.String(),
		"exp":       sess.Exp,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, sess Session) {
	limit := parseLimit(r, 100)
	if sess.Role == "engineer" {
		// Cross-tenant for engineers (vendor_reader pool). Implementation
		// uses a separate read path that runs against the vendor pool —
		// no `app.tenant_id` set, RLS policy USING (true).
		writeError(w, http.StatusNotImplemented, "engineer_events_pending",
			"engineer cross-tenant events list — see /api/v1/vendor/usage for now")
		return
	}
	events, err := s.Read.ListRouterEventsForTenant(r.Context(), sess.TenantID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "events_query_failed", err.Error())
		return
	}
	// Stamp the human model label + serving platform/region onto each row so
	// the SOC feed reads "Claude Haiku 4.5 · AWS Bedrock · us-west-2" instead
	// of just a token count. Derived (not stored) so it stays correct if the
	// catalog or region changes. Rows with no model (e.g. /v1/scan, channel
	// blocks pre-model) stay blank.
	region := s.region()
	for i := range events {
		if events[i].Model != "" {
			events[i].ModelLabel = billing.DisplayName(events[i].Model)
			events[i].Provider = eventProvider
			events[i].Region = region
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": orEmpty(events)})
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request, sess Session) {
	if sess.Role == "engineer" {
		writeError(w, http.StatusForbidden, "use_vendor_endpoint",
			"engineer role should call /api/v1/vendor/usage instead")
		return
	}
	capUSD := s.DefaultMonthlyBudgetUSD
	if capUSD <= 0 {
		capUSD = billing.DefaultMonthlyBudgetUSD
	}
	if override, err := s.Read.TenantBudget(r.Context(), sess.TenantID); err == nil && override != nil {
		capUSD = *override
	}
	u, err := s.Read.MonthlyUsageForTenant(r.Context(), sess.TenantID, capUSD)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "usage_query_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// handleModels returns the per-model breakdown for the caller's tenant: the
// full catalog (entitled models) merged with this month's usage and the admin
// enablement flag. Powers the IT "models & usage" table.
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request, sess Session) {
	if sess.Role == "engineer" {
		writeError(w, http.StatusForbidden, "use_vendor_endpoint",
			"engineer role should call /api/v1/vendor/models instead")
		return
	}
	usage, err := s.Read.PerModelUsageForTenant(r.Context(), sess.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "model_usage_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"region": s.region(), "models": s.buildModelList(usage)})
}

// handleVendorModels is the engineer/Ops cross-tenant per-model breakdown.
// Cross-tenant metering only — vendor_reader has zero access to prompt bodies.
func (s *Server) handleVendorModels(w http.ResponseWriter, r *http.Request, _ Session) {
	usage, err := s.Read.PerModelUsageAllTenants(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "vendor_model_usage_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"region": s.region(), "models": s.buildModelList(usage)})
}

func (s *Server) handlePrompts(w http.ResponseWriter, r *http.Request, sess Session) {
	limit := parseLimit(r, 50)
	prompts, err := s.Read.ListPromptsForTenant(r.Context(), sess.TenantID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "prompts_query_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"prompts": orEmpty(prompts)})
}

func (s *Server) handleReceipts(w http.ResponseWriter, r *http.Request, sess Session) {
	if sess.Role == "engineer" {
		writeError(w, http.StatusForbidden, "engineer_no_receipts",
			"receipts are per-tenant; engineer role does not access them")
		return
	}
	limit := parseLimit(r, 20)
	recs, err := s.Read.ListReceiptsForTenant(r.Context(), sess.TenantID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "receipts_query_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"receipts": orEmpty(recs)})
}

func (s *Server) handleVendorUsage(w http.ResponseWriter, r *http.Request, sess Session) {
	// Refresh the materialized view first so the cross-tenant aggregates
	// reflect activity that just happened (the demo runs are low-volume, so
	// this is instant). Best-effort: if the refresh fails we still serve the
	// last-known view rather than erroring. This is why the "Refresh" button
	// shows fresh numbers immediately.
	_ = s.Read.RefreshVendorView(r.Context())
	limit := parseLimit(r, 100)
	rows, err := s.Read.ListVendorDailyUsage(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "vendor_usage_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"daily": orEmpty(rows)})
}

// handleVerifyNoPromptAccess is one of the engineer dashboard's "verify our
// access" demo proofs. Tries to read sensitive.prompt_records via the
// vendor_reader pool — expects Postgres to return permission denied. The
// caller gets the EXACT error string back so it can be screenshot as proof.
func (s *Server) handleVerifyNoPromptAccess(w http.ResponseWriter, r *http.Request, _ Session) {
	denyMsg, unexpected := s.Read.VerifyVendorCantReadPrompts(r.Context())
	if unexpected != nil {
		// The boundary actually broke — this should not happen but we
		// must surface it loudly if it does.
		writeError(w, http.StatusInternalServerError, "boundary_broken", unexpected.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"attempted_query":  "SELECT prompt_text FROM sensitive.prompt_records LIMIT 1",
		"pool":             "vendor_reader",
		"result":           "denied",
		"postgres_message": denyMsg,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok\n"))
}

// --- helpers ---------------------------------------------------------------

// orEmpty coalesces a nil slice to an empty one so JSON renders [] not null —
// clients .map()/.length over these without a guard, and an empty result (e.g.
// after the demo body purge) must not crash them.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"code": code, "message": msg})
}

func parseLimit(r *http.Request, def int) int {
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func joinRoles(roles []string) string {
	if len(roles) == 0 {
		return ""
	}
	out := roles[0]
	for _, r := range roles[1:] {
		out += ", " + r
	}
	return out
}

// SuppressUnused — gosatisfies tools when a placeholder is added later.
var _ = uuid.Nil
var _ = store.RouterEvent{}
var _ = errors.New
var _ = log.Println
