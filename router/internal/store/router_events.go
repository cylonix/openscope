package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RouterEvent mirrors app.router_events. No body fields — metadata only.
// Prompt/response bodies live in sensitive.prompt_records, etc.
type RouterEvent struct {
	RequestID  uuid.UUID
	TenantID   uuid.UUID
	APIKeyID   *uuid.UUID
	Role       string
	Agent      string
	Endpoint   string
	Model      string
	Decision   string // "allow" | "deny"
	Result     string // "success" | "dlp_block" | "upstream_error" ...
	Reason     string
	DLPRuleIDs []string
	BytesIn    int
	BytesOut   int
}

// AppendRouterEvent writes one row to app.router_events. Called on every
// /v1/scan and /v1/chat request, regardless of decision. Accepts an
// optional tx so /v1/chat can write event + prompt + response + usage +
// receipt atomically.
func (s *Store) AppendRouterEvent(ctx context.Context, tx pgx.Tx, e RouterEvent) error {
	q := `INSERT INTO app.router_events
			(request_id, tenant_id, api_key_id, role, agent, endpoint, model,
			 decision, result, reason, dlp_rule_ids, bytes_in, bytes_out)
		  VALUES
			($1, $2, $3, $4, NULLIF($5, ''), $6, NULLIF($7, ''),
			 $8, $9, NULLIF($10, ''), $11, $12, $13)`
	if tx != nil {
		_, err := tx.Exec(ctx, q, e.RequestID, e.TenantID, e.APIKeyID, e.Role, e.Agent, e.Endpoint, e.Model,
			e.Decision, e.Result, e.Reason, e.DLPRuleIDs, e.BytesIn, e.BytesOut)
		return err
	}
	_, err := s.pool.Exec(ctx, q, e.RequestID, e.TenantID, e.APIKeyID, e.Role, e.Agent, e.Endpoint, e.Model,
		e.Decision, e.Result, e.Reason, e.DLPRuleIDs, e.BytesIn, e.BytesOut)
	return err
}

// BeginTx starts a Postgres transaction. /v1/chat uses one for the
// multi-row commit (router_events + prompt_records + response_records +
// usage_metrics + receipts). On Bedrock error pre-commit, we roll back —
// no half-written state.
func (s *Store) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return s.pool.Begin(ctx)
}
