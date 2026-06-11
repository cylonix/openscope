package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type UsageMetric struct {
	TenantID      uuid.UUID
	APIKeyID      *uuid.UUID
	RequestID     uuid.UUID
	Model         string
	InputTokens   int
	OutputTokens  int
	InputCostUSD  float64
	OutputCostUSD float64
	// total_cost_usd is a generated column in the DB — do not set here.
}

func (s *Store) InsertUsageMetric(ctx context.Context, tx pgx.Tx, u UsageMetric) error {
	q := `INSERT INTO app.usage_metrics
			(tenant_id, api_key_id, request_id, model,
			 input_tokens, output_tokens, input_cost_usd, output_cost_usd)
		  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if tx != nil {
		_, err := tx.Exec(ctx, q, u.TenantID, u.APIKeyID, u.RequestID, u.Model,
			u.InputTokens, u.OutputTokens, u.InputCostUSD, u.OutputCostUSD)
		return err
	}
	_, err := s.pool.Exec(ctx, q, u.TenantID, u.APIKeyID, u.RequestID, u.Model,
		u.InputTokens, u.OutputTokens, u.InputCostUSD, u.OutputCostUSD)
	return err
}

// GetMonthlySpend sums total_cost_usd for the given tenant across the
// current calendar month. Called by pkg/billing.CheckMonthlyCap before
// each /v1/chat. The (tenant_id, ts DESC) index serves this query.
//
// Returns 0 if no usage_metrics rows exist (no calls this month) rather
// than an error.
func (s *Store) GetMonthlySpend(ctx context.Context, tenantID uuid.UUID) (float64, error) {
	var total float64
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(total_cost_usd), 0)::float8
		FROM app.usage_metrics
		WHERE tenant_id = $1 AND ts >= date_trunc('month', now())`,
		tenantID).Scan(&total)
	return total, err
}
