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
