package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ResponseRecord struct {
	RequestID    uuid.UUID
	TenantID     uuid.UUID
	ResponseText string
	FinishReason string
	Model        string
}

// InsertResponseRecord writes one row to sensitive.response_records.
// Called only when Bedrock actually returned a response — DLP-blocked
// requests don't reach the upstream so no response row exists for them.
func (s *Store) InsertResponseRecord(ctx context.Context, tx pgx.Tx, r ResponseRecord) error {
	q := `INSERT INTO sensitive.response_records
			(request_id, tenant_id, response_text, finish_reason, model)
		  VALUES ($1, $2, $3, NULLIF($4, ''), $5)`
	if tx != nil {
		_, err := tx.Exec(ctx, q, r.RequestID, r.TenantID, r.ResponseText, r.FinishReason, r.Model)
		return err
	}
	_, err := s.pool.Exec(ctx, q, r.RequestID, r.TenantID, r.ResponseText, r.FinishReason, r.Model)
	return err
}
