package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type PromptRecord struct {
	RequestID    uuid.UUID
	TenantID     uuid.UUID
	PromptText   string
	PromptSHA256 []byte
	DLPFindings  []byte // JSON []dlp.Finding
}

// InsertPromptRecord writes one row to sensitive.prompt_records. Called
// on every /v1/chat regardless of decision — the customer's IT role
// (tenant_reader) can review what was requested even if blocked.
// vendor_reader (engineer side) is denied at the schema GRANT level.
func (s *Store) InsertPromptRecord(ctx context.Context, tx pgx.Tx, p PromptRecord) error {
	q := `INSERT INTO sensitive.prompt_records
			(request_id, tenant_id, prompt_text, prompt_sha256, dlp_findings)
		  VALUES ($1, $2, $3, $4, $5)`
	if tx != nil {
		_, err := tx.Exec(ctx, q, p.RequestID, p.TenantID, p.PromptText, p.PromptSHA256, p.DLPFindings)
		return err
	}
	_, err := s.pool.Exec(ctx, q, p.RequestID, p.TenantID, p.PromptText, p.PromptSHA256, p.DLPFindings)
	return err
}
