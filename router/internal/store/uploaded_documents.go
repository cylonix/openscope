package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type UploadedDocument struct {
	RequestID     uuid.UUID
	TenantID      uuid.UUID
	Filename      string
	ContentText   string
	ContentSHA256 []byte
	DLPFindings   []byte // JSON-encoded []dlp.Finding
}

// InsertUploadedDocument writes one row to sensitive.uploaded_documents.
// Only called when DLP blocks a /v1/scan upload — we don't store passed
// content (avoids growing the sensitive table unbounded).
func (s *Store) InsertUploadedDocument(ctx context.Context, tx pgx.Tx, d UploadedDocument) error {
	q := `INSERT INTO sensitive.uploaded_documents
			(request_id, tenant_id, filename, content_text, content_sha256, dlp_findings)
		  VALUES ($1, $2, $3, $4, $5, $6)`
	if tx != nil {
		_, err := tx.Exec(ctx, q, d.RequestID, d.TenantID, d.Filename, d.ContentText, d.ContentSHA256, d.DLPFindings)
		return err
	}
	_, err := s.pool.Exec(ctx, q, d.RequestID, d.TenantID, d.Filename, d.ContentText, d.ContentSHA256, d.DLPFindings)
	return err
}
