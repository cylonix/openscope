package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ReceiptRow struct {
	RequestID   uuid.UUID
	TenantID    uuid.UUID
	Payload     []byte // canonical JSON
	Signature   []byte // Ed25519, 64 bytes
	PublicKeyID string
}

// InsertReceipt writes one row to app.receipts. The (tenant_id, ts DESC)
// index serves the IT dashboard's "last 5 receipts" panel; (request_id)
// unique index is enforced by schema.
func (s *Store) InsertReceipt(ctx context.Context, tx pgx.Tx, r ReceiptRow) error {
	q := `INSERT INTO app.receipts
			(request_id, tenant_id, payload, signature, public_key_id)
		  VALUES ($1, $2, $3, $4, $5)`
	if tx != nil {
		_, err := tx.Exec(ctx, q, r.RequestID, r.TenantID, r.Payload, r.Signature, r.PublicKeyID)
		return err
	}
	_, err := s.pool.Exec(ctx, q, r.RequestID, r.TenantID, r.Payload, r.Signature, r.PublicKeyID)
	return err
}
