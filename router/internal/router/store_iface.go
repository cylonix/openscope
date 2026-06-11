package router

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/openscope/openscope/audit"
	"github.com/openscope/openscope/router/internal/store"
)

// Tx is the transaction handle RecordStore hands back from BeginTx.
// pgx.Tx satisfies it; the in-memory test store fakes it.
type Tx interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// RecordStore is exactly what the handlers persist through. *store.Store
// satisfies it via NewPGRecordStore; tests inject an in-memory fake so the
// full pipeline (auth → budget → DLP → provider → persist → receipt) runs
// without Postgres.
type RecordStore interface {
	BeginTx(ctx context.Context) (Tx, error)
	AppendRouterEvent(ctx context.Context, tx Tx, e store.RouterEvent) error
	InsertPromptRecord(ctx context.Context, tx Tx, p store.PromptRecord) error
	InsertResponseRecord(ctx context.Context, tx Tx, r store.ResponseRecord) error
	InsertUsageMetric(ctx context.Context, tx Tx, u store.UsageMetric) error
	InsertReceipt(ctx context.Context, tx Tx, r store.ReceiptRow) error
	InsertUploadedDocument(ctx context.Context, tx Tx, d store.UploadedDocument) error
	GetMonthlySpend(ctx context.Context, tenantID uuid.UUID) (float64, error)
	GetTenantBudget(ctx context.Context, tenantID uuid.UUID) (*float64, error)
}

// NewPGRecordStore adapts *store.Store to RecordStore. The adapter exists
// only to bridge the Tx types: store.Store methods take pgx.Tx, the
// interface takes the neutral Tx.
func NewPGRecordStore(s *store.Store) RecordStore { return pgRecordStore{s} }

type pgRecordStore struct{ s *store.Store }

func asPgxTx(tx Tx) pgx.Tx {
	if tx == nil {
		return nil
	}
	return tx.(pgx.Tx)
}

func (p pgRecordStore) BeginTx(ctx context.Context) (Tx, error) { return p.s.BeginTx(ctx) }

func (p pgRecordStore) AppendRouterEvent(ctx context.Context, tx Tx, e store.RouterEvent) error {
	return p.s.AppendRouterEvent(ctx, asPgxTx(tx), e)
}

func (p pgRecordStore) InsertPromptRecord(ctx context.Context, tx Tx, r store.PromptRecord) error {
	return p.s.InsertPromptRecord(ctx, asPgxTx(tx), r)
}

func (p pgRecordStore) InsertResponseRecord(ctx context.Context, tx Tx, r store.ResponseRecord) error {
	return p.s.InsertResponseRecord(ctx, asPgxTx(tx), r)
}

func (p pgRecordStore) InsertUsageMetric(ctx context.Context, tx Tx, u store.UsageMetric) error {
	return p.s.InsertUsageMetric(ctx, asPgxTx(tx), u)
}

func (p pgRecordStore) InsertReceipt(ctx context.Context, tx Tx, r store.ReceiptRow) error {
	return p.s.InsertReceipt(ctx, asPgxTx(tx), r)
}

func (p pgRecordStore) InsertUploadedDocument(ctx context.Context, tx Tx, d store.UploadedDocument) error {
	return p.s.InsertUploadedDocument(ctx, asPgxTx(tx), d)
}

func (p pgRecordStore) GetMonthlySpend(ctx context.Context, tenantID uuid.UUID) (float64, error) {
	return p.s.GetMonthlySpend(ctx, tenantID)
}

func (p pgRecordStore) GetTenantBudget(ctx context.Context, tenantID uuid.UUID) (*float64, error) {
	return p.s.GetTenantBudget(ctx, tenantID)
}

// WithJSONLMirror decorates a RecordStore so every router event is also
// appended to an ascope-format audit JSONL file (OPENSCOPE_AUDIT_JSONL_PATH).
// Postgres stays canonical; the mirror exists so one `tail -f` covers both
// the broker's and the router's decisions. Mirror failures are swallowed —
// the audit of record is the database row.
func WithJSONLMirror(rs RecordStore, path string) RecordStore {
	return jsonlMirror{rs: rs, path: path}
}

type jsonlMirror struct {
	rs   RecordStore
	path string
}

func (m jsonlMirror) AppendRouterEvent(ctx context.Context, tx Tx, e store.RouterEvent) error {
	err := m.rs.AppendRouterEvent(ctx, tx, e)
	if err == nil {
		_ = audit.Append(m.path, audit.Event{
			Timestamp: time.Now().UTC(),
			Agent:     e.Role,
			App:       "router",
			Action:    e.Endpoint,
			Params:    map[string]string{"model": e.Model, "tenant_id": e.TenantID.String()},
			Decision:  e.Decision,
			Result:    e.Result,
			Reason:    e.Reason,
		})
	}
	return err
}

func (m jsonlMirror) BeginTx(ctx context.Context) (Tx, error) { return m.rs.BeginTx(ctx) }
func (m jsonlMirror) InsertPromptRecord(ctx context.Context, tx Tx, r store.PromptRecord) error {
	return m.rs.InsertPromptRecord(ctx, tx, r)
}
func (m jsonlMirror) InsertResponseRecord(ctx context.Context, tx Tx, r store.ResponseRecord) error {
	return m.rs.InsertResponseRecord(ctx, tx, r)
}
func (m jsonlMirror) InsertUsageMetric(ctx context.Context, tx Tx, u store.UsageMetric) error {
	return m.rs.InsertUsageMetric(ctx, tx, u)
}
func (m jsonlMirror) InsertReceipt(ctx context.Context, tx Tx, r store.ReceiptRow) error {
	return m.rs.InsertReceipt(ctx, tx, r)
}
func (m jsonlMirror) InsertUploadedDocument(ctx context.Context, tx Tx, d store.UploadedDocument) error {
	return m.rs.InsertUploadedDocument(ctx, tx, d)
}
func (m jsonlMirror) GetMonthlySpend(ctx context.Context, tenantID uuid.UUID) (float64, error) {
	return m.rs.GetMonthlySpend(ctx, tenantID)
}
func (m jsonlMirror) GetTenantBudget(ctx context.Context, tenantID uuid.UUID) (*float64, error) {
	return m.rs.GetTenantBudget(ctx, tenantID)
}
