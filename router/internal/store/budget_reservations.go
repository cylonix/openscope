package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ReserveBudget atomically admits a request against the tenant's monthly cap.
// It counts other IN-FLIGHT reservations alongside committed usage, so
// concurrent /v1/chat requests can no longer all read the same under-cap total
// and overshoot. Per tenant it serializes on a transaction-scoped advisory lock
// held only for this fast check+insert (never across the provider call), sums
// committed usage_metrics for the calendar month plus active reservations, and
// if that is below capUSD inserts a reservation for estCostUSD.
//
// Reservations are admission-only: they never enter usage_metrics/receipts and
// self-expire, so a crash between reserve and release can only make the cap
// briefly conservative, never over-charge. Returns the committed month-to-date
// spend (for display), whether the request was admitted, and the reservation id
// to release with ReleaseBudget once the real usage is recorded.
func (s *Store) ReserveBudget(ctx context.Context, tenantID uuid.UUID, estCostUSD, capUSD float64) (reservationID uuid.UUID, committedMTD float64, admitted bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, 0, false, err
	}
	defer tx.Rollback(ctx)

	// Serialize admission per tenant; the lock releases automatically at
	// commit/rollback, i.e. before the provider call — it never spans the LLM.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, tenantID.String()); err != nil {
		return uuid.Nil, 0, false, err
	}
	// GC expired reservations so a crashed request stops counting toward the cap
	// and the table stays small. Best-effort, under the same per-tenant lock.
	if _, err = tx.Exec(ctx, `DELETE FROM app.budget_reservations WHERE created_at < now() - interval '5 minutes'`); err != nil {
		return uuid.Nil, 0, false, err
	}

	var reserved float64
	if err = tx.QueryRow(ctx, `
		SELECT
			COALESCE((SELECT SUM(total_cost_usd) FROM app.usage_metrics
			          WHERE tenant_id = $1 AND ts >= date_trunc('month', now())), 0)::float8,
			COALESCE((SELECT SUM(est_cost_usd) FROM app.budget_reservations
			          WHERE tenant_id = $1), 0)::float8`,
		tenantID).Scan(&committedMTD, &reserved); err != nil {
		return uuid.Nil, 0, false, err
	}

	if committedMTD+reserved >= capUSD {
		if err = tx.Commit(ctx); err != nil {
			return uuid.Nil, committedMTD, false, err
		}
		return uuid.Nil, committedMTD, false, nil // over cap: nothing reserved
	}

	if err = tx.QueryRow(ctx, `
		INSERT INTO app.budget_reservations (tenant_id, est_cost_usd)
		VALUES ($1, $2) RETURNING id`, tenantID, estCostUSD).Scan(&reservationID); err != nil {
		return uuid.Nil, committedMTD, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return uuid.Nil, committedMTD, false, err
	}
	return reservationID, committedMTD, true, nil
}

// ReleaseBudget deletes a reservation once its real usage has been recorded
// (pass the persist tx so release is atomic with the usage_metrics insert), or
// on an early-return error path (tx nil). A missed release self-heals: the row
// expires and the next ReserveBudget GCs it. A Nil id is a no-op.
func (s *Store) ReleaseBudget(ctx context.Context, tx pgx.Tx, reservationID uuid.UUID) error {
	if reservationID == uuid.Nil {
		return nil
	}
	const q = `DELETE FROM app.budget_reservations WHERE id = $1`
	if tx != nil {
		_, err := tx.Exec(ctx, q, reservationID)
		return err
	}
	_, err := s.pool.Exec(ctx, q, reservationID)
	return err
}
