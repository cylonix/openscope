package store

import (
	"context"

	"github.com/google/uuid"
)

// GetTenantBudget returns the tenant's monthly budget override in USD, or
// nil when the tenant uses the deployment-wide default
// (OPENSCOPE_DEFAULT_MONTHLY_BUDGET_USD).
func (s *Store) GetTenantBudget(ctx context.Context, tenantID uuid.UUID) (*float64, error) {
	var budget *float64
	err := s.pool.QueryRow(ctx, `
		SELECT monthly_budget_usd::float8
		FROM app.tenants
		WHERE id = $1`,
		tenantID).Scan(&budget)
	return budget, err
}

// SetTenantBudget sets (or clears, with nil) the tenant's monthly budget
// override. Reachable through the console admin API.
func (s *Store) SetTenantBudget(ctx context.Context, tenantID uuid.UUID, budgetUSD *float64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE app.tenants SET monthly_budget_usd = $2 WHERE id = $1`,
		tenantID, budgetUSD)
	return err
}
