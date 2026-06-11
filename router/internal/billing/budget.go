package billing

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// SpendStore is the subset of pkg/store needed for budget enforcement.
// *store.Store satisfies this interface (defined in pkg/store/usage_metrics.go).
type SpendStore interface {
	GetMonthlySpend(ctx context.Context, tenantID uuid.UUID) (float64, error)
}

var ErrBudgetExceeded = errors.New("monthly Bedrock budget exceeded for tenant")

// CheckMonthlyCap is the Layer-1 (router-side) budget check. Returns
// ErrBudgetExceeded if the tenant's accumulated total_cost_usd for the
// current calendar month is at or above capUSD. The caller resolves the
// cap: app.tenants.monthly_budget_usd when set, else the deployment-wide
// OPENSCOPE_DEFAULT_MONTHLY_BUDGET_USD.
//
// A cloud-side hard cap (e.g. AWS Budgets + IAM-policy-attach in the
// customer's Bedrock account — see router/deploy/iam-bedrock.md) fires
// regardless of this check. The two layers together protect against:
//
//   - the expected path: router miscounts → Layer 2 catches at the hard cap
//   - the bug path: router has a budget-check bypass → Layer 2 catches anyway
//   - the malicious path: someone hits Bedrock with leaked creds → Layer 2 catches
func CheckMonthlyCap(ctx context.Context, store SpendStore, tenantID uuid.UUID, capUSD float64) (currentUSD float64, err error) {
	currentUSD, err = store.GetMonthlySpend(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("query monthly spend: %w", err)
	}
	if currentUSD >= capUSD {
		return currentUSD, ErrBudgetExceeded
	}
	return currentUSD, nil
}
