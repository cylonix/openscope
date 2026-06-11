// Package billing computes per-request token costs and maintains the
// catalog of models the router accepts.
//
// Pricing constants are hardcoded for MVP. When we grow past one provider
// (v1.x) we move these into a model_pricing Postgres table; for now they
// live here so the router can compute cost on the hot path with no DB hop.
//
// The router is built on Bedrock Converse API (unified across providers),
// so adding a model is just appending to Catalog with the right tier and
// price constants. The model_id is exactly what InvokeModelWithResponseStream
// / Converse accepts — for AWS that's typically the inference-profile ID
// (us.*/global.* prefix) for newer models that require profile-based routing.
package billing

import (
	"math/big"
	"strings"
)

// Tier ranks a model by cost/sophistication. Tiers drive the dashboard
// dropdown (Stage 6) and gate which models a given role can request.
type Tier string

const (
	TierDev      Tier = "dev"      // cheap connectivity model (dev/test)
	TierStandard Tier = "standard" // demo default (customer-facing default)
	TierPremium  Tier = "premium"  // top-of-the-line (CISO-impress toggle)
)

// Model is one entry in the catalog.
//
//   - ID is what the bedrock-runtime Converse call uses as model-id. For
//     newer models that require inference profiles, this is the profile ID
//     (e.g., us.amazon.nova-micro-v1:0). For older models it's the
//     foundation-model ID directly.
//   - Provider is informational (also useful for IAM resource ARN building).
//   - InputUSDPerToken / OutputUSDPerToken are per-token (divide MTok price
//     by 1,000,000).
type Model struct {
	ID                string
	Provider          string
	DisplayName       string
	Tier              Tier
	InputUSDPerToken  float64
	OutputUSDPerToken float64
}

// Catalog is the full list of models the router will accept. Stage 6's
// model-picker dashboard reads this. Per-request model selection is
// validated against this list — anything not here is rejected.
//
// The user-facing demo defaults to TierStandard. Add or remove entries
// freely; the router config picks defaults by tier.
// Prices are per-token (per-MTok ÷ 1,000,000) and track current Bedrock
// on-demand list prices closely enough for the demo. The lineup mirrors a
// realistic set of models a customer would have enabled in one Bedrock
// account across providers and tiers.
var Catalog = []Model{
	{
		ID:                "anthropic.claude-opus-4-7",
		Provider:          "Anthropic",
		DisplayName:       "Claude Opus 4.7",
		Tier:              TierPremium,
		InputUSDPerToken:  0.000015, // $15 / MTok
		OutputUSDPerToken: 0.000075, // $75 / MTok
	},
	{
		ID:                "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
		Provider:          "Anthropic",
		DisplayName:       "Claude Sonnet 4.5",
		Tier:              TierStandard,
		InputUSDPerToken:  0.000003, // $3 / MTok
		OutputUSDPerToken: 0.000015, // $15 / MTok
	},
	{
		ID:                "us.anthropic.claude-haiku-4-5-20251001-v1:0",
		Provider:          "Anthropic",
		DisplayName:       "Claude Haiku 4.5",
		Tier:              TierStandard,
		InputUSDPerToken:  0.000001, // $1.00 / MTok
		OutputUSDPerToken: 0.000005, // $5.00 / MTok
	},
	{
		ID:                "us.amazon.nova-pro-v1:0",
		Provider:          "Amazon",
		DisplayName:       "Amazon Nova Pro",
		Tier:              TierStandard,
		InputUSDPerToken:  0.0000008, // $0.80 / MTok
		OutputUSDPerToken: 0.0000032, // $3.20 / MTok
	},
	{
		ID:                "meta.llama3-3-70b-instruct-v1:0",
		Provider:          "Meta",
		DisplayName:       "Llama 3.3 70B Instruct",
		Tier:              TierStandard,
		InputUSDPerToken:  0.00000072, // $0.72 / MTok
		OutputUSDPerToken: 0.00000072, // $0.72 / MTok
	},
	{
		ID:                "us.amazon.nova-lite-v1:0",
		Provider:          "Amazon",
		DisplayName:       "Amazon Nova Lite",
		Tier:              TierDev,
		InputUSDPerToken:  0.00000006, // $0.06 / MTok
		OutputUSDPerToken: 0.00000024, // $0.24 / MTok
	},
	{
		ID:                "us.amazon.nova-micro-v1:0",
		Provider:          "Amazon",
		DisplayName:       "Amazon Nova Micro",
		Tier:              TierDev,
		InputUSDPerToken:  0.000000035, // $0.035 / MTok
		OutputUSDPerToken: 0.00000014,  // $0.14 / MTok
	},
	{
		ID:                "amazon.titan-text-premier-v1:0",
		Provider:          "Amazon",
		DisplayName:       "Titan Text Premier",
		Tier:              TierDev,
		InputUSDPerToken:  0.0000005, // $0.50 / MTok
		OutputUSDPerToken: 0.0000015, // $1.50 / MTok
	},
}

// adminDisabledByDefault are the models the demo's customer admin has turned
// OFF — illustrating why an admin curates the lineup even when the Bedrock
// account makes more available: Claude Opus is left disabled as "too
// expensive for routine agent calls", Titan as "below our quality bar". The
// router refuses a disabled model; the console greys it out. Override per
// deployment with OPENSCOPE_ENABLED_MODELS (a comma-separated allowlist of IDs).
var adminDisabledByDefault = map[string]bool{
	"anthropic.claude-opus-4-7":      true,
	"amazon.titan-text-premier-v1:0": true,
}

// DefaultEnabledSet is the admin-enabled allowlist used when
// OPENSCOPE_ENABLED_MODELS is unset: every catalog model except those in
// adminDisabledByDefault.
func DefaultEnabledSet() map[string]bool {
	s := make(map[string]bool, len(Catalog))
	for _, m := range Catalog {
		if !adminDisabledByDefault[m.ID] {
			s[m.ID] = true
		}
	}
	return s
}

// ParseEnabledSet builds the admin-enabled allowlist from a comma-separated
// list of model IDs (OPENSCOPE_ENABLED_MODELS). Empty → DefaultEnabledSet.
func ParseEnabledSet(raw string) map[string]bool {
	if strings.TrimSpace(raw) == "" {
		return DefaultEnabledSet()
	}
	s := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		if id := strings.TrimSpace(part); id != "" {
			s[id] = true
		}
	}
	return s
}

// DefaultModelID returns the catalog ID matching the given tier. If no
// model is registered for that tier, the standard tier is used.
func DefaultModelID(t Tier) string {
	for _, m := range Catalog {
		if m.Tier == t {
			return m.ID
		}
	}
	for _, m := range Catalog {
		if m.Tier == TierStandard {
			return m.ID
		}
	}
	return Catalog[0].ID
}

// DisplayName returns the human-friendly label for a model ID (e.g.
// "Claude Haiku 4.5"), falling back to the raw catalog ID if the model
// isn't registered. Used by the dashboards so entries read "Claude Haiku
// 4.5" instead of "us.anthropic.claude-haiku-4-5-20251001-v1:0".
func DisplayName(id string) string {
	if m := Find(id); m != nil {
		return m.DisplayName
	}
	return id
}

// Find returns the Model for a given ID or nil if not in the catalog.
// Used by the router to validate per-request model selection and to
// compute cost.
func Find(id string) *Model {
	for i := range Catalog {
		if Catalog[i].ID == id {
			return &Catalog[i]
		}
	}
	return nil
}

// CostUSD returns input cost, output cost, and total cost for a call to
// the given model. Returns are *big.Rat to avoid float64 rounding drift
// across many requests; the caller formats to numeric(12,6) for storage.
func CostUSD(modelID string, inputTokens, outputTokens int) (inUSD, outUSD, totalUSD *big.Rat) {
	m := Find(modelID)
	if m == nil {
		// Unknown model — return zero costs; the request will have been
		// rejected upstream so this path shouldn't normally hit.
		return new(big.Rat), new(big.Rat), new(big.Rat)
	}
	inUSD = new(big.Rat).SetFloat64(float64(inputTokens) * m.InputUSDPerToken)
	outUSD = new(big.Rat).SetFloat64(float64(outputTokens) * m.OutputUSDPerToken)
	totalUSD = new(big.Rat).Add(inUSD, outUSD)
	return
}

// CostUSDFloat is the simpler float64 variant for log lines and dashboard
// display. Do not use for storage or accounting.
func CostUSDFloat(modelID string, inputTokens, outputTokens int) float64 {
	m := Find(modelID)
	if m == nil {
		return 0
	}
	return float64(inputTokens)*m.InputUSDPerToken +
		float64(outputTokens)*m.OutputUSDPerToken
}

// DefaultMonthlyBudgetUSD is the deployment-wide soft cap used when a
// tenant has no app.tenants.monthly_budget_usd override and the operator
// did not set OPENSCOPE_DEFAULT_MONTHLY_BUDGET_USD.
const DefaultMonthlyBudgetUSD = 25.00
