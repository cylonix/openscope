package billing

// EstimateMaxCostUSD is a conservative upper bound on a request's cost, used to
// reserve budget BEFORE the provider call (see store.ReserveBudget). It prices
// the FULL clamped max_tokens as output (actual output is usually less) plus an
// input-token estimate from the prompt byte length (~4 bytes/token). Over-
// estimating is the safe direction: it reserves more, so a tenant near the cap
// is denied rather than allowed to overshoot. Unknown models price at 0 (they
// exert no cap pressure — the same as costBreakdown/CostUSD for an unknown id).
//
// Admission is atomic and race-free: store.ReserveBudget counts committed usage
// plus other in-flight reservations under a per-tenant lock, replacing the old
// non-atomic read-then-write check that let concurrent requests overshoot.
func EstimateMaxCostUSD(modelID string, promptBytes, maxOutputTokens int) float64 {
	m := Find(modelID)
	if m == nil {
		return 0
	}
	estInputTokens := promptBytes / 4
	return float64(estInputTokens)*m.InputUSDPerToken + float64(maxOutputTokens)*m.OutputUSDPerToken
}
