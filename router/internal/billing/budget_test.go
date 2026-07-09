package billing

import "testing"

func TestEstimateMaxCostUSD(t *testing.T) {
	const model = "us.amazon.nova-micro-v1:0"
	m := Find(model)
	if m == nil {
		t.Fatalf("test model %q not in catalog", model)
	}

	// 400 prompt bytes ~= 100 input tokens; price the full 1000 max output tokens.
	got := EstimateMaxCostUSD(model, 400, 1000)
	want := float64(400/4)*m.InputUSDPerToken + 1000*m.OutputUSDPerToken
	if got != want {
		t.Fatalf("estimate = %v, want %v", got, want)
	}

	// Output is reserved at the full max_tokens (conservative), so a larger
	// max_tokens must reserve strictly more — the safe direction for admission.
	if EstimateMaxCostUSD(model, 400, 2000) <= got {
		t.Error("a larger max_tokens must reserve more")
	}

	// An unknown model exerts no cap pressure (priced at 0).
	if c := EstimateMaxCostUSD("nope-not-a-model", 400, 1000); c != 0 {
		t.Fatalf("unknown model estimate = %v, want 0", c)
	}
}
