// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

// JSONFinding is the machine-readable form of a finding for `plan --json`.
type JSONFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Blocking bool   `json:"blocking"`
	Resource string `json:"resource"`
	Summary  string `json:"summary"`
	Fix      string `json:"fix,omitempty"`
}

// JSONView is the structured plan result for agents and CI to parse.
type JSONView struct {
	Proposal     string         `json:"proposal"`
	SHA256       string         `json:"sha256"`
	BoundsSource string         `json:"bounds_source"`
	Blocked      bool           `json:"blocked"`
	Verdict      string         `json:"verdict"`
	AckCount     int            `json:"acknowledge_count"`
	Findings     []JSONFinding  `json:"findings"`
	Bounds       []BoundsResult `json:"bounds"`
	Capabilities []Capability   `json:"capabilities"`
	VerbDiffs    []VerbDiff     `json:"verb_replacements,omitempty"`
	VerbEffects  []VerbEffects  `json:"verb_effects,omitempty"`
	VerbHistory  []VerbHistory  `json:"verb_history,omitempty"`
}

func (p Plan) JSON() JSONView {
	v := JSONView{
		Proposal:     p.Proposal.Metadata.Name,
		SHA256:       p.Proposal.SHA256,
		BoundsSource: p.BoundsSource,
		Blocked:      p.Blocked,
		AckCount:     len(p.Acknowledge),
		Bounds:       p.BoundsTable,
		Capabilities: p.Capabilities,
		VerbDiffs:    p.VerbDiffs,
		VerbEffects:  p.VerbEffects,
		VerbHistory:  p.VerbHistories,
	}
	switch {
	case p.Blocked:
		v.Verdict = "blocked"
	case len(p.Acknowledge) > 0:
		v.Verdict = "ok-with-confirmation"
	default:
		v.Verdict = "clean"
	}
	for _, f := range p.Findings {
		v.Findings = append(v.Findings, JSONFinding{
			RuleID:   f.RuleID,
			Severity: f.Severity.String(),
			Blocking: isBlocking(p.Bounds, f),
			Resource: f.Resource,
			Summary:  f.Summary,
			Fix:      f.Fix,
		})
	}
	return v
}
