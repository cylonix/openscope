// Package dlp scans text against a set of regex rules and reports findings.
// Findings drive the deny/allow decision for /v1/scan (any finding → deny)
// and the redaction pass for /v1/chat (Stage 4 — matched substrings get
// replaced with [REDACTED:<rule_id>] tokens before forwarding to Bedrock).
package dlp

// Finding is one rule that matched, with the number of matches in the text.
// Bodies/excerpts are deliberately NOT included — findings can be logged
// to app.router_events (operational metadata, vendor_reader-visible) without
// leaking content.
type Finding struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type Scanner struct {
	rules []Rule
}

func NewScanner(rules []Rule) *Scanner {
	return &Scanner{rules: rules}
}

// Scan runs every rule against text and returns the list of findings.
// Returns nil (length 0) if nothing matched — callers check len() rather
// than a separate bool.
func (s *Scanner) Scan(text string) []Finding {
	var findings []Finding
	for _, r := range s.rules {
		matches := r.Pattern.FindAllStringIndex(text, -1)
		minHits := r.MinHits
		if minHits < 1 {
			minHits = 1
		}
		if len(matches) < minHits {
			continue
		}
		findings = append(findings, Finding{
			RuleID:   r.ID,
			RuleName: r.Name,
			Category: r.Category,
			Severity: r.Severity,
			Count:    len(matches),
		})
	}
	return findings
}

// RuleIDs extracts just the rule IDs from a findings slice. Used to populate
// app.router_events.dlp_rule_ids (a text[] column — no full bodies leak).
func RuleIDs(findings []Finding) []string {
	if len(findings) == 0 {
		return nil
	}
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}

// categoryPriority orders categories by demo salience — content-class (the
// crown jewels) first, PII last. Used to pick the "primary" finding for the
// agent-facing one-line block reason.
var categoryPriority = map[string]int{
	CategoryContentClass:   0,
	CategoryExportControl:  1,
	CategorySecret:         2,
	CategoryClassification: 3,
	CategoryFoundry:        4,
	CategoryPII:            5,
}

// categoryLabel is the human phrase used in the block reason.
var categoryLabel = map[string]string{
	CategoryContentClass:   "proprietary source/IP",
	CategoryExportControl:  "export-controlled material",
	CategorySecret:         "secret/credential",
	CategoryClassification: "confidential-marked content",
	CategoryFoundry:        "foundry/PDK material",
	CategoryPII:            "personal data",
}

// PrimaryReason returns a short, agent-facing explanation of the strongest
// finding — e.g. "proprietary source/IP detected (Verilog / SystemVerilog
// source)". Suitable to surface inside a coding agent's error message.
func PrimaryReason(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	best := findings[0]
	for _, f := range findings[1:] {
		if categoryPriority[f.Category] < categoryPriority[best.Category] {
			best = f
		}
	}
	label := categoryLabel[best.Category]
	if label == "" {
		label = best.Category
	}
	return label + " detected (" + best.RuleName + ")"
}

// Categories returns the distinct categories present across findings, ordered
// by salience.
func Categories(findings []Finding) []string {
	seen := map[string]bool{}
	var cats []string
	for _, f := range findings {
		if !seen[f.Category] {
			seen[f.Category] = true
			cats = append(cats, f.Category)
		}
	}
	sortByPriority(cats)
	return cats
}

func sortByPriority(cats []string) {
	for i := 1; i < len(cats); i++ {
		for j := i; j > 0 && categoryPriority[cats[j]] < categoryPriority[cats[j-1]]; j-- {
			cats[j], cats[j-1] = cats[j-1], cats[j]
		}
	}
}
