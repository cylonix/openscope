package dlp

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRulesExtend(t *testing.T) {
	path := writeRules(t, `
version: 1
mode: extend
rules:
  - id: internal-project-name
    name: Internal project codename
    category: classification
    severity: high
    min_hits: 1
    pattern: '(?i)project\s+nightjar'
`)
	rules, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	if len(rules) != len(DefaultRules)+1 {
		t.Fatalf("len = %d, want %d", len(rules), len(DefaultRules)+1)
	}
	s := NewScanner(rules)
	if got := s.Scan("kicking off Project Nightjar tomorrow"); len(got) != 1 || got[0].RuleID != "internal-project-name" {
		t.Errorf("custom rule did not fire: %v", got)
	}
	// Built-ins still active in extend mode.
	if got := s.Scan("-----BEGIN PRIVATE KEY-----"); len(got) == 0 {
		t.Error("built-in private-key rule lost in extend mode")
	}
}

func TestLoadRulesExtendOverridesByID(t *testing.T) {
	// Override a built-in by reusing its ID with a different pattern.
	path := writeRules(t, `
mode: extend
rules:
  - id: us-ssn
    name: SSN (custom, stricter)
    category: pii
    severity: critical
    min_hits: 3
    pattern: '\b\d{3}-\d{2}-\d{4}\b'
`)
	rules, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	if len(rules) != len(DefaultRules) {
		t.Fatalf("override should not grow the set: len = %d, want %d", len(rules), len(DefaultRules))
	}
	for _, r := range rules {
		if r.ID == "us-ssn" {
			if r.MinHits != 3 || r.Severity != "critical" {
				t.Errorf("override not applied: %+v", r)
			}
			return
		}
	}
	t.Error("us-ssn rule missing after override")
}

func TestLoadRulesReplace(t *testing.T) {
	path := writeRules(t, `
mode: replace
rules:
  - id: only-rule
    category: secret
    severity: high
    pattern: 'hunter2'
`)
	rules, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "only-rule" {
		t.Fatalf("replace mode kept built-ins: %d rules", len(rules))
	}
	if rules[0].Name != "only-rule" {
		t.Errorf("name should default to id, got %q", rules[0].Name)
	}
}

func TestLoadRulesRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"bad regex":        "mode: extend\nrules:\n  - id: x\n    category: pii\n    pattern: '['\n",
		"dup id":           "rules:\n  - id: x\n    category: pii\n    pattern: a\n  - id: x\n    category: pii\n    pattern: b\n",
		"missing id":       "rules:\n  - category: pii\n    pattern: a\n",
		"missing pattern":  "rules:\n  - id: x\n    category: pii\n",
		"unknown category": "rules:\n  - id: x\n    category: nope\n    pattern: a\n",
		"unknown severity": "rules:\n  - id: x\n    category: pii\n    severity: extreme\n    pattern: a\n",
		"bad mode":         "mode: merge\nrules: []\n",
		"empty replace":    "mode: replace\nrules: []\n",
		"bad version":      "version: 9\nrules: []\n",
	}
	for label, content := range cases {
		if _, err := LoadRulesFile(writeRules(t, content)); err == nil {
			t.Errorf("%s: accepted, want error", label)
		}
	}
}

// The shipped example file in replace mode must behave identically to the
// built-in rules — it is generated from them (go run ./internal/dlp/gen).
func TestExampleFileMatchesBuiltins(t *testing.T) {
	rules, err := LoadRulesFile("../../configs/dlp.example.yaml")
	if err != nil {
		t.Fatalf("load example: %v", err)
	}
	if len(rules) != len(DefaultRules) {
		t.Fatalf("example has %d rules, built-ins have %d — regenerate with: go run ./internal/dlp/gen", len(rules), len(DefaultRules))
	}
	for i, r := range rules {
		d := DefaultRules[i]
		if r.ID != d.ID || r.Category != d.Category || r.Severity != d.Severity ||
			r.MinHits != d.MinHits || r.Pattern.String() != d.Pattern.String() {
			t.Errorf("rule %d differs from built-in:\n got %s %s %s %d %q\nwant %s %s %s %d %q — regenerate with: go run ./internal/dlp/gen",
				i, r.ID, r.Category, r.Severity, r.MinHits, r.Pattern,
				d.ID, d.Category, d.Severity, d.MinHits, d.Pattern)
		}
	}
	if got, want := RulesetVersion(rules), RulesetVersion(DefaultRules); got != want {
		t.Errorf("RulesetVersion mismatch: %s vs %s", got, want)
	}
}

func TestRulesetVersionStability(t *testing.T) {
	v1 := RulesetVersion(DefaultRules)
	v2 := RulesetVersion(DefaultRules)
	if v1 != v2 {
		t.Errorf("not deterministic: %s vs %s", v1, v2)
	}
	custom, err := ParseRules([]byte("mode: replace\nrules:\n  - id: x\n    category: pii\n    pattern: a\n"), "t")
	if err != nil {
		t.Fatal(err)
	}
	if RulesetVersion(custom) == v1 {
		t.Error("different rule sets share a version hash")
	}
}
