package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// RulesConfig is the YAML schema for operator-supplied DLP rules
// (OPENSCOPE_DLP_RULES_FILE). mode "extend" appends to the built-in rule
// set, overriding built-ins by ID; mode "replace" discards the built-ins
// entirely. See router/configs/dlp.example.yaml for the built-in set
// expressed in this format.
type RulesConfig struct {
	Version int          `yaml:"version"`
	Mode    string       `yaml:"mode"` // "extend" (default) | "replace"
	Rules   []ConfigRule `yaml:"rules"`
}

type ConfigRule struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Category string `yaml:"category"`
	Severity string `yaml:"severity"`
	Pattern  string `yaml:"pattern"`
	MinHits  int    `yaml:"min_hits"`
}

var validCategories = map[string]bool{
	CategoryContentClass:   true,
	CategoryClassification: true,
	CategoryExportControl:  true,
	CategoryFoundry:        true,
	CategorySecret:         true,
	CategoryPII:            true,
}

var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true,
}

// LoadRulesFile reads a YAML rules file and merges it with the built-in
// DefaultRules according to its mode. Returns the effective rule set.
func LoadRulesFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dlp rules: %w", err)
	}
	return ParseRules(data, path)
}

// ParseRules parses and validates a YAML rules document. The name is used
// in error messages only.
func ParseRules(data []byte, name string) ([]Rule, error) {
	var cfg RulesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%s: parse: %w", name, err)
	}
	if cfg.Version != 0 && cfg.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d (want 1)", name, cfg.Version)
	}
	switch cfg.Mode {
	case "", "extend", "replace":
	default:
		return nil, fmt.Errorf("%s: mode must be \"extend\" or \"replace\", got %q", name, cfg.Mode)
	}

	compiled := make([]Rule, 0, len(cfg.Rules))
	seen := map[string]bool{}
	for i, cr := range cfg.Rules {
		where := fmt.Sprintf("%s: rule %d (%s)", name, i+1, cr.ID)
		if cr.ID == "" {
			return nil, fmt.Errorf("%s: rules[%d]: id is required", name, i)
		}
		if seen[cr.ID] {
			return nil, fmt.Errorf("%s: duplicate rule id", where)
		}
		seen[cr.ID] = true
		if !validCategories[cr.Category] {
			return nil, fmt.Errorf("%s: unknown category %q", where, cr.Category)
		}
		if cr.Severity != "" && !validSeverities[cr.Severity] {
			return nil, fmt.Errorf("%s: unknown severity %q", where, cr.Severity)
		}
		if cr.Pattern == "" {
			return nil, fmt.Errorf("%s: pattern is required", where)
		}
		re, err := regexp.Compile(cr.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%s: bad pattern: %v", where, err)
		}
		name := cr.Name
		if name == "" {
			name = cr.ID
		}
		compiled = append(compiled, Rule{
			ID: cr.ID, Name: name, Category: cr.Category,
			Severity: cr.Severity, Pattern: re, MinHits: cr.MinHits,
		})
	}

	if cfg.Mode == "replace" {
		if len(compiled) == 0 {
			return nil, fmt.Errorf("%s: mode \"replace\" with no rules would disable DLP entirely", name)
		}
		return compiled, nil
	}

	// extend: config rules override built-ins by ID, then append.
	overridden := map[string]Rule{}
	for _, r := range compiled {
		overridden[r.ID] = r
	}
	out := make([]Rule, 0, len(DefaultRules)+len(compiled))
	for _, r := range DefaultRules {
		if o, ok := overridden[r.ID]; ok {
			out = append(out, o)
			delete(overridden, r.ID)
			continue
		}
		out = append(out, r)
	}
	for _, r := range compiled {
		if _, stillNew := overridden[r.ID]; stillNew {
			out = append(out, r)
		}
	}
	return out, nil
}

// RulesetVersion returns a stable content hash of the effective rule set,
// stamped onto receipts and events so an auditor can tie each decision to
// the exact rules that produced it. The built-in set hashes like any other.
func RulesetVersion(rules []Rule) string {
	lines := make([]string, 0, len(rules))
	for _, r := range rules {
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%d|%s", r.ID, r.Category, r.Severity, r.MinHits, r.Pattern.String()))
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return "dlp-" + hex.EncodeToString(h.Sum(nil))[:16]
}
