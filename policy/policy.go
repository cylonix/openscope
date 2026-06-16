// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"gopkg.in/yaml.v3"
)

type File struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type Rule struct {
	Effect string `yaml:"effect"`
	// Principal selectors. An empty selector is a wildcard; a set selector must
	// match the request principal. A rule must set at least one of Agent, User,
	// or Groups (see Validate) so it always names who it applies to.
	Agent  string   `yaml:"agent,omitempty"`
	User   string   `yaml:"user,omitempty"`
	Groups []string `yaml:"groups,omitempty"`

	App         string            `yaml:"app"`
	Action      string            `yaml:"action"`
	Constraints map[string]string `yaml:"constraints"`
}

// Principal is the authenticated identity a request is evaluated against: the
// agent (the acting tool) plus the user/groups (the human, when authenticated
// via an SSO proxy or a per-user token).
type Principal struct {
	Agent  string
	User   string
	Groups []string
}

type Decision struct {
	Allowed bool
	Reason  string
	Rule    *Rule
}

func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("read policy file: %w", err)
	}

	var policyFile File
	if err := yaml.Unmarshal(data, &policyFile); err != nil {
		return File{}, fmt.Errorf("parse policy file: %w", err)
	}

	return policyFile, policyFile.Validate()
}

func LoadDefault(paths config.Paths) (File, error) {
	return Load(defaultPoliciesPath(paths))
}

// defaultPoliciesPath returns the root-owned policy file, falling back to the
// legacy user-owned location only when the new one does not yet exist — so an
// install upgraded before its next `sudo apply` keeps enforcing its policy.
// Writes always target PoliciesFile (the root-owned location); the fallback is
// read-only.
func defaultPoliciesPath(paths config.Paths) string {
	if paths.LegacyPoliciesFile == "" {
		return paths.PoliciesFile
	}
	if _, err := os.Stat(paths.PoliciesFile); errors.Is(err, os.ErrNotExist) {
		if _, lerr := os.Stat(paths.LegacyPoliciesFile); lerr == nil {
			return paths.LegacyPoliciesFile
		}
	}
	return paths.PoliciesFile
}

func LoadDefaultOrEmpty(paths config.Paths) (File, error) {
	loaded, err := LoadDefault(paths)
	if err == nil {
		return loaded, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return File{Version: 1, Rules: []Rule{}}, nil
	}
	return File{}, err
}

func Save(path string, pf File) error {
	if pf.Version == 0 {
		pf.Version = 1
	}
	data, err := yaml.Marshal(pf)
	if err != nil {
		return fmt.Errorf("marshal policy file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create policy dir: %w", err)
	}
	// 0644: the policy lives root-owned in the admin dir and must stay readable
	// by the (non-root) daemon. Rules are authorization, not secrets. Chmod
	// explicitly so a restrictive umask (or a pre-existing 0600 file) can't leave
	// it unreadable by the daemon.
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write policy file: %w", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("chmod policy file: %w", err)
	}
	return nil
}

func SaveDefault(paths config.Paths, pf File) error {
	return Save(paths.PoliciesFile, pf)
}

// AddRule appends a rule to the policy file if an identical rule does not
// already exist. Returns the updated file and whether the rule was added.
func AddRule(paths config.Paths, rule Rule) (File, bool, error) {
	pf, err := LoadDefaultOrEmpty(paths)
	if err != nil {
		return File{}, false, err
	}
	for _, existing := range pf.Rules {
		if rulesEqual(existing, rule) {
			return pf, false, nil
		}
	}
	pf.Rules = append(pf.Rules, rule)
	if err := SaveDefault(paths, pf); err != nil {
		return File{}, false, err
	}
	return pf, true, nil
}

// RemoveRules removes every rule that matches the predicate and returns the
// updated file plus the number of removed rules.
func RemoveRules(paths config.Paths, predicate func(Rule) bool) (File, int, error) {
	pf, err := LoadDefaultOrEmpty(paths)
	if err != nil {
		return File{}, 0, err
	}

	filtered := make([]Rule, 0, len(pf.Rules))
	removed := 0
	for _, rule := range pf.Rules {
		if predicate(rule) {
			removed++
			continue
		}
		filtered = append(filtered, rule)
	}
	if removed == 0 {
		return pf, 0, nil
	}

	pf.Rules = filtered
	if err := SaveDefault(paths, pf); err != nil {
		return File{}, 0, err
	}
	return pf, removed, nil
}

func rulesEqual(a, b Rule) bool {
	if a.Effect != b.Effect || a.Agent != b.Agent || a.User != b.User || a.App != b.App || a.Action != b.Action {
		return false
	}
	if !equalStringSets(a.Groups, b.Groups) {
		return false
	}
	if len(a.Constraints) != len(b.Constraints) {
		return false
	}
	for k, v := range a.Constraints {
		if b.Constraints[k] != v {
			return false
		}
	}
	return true
}

// equalStringSets reports whether a and b contain the same elements,
// regardless of order or duplicates.
func equalStringSets(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; !ok {
			return false
		}
		delete(set, v)
	}
	return len(set) == 0
}

func (f File) Validate() error {
	if f.Version == 0 {
		return fmt.Errorf("policy version is required")
	}

	for i, rule := range f.Rules {
		if rule.Effect != "allow" && rule.Effect != "deny" {
			return fmt.Errorf("rule %d has invalid effect %q", i, rule.Effect)
		}
		if rule.App == "" || rule.Action == "" {
			return fmt.Errorf("rule %d must set app and action", i)
		}
		// A rule must name a principal — at least one of agent, user, or
		// group — so it can never match every request indiscriminately.
		if rule.Agent == "" && rule.User == "" && len(rule.Groups) == 0 {
			return fmt.Errorf("rule %d must set at least one of agent, user, or groups", i)
		}
	}

	return nil
}

func Evaluate(policyFile File, def appdef.Definition, actionName string, principal Principal, params map[string]string) Decision {
	if _, ok := def.Action(actionName); !ok {
		return Decision{Allowed: false, Reason: "unknown action"}
	}

	context := def.PolicyContext(actionName, params)
	var matchedAllow *Rule

	for i := range policyFile.Rules {
		rule := policyFile.Rules[i]
		if rule.App != def.App.Name || rule.Action != actionName {
			continue
		}
		if !matchesPrincipal(rule, principal) {
			continue
		}
		if !matches(rule.Constraints, context) {
			continue
		}
		if rule.Effect == "deny" {
			return Decision{
				Allowed: false,
				Reason:  "denied by matching policy rule",
				Rule:    &rule,
			}
		}
		if rule.Effect == "allow" && matchedAllow == nil {
			ruleCopy := rule
			matchedAllow = &ruleCopy
		}
	}

	if matchedAllow != nil {
		return Decision{
			Allowed: true,
			Reason:  "allowed by matching policy rule",
			Rule:    matchedAllow,
		}
	}

	return Decision{
		Allowed: false,
		Reason:  "no matching allow rule",
	}
}

// matchesPrincipal reports whether the rule's principal selectors all match
// the request principal. An empty selector is a wildcard; a set Agent or User
// must match exactly; a set Groups list matches when the principal belongs to
// at least one of the listed groups.
func matchesPrincipal(rule Rule, principal Principal) bool {
	if rule.Agent != "" && rule.Agent != principal.Agent {
		return false
	}
	if rule.User != "" && rule.User != principal.User {
		return false
	}
	if len(rule.Groups) > 0 && !anyGroupMatches(rule.Groups, principal.Groups) {
		return false
	}
	return true
}

func anyGroupMatches(ruleGroups, principalGroups []string) bool {
	for _, rg := range ruleGroups {
		if slices.Contains(principalGroups, rg) {
			return true
		}
	}
	return false
}

func matches(constraints, context map[string]string) bool {
	for key, expected := range constraints {
		actual, ok := context[key]
		if !ok || actual != expected {
			return false
		}
	}
	return true
}
