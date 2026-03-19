// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"errors"
	"fmt"
	"os"

	"github.com/agentscope/ascope/appdef"
	"github.com/agentscope/ascope/config"
	"gopkg.in/yaml.v3"
)

type File struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type Rule struct {
	Effect      string            `yaml:"effect"`
	Agent       string            `yaml:"agent"`
	App         string            `yaml:"app"`
	Action      string            `yaml:"action"`
	Constraints map[string]string `yaml:"constraints"`
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
	return Load(paths.PoliciesFile)
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
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write policy file: %w", err)
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

func rulesEqual(a, b Rule) bool {
	if a.Effect != b.Effect || a.Agent != b.Agent || a.App != b.App || a.Action != b.Action {
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

func (f File) Validate() error {
	if f.Version == 0 {
		return fmt.Errorf("policy version is required")
	}

	for i, rule := range f.Rules {
		if rule.Effect != "allow" && rule.Effect != "deny" {
			return fmt.Errorf("rule %d has invalid effect %q", i, rule.Effect)
		}
		if rule.Agent == "" || rule.App == "" || rule.Action == "" {
			return fmt.Errorf("rule %d must set agent, app, and action", i)
		}
	}

	return nil
}

func Evaluate(policyFile File, def appdef.Definition, actionName, agentID string, params map[string]string) Decision {
	action, ok := def.Action(actionName)
	if !ok {
		return Decision{Allowed: false, Reason: "unknown action"}
	}

	context := action.PolicyContext(params)
	var matchedAllow *Rule

	for i := range policyFile.Rules {
		rule := policyFile.Rules[i]
		if rule.Agent != agentID || rule.App != def.App.Name || rule.Action != actionName {
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

func matches(constraints, context map[string]string) bool {
	for key, expected := range constraints {
		actual, ok := context[key]
		if !ok || actual != expected {
			return false
		}
	}
	return true
}
