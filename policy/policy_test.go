// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
)

func TestLoadDefaultFallsBackToLegacy(t *testing.T) {
	paths := config.Paths{
		PoliciesFile:       filepath.Join(t.TempDir(), "policies.yaml"),       // admin dir (absent)
		LegacyPoliciesFile: filepath.Join(t.TempDir(), "legacy-policies.yaml"), // user dir
	}
	// Only the legacy file exists → LoadDefault must read it (upgraded install
	// before its first `sudo apply` keeps enforcing policy).
	if err := Save(paths.LegacyPoliciesFile, File{Version: 1,
		Rules: []Rule{{Effect: "allow", Agent: "a", App: "ssh", Action: "read_file"}}}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDefault(paths)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Agent != "a" {
		t.Fatalf("expected the legacy rule, got %+v", got.Rules)
	}
	// Once the root-owned location exists, it wins; the legacy file is ignored.
	if err := SaveDefault(paths, File{Version: 1, Rules: []Rule{
		{Effect: "allow", Agent: "b", App: "ssh", Action: "read_file"},
		{Effect: "deny", Agent: "b", App: "ssh", Action: "list_dir"},
	}}); err != nil {
		t.Fatal(err)
	}
	got, err = LoadDefault(paths)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Rules) != 2 || got.Rules[0].Agent != "b" {
		t.Fatalf("root-owned location should win, got %+v", got.Rules)
	}
}

func TestSaveIsWorldReadableAndCreatesDir(t *testing.T) {
	// Daemon runs unprivileged and must read the root-owned policy, so Save must
	// leave it 0644 even under a restrictive umask, and create a missing dir.
	path := filepath.Join(t.TempDir(), "admin", "policies.yaml")
	if err := Save(path, File{Version: 1}); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("policy mode = %04o, want 0644", info.Mode().Perm())
	}
}

func TestEvaluateDenyOverridesAllow(t *testing.T) {
	def := appdef.Definition{
		App: appdef.App{Name: "notes"},
		Actions: map[string]appdef.Action{
			"read_note": {
				Parameters: []appdef.Parameter{
					{Name: "folder", PolicyKey: "folder"},
					{Name: "note", PolicyKey: "note"},
				},
			},
		},
	}

	pf := File{
		Version: 1,
		Rules: []Rule{
			{Effect: "allow", Agent: "demo", App: "notes", Action: "read_note", Constraints: map[string]string{"folder": "Work"}},
			{Effect: "deny", Agent: "demo", App: "notes", Action: "read_note", Constraints: map[string]string{"folder": "Work", "note": "Secret"}},
		},
	}

	decision := Evaluate(pf, def, "read_note", Principal{Agent: "demo"}, map[string]string{
		"folder": "Work",
		"note":   "Secret",
	})

	if decision.Allowed {
		t.Fatalf("expected deny rule to win")
	}
}

func TestEvaluateRequiresMatchingAllow(t *testing.T) {
	def := appdef.Definition{
		App: appdef.App{Name: "notes"},
		Actions: map[string]appdef.Action{
			"read_note": {
				Parameters: []appdef.Parameter{
					{Name: "folder", PolicyKey: "folder"},
				},
			},
		},
	}

	pf := File{
		Version: 1,
		Rules: []Rule{
			{Effect: "allow", Agent: "demo", App: "notes", Action: "read_note", Constraints: map[string]string{"folder": "Work"}},
		},
	}

	decision := Evaluate(pf, def, "read_note", Principal{Agent: "demo"}, map[string]string{
		"folder": "Personal",
	})

	if decision.Allowed {
		t.Fatalf("expected no matching allow to deny by default")
	}
}

func TestEvaluatePassthroughAppIgnoresParameterConstraints(t *testing.T) {
	def := appdef.Definition{
		App: appdef.App{Name: "calendar", SecurityMode: "passthrough"},
		Actions: map[string]appdef.Action{
			"list_events": {
				Parameters: []appdef.Parameter{
					{Name: "calendar", PolicyKey: "calendar"},
				},
			},
		},
	}

	pf := File{
		Version: 1,
		Rules: []Rule{
			{Effect: "allow", Agent: "openclaw", App: "calendar", Action: "list_events"},
		},
	}

	decision := Evaluate(pf, def, "list_events", Principal{Agent: "openclaw"}, map[string]string{
		"calendar": "Personal",
	})

	if !decision.Allowed {
		t.Fatalf("expected passthrough app allow rule without constraints to match, got deny: %s", decision.Reason)
	}
}

// sshDef is a minimal ssh app definition for principal-matching tests: one
// action with a target param used as a policy constraint.
func sshDef() appdef.Definition {
	return appdef.Definition{
		App: appdef.App{Name: "ssh"},
		Actions: map[string]appdef.Action{
			"restart_service": {
				Parameters: []appdef.Parameter{
					{Name: "target", PolicyKey: "target"},
				},
			},
		},
	}
}

func TestEvaluateUserScopedRule(t *testing.T) {
	def := sshDef()
	pf := File{Version: 1, Rules: []Rule{
		// No agent selector: any agent acting as alice@corp may restart prod-api.
		{Effect: "allow", User: "alice@corp", App: "ssh", Action: "restart_service",
			Constraints: map[string]string{"target": "prod-api"}},
	}}

	// alice, allowed target → allowed regardless of which agent.
	if d := Evaluate(pf, def, "restart_service",
		Principal{Agent: "claude-code", User: "alice@corp"},
		map[string]string{"target": "prod-api"}); !d.Allowed {
		t.Fatalf("alice on prod-api should be allowed: %s", d.Reason)
	}
	// bob, same target → no matching allow.
	if d := Evaluate(pf, def, "restart_service",
		Principal{Agent: "claude-code", User: "bob@corp"},
		map[string]string{"target": "prod-api"}); d.Allowed {
		t.Fatalf("bob should not match alice's rule")
	}
	// alice, different target → constraint mismatch.
	if d := Evaluate(pf, def, "restart_service",
		Principal{Agent: "claude-code", User: "alice@corp"},
		map[string]string{"target": "staging"}); d.Allowed {
		t.Fatalf("alice on staging should not match prod-api constraint")
	}
}

func TestEvaluateGroupScopedRule(t *testing.T) {
	def := sshDef()
	pf := File{Version: 1, Rules: []Rule{
		{Effect: "allow", Groups: []string{"sre"}, App: "ssh", Action: "restart_service"},
	}}

	// Principal in the sre group (among others) → allowed.
	if d := Evaluate(pf, def, "restart_service",
		Principal{User: "alice@corp", Groups: []string{"oncall", "sre"}}, nil); !d.Allowed {
		t.Fatalf("sre member should be allowed: %s", d.Reason)
	}
	// Principal not in any listed group → denied.
	if d := Evaluate(pf, def, "restart_service",
		Principal{User: "bob@corp", Groups: []string{"interns"}}, nil); d.Allowed {
		t.Fatalf("non-sre member should be denied")
	}
}

func TestEvaluateDenyOverridesUserAllow(t *testing.T) {
	def := sshDef()
	pf := File{Version: 1, Rules: []Rule{
		{Effect: "allow", Groups: []string{"sre"}, App: "ssh", Action: "restart_service"},
		// A targeted deny on one user wins even though the group allow matches.
		{Effect: "deny", User: "alice@corp", App: "ssh", Action: "restart_service"},
	}}
	if d := Evaluate(pf, def, "restart_service",
		Principal{User: "alice@corp", Groups: []string{"sre"}}, nil); d.Allowed {
		t.Fatalf("deny on alice must override the group allow")
	}
	// A different sre member is still allowed.
	if d := Evaluate(pf, def, "restart_service",
		Principal{User: "carol@corp", Groups: []string{"sre"}}, nil); !d.Allowed {
		t.Fatalf("carol should still be allowed: %s", d.Reason)
	}
}

func TestEvaluateAgentRuleIgnoresUser(t *testing.T) {
	// A legacy agent-only rule (no user/groups) keeps matching regardless of the
	// authenticated user — backward compatibility for existing policies.
	def := sshDef()
	pf := File{Version: 1, Rules: []Rule{
		{Effect: "allow", Agent: "ci-runner", App: "ssh", Action: "restart_service"},
	}}
	if d := Evaluate(pf, def, "restart_service",
		Principal{Agent: "ci-runner", User: "whoever@corp"}, nil); !d.Allowed {
		t.Fatalf("agent-only rule should match any user: %s", d.Reason)
	}
}

func TestValidateRequiresPrincipalSelector(t *testing.T) {
	// app+action but no agent/user/groups → invalid (would match everything).
	bad := File{Version: 1, Rules: []Rule{{Effect: "allow", App: "ssh", Action: "restart_service"}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected a rule with no principal selector to be invalid")
	}
	// A user-only rule is valid.
	ok := File{Version: 1, Rules: []Rule{{Effect: "allow", User: "alice@corp", App: "ssh", Action: "restart_service"}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("user-only rule should be valid: %v", err)
	}
}
