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

	decision := Evaluate(pf, def, "read_note", "demo", map[string]string{
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

	decision := Evaluate(pf, def, "read_note", "demo", map[string]string{
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

	decision := Evaluate(pf, def, "list_events", "openclaw", map[string]string{
		"calendar": "Personal",
	})

	if !decision.Allowed {
		t.Fatalf("expected passthrough app allow rule without constraints to match, got deny: %s", decision.Reason)
	}
}
