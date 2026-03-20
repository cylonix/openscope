// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"testing"

	"github.com/openscope/openscope/appdef"
)

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
