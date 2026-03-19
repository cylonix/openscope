// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appdef

import "testing"

func TestActionPolicyContextUsesPolicyKeys(t *testing.T) {
	action := Action{
		Parameters: []Parameter{
			{Name: "folder", PolicyKey: "folder"},
			{Name: "note", PolicyKey: "note_title"},
		},
	}

	got := action.PolicyContext(map[string]string{
		"folder": "Work",
		"note":   "Sprint Plan",
	})

	if got["folder"] != "Work" {
		t.Fatalf("expected folder policy key to be mapped")
	}
	if got["note_title"] != "Sprint Plan" {
		t.Fatalf("expected note_title policy key to be mapped")
	}
}
