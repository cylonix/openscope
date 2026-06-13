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

func TestDefinitionPolicyContextIgnoresConstraintsForPassthroughApps(t *testing.T) {
	def := Definition{
		App: App{Name: "calendar", Executor: "applescript", SecurityMode: "passthrough"},
		Actions: map[string]Action{
			"list_events": {
				Parameters: []Parameter{
					{Name: "calendar", PolicyKey: "calendar"},
				},
			},
		},
	}

	got := def.PolicyContext("list_events", map[string]string{"calendar": "Work"})
	if len(got) != 0 {
		t.Fatalf("expected passthrough apps to ignore parameter constraints, got %#v", got)
	}
}

func TestValidateAcceptsCommandActionAndConstraints(t *testing.T) {
	def, err := Parse([]byte(`
version: 1
app:
  name: ssh
  executor: ssh
actions:
  write_file:
    command: "cat > {path}"
    stdin: "{content}"
    parameters:
      - {name: target, type: string, required: true, policy_key: target}
      - {name: path, type: string, required: true, constraint: path}
      - {name: content, type: string, required: true}
`), "test")
	if err != nil {
		t.Fatalf("command action should validate: %v", err)
	}
	a, ok := def.Action("write_file")
	if !ok || a.Command == "" || a.Stdin == "" {
		t.Fatalf("command/stdin not parsed: %+v", a)
	}
}

func TestValidateRejectsActionWithoutScriptOrCommand(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
app: {name: ssh, executor: ssh}
actions:
  frob:
    parameters:
      - {name: target, type: string, required: true}
`), "test")
	if err == nil {
		t.Fatal("an action with neither script nor command should be rejected")
	}
}

func TestValidateRejectsUnknownConstraint(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
app: {name: ssh, executor: ssh}
actions:
  x:
    command: "echo {y}"
    parameters:
      - {name: y, type: string, required: true, constraint: bogus}
`), "test")
	if err == nil {
		t.Fatal("unknown constraint should be rejected")
	}
}

func TestValidateRejectsUndeclaredPlaceholder(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
app: {name: ssh, executor: ssh}
actions:
  x:
    command: "cat {path}"
    parameters:
      - {name: target, type: string, required: true}
`), "test")
	if err == nil {
		t.Fatal("a template referencing an undeclared parameter should be rejected")
	}
}
