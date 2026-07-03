// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appdef

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyRootOwnedRegistryRejectsNonRoot(t *testing.T) {
	// A registry a same-uid agent owns (or could rewrite) must not be trusted to
	// carry RootApplied command templates. Tests never run as root, so the temp
	// file is owned by the current (non-root) user — exactly the case to reject.
	path := filepath.Join(t.TempDir(), "app_definitions.yaml")
	if err := os.WriteFile(path, []byte("version: 1\napps: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyRootOwnedRegistry(path); err == nil {
		t.Fatal("expected a non-root-owned registry to be rejected")
	}
}

func TestVerifyRootOwnedRegistryMissingIsOK(t *testing.T) {
	// No registry means no custom verbs have been applied — not an error.
	if err := verifyRootOwnedRegistry(filepath.Join(t.TempDir(), "absent.yaml")); err != nil {
		t.Fatalf("missing registry should be fine, got: %v", err)
	}
}

func cmdDef(name, executor string, actions map[string]Action) Definition {
	return Definition{
		Version: 1,
		App:     App{Name: name, Executor: executor, SecurityMode: "protected"},
		Actions: actions,
	}
}

func writeAction(cmd string) Action {
	return Action{
		Description: "test",
		Parameters:  []Parameter{{Name: "path", Type: "string", Constraint: "path"}},
		Command:     cmd,
	}
}

func TestMergeUnionsActionsOverlayWins(t *testing.T) {
	base := cmdDef("ssh", "ssh", map[string]Action{
		"write_file": writeAction("cat > {path}"),
	})
	overlay := cmdDef("ssh", "ssh", map[string]Action{
		"gen_promo": writeAction("/opt/k/gen --path {path}"),
		// override an existing action
		"write_file": writeAction("tee {path}"),
	})
	merged, err := Merge(base, overlay)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(merged.Actions) != 2 {
		t.Fatalf("want 2 actions, got %d", len(merged.Actions))
	}
	if got := merged.Actions["write_file"].Command; got != "tee {path}" {
		t.Fatalf("overlay should win, got %q", got)
	}
	if _, ok := merged.Actions["gen_promo"]; !ok {
		t.Fatal("gen_promo not merged in")
	}
	// base must be untouched
	if got := base.Actions["write_file"].Command; got != "cat > {path}" {
		t.Fatalf("base mutated: %q", got)
	}
}

func TestMergeRejectsExecutorChange(t *testing.T) {
	base := cmdDef("ssh", "ssh", map[string]Action{"a": writeAction("x {path}")})
	overlay := cmdDef("ssh", "system", map[string]Action{"b": writeAction("y {path}")})
	if _, err := Merge(base, overlay); err == nil {
		t.Fatal("expected error on executor change")
	}
}

func TestAppliedFileRoundTripMarksRootApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app_definitions.yaml")
	in := []Definition{cmdDef("ssh", "ssh", map[string]Action{"gen_promo": writeAction("gen {path}")})}
	if err := SaveAppliedFile(path, in); err != nil {
		t.Fatalf("SaveAppliedFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("want 0644, got %v", info.Mode().Perm())
	}
	out, err := LoadAppliedFile(path)
	if err != nil {
		t.Fatalf("LoadAppliedFile: %v", err)
	}
	if len(out) != 1 || !out[0].RootApplied {
		t.Fatalf("expected one RootApplied def, got %#v", out)
	}
}

func TestLoadAppliedFileMissingIsNotError(t *testing.T) {
	defs, err := LoadAppliedFile(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if defs != nil {
		t.Fatalf("want nil, got %#v", defs)
	}
}

func TestAssembleDefinitionsRegistryWinsOverAppsDir(t *testing.T) {
	dir := t.TempDir()
	appsDir := filepath.Join(dir, "apps.d")
	if err := os.MkdirAll(appsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// agent-writable apps.d defines gen_promo with a tampered command
	userYAML := `version: 1
app: {name: ssh, executor: ssh, security_mode: protected}
actions:
  gen_promo:
    description: tampered
    parameters: [{name: path, type: string, constraint: path}]
    command: "evil {path}"
`
	if err := os.WriteFile(filepath.Join(appsDir, "ssh.yaml"), []byte(userYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(dir, "app_definitions.yaml")
	if err := SaveAppliedFile(registry, []Definition{
		cmdDef("ssh", "ssh", map[string]Action{"gen_promo": writeAction("pinned {path}")}),
	}); err != nil {
		t.Fatal(err)
	}
	bundled := []Definition{cmdDef("ssh", "ssh", map[string]Action{"write_file": writeAction("cat > {path}")})}

	// personal mode: apps.d is allowed, but the root registry still wins.
	defs, err := AssembleDefinitions(bundled, appsDir, registry, false)
	if err != nil {
		t.Fatalf("AssembleDefinitions: %v", err)
	}
	if got := defs["ssh"].Actions["gen_promo"].Command; got != "pinned {path}" {
		t.Fatalf("registry must win over apps.d, got %q", got)
	}
	if _, ok := defs["ssh"].Actions["write_file"]; !ok {
		t.Fatal("bundled write_file lost")
	}
}

func TestAssembleDefinitionsSystemModeDropsAppsDirCommandVerbs(t *testing.T) {
	dir := t.TempDir()
	appsDir := filepath.Join(dir, "apps.d")
	if err := os.MkdirAll(appsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	userYAML := `version: 1
app: {name: ssh, executor: ssh, security_mode: protected}
actions:
  rogue:
    description: rogue
    parameters: [{name: path, type: string, constraint: path}]
    command: "rogue {path}"
`
	if err := os.WriteFile(filepath.Join(appsDir, "ssh.yaml"), []byte(userYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	bundled := []Definition{cmdDef("ssh", "ssh", map[string]Action{"write_file": writeAction("cat > {path}")})}

	defs, err := AssembleDefinitions(bundled, appsDir, filepath.Join(dir, "none.yaml"), true)
	if err != nil {
		t.Fatalf("AssembleDefinitions: %v", err)
	}
	if _, ok := defs["ssh"].Actions["rogue"]; ok {
		t.Fatal("system mode must drop apps.d command-template verbs")
	}
	if _, ok := defs["ssh"].Actions["write_file"]; !ok {
		t.Fatal("bundled verb must survive")
	}
}

func TestRemoveDefinitionAction(t *testing.T) {
	list := []Definition{cmdDef("ssh", "ssh", map[string]Action{
		"a": writeAction("a {path}"),
		"b": writeAction("b {path}"),
	})}
	list = RemoveDefinitionAction(list, "ssh", "a")
	if len(list) != 1 || len(list[0].Actions) != 1 {
		t.Fatalf("want one app with one action, got %#v", list)
	}
	if _, ok := list[0].Actions["a"]; ok {
		t.Fatal("action a should be gone")
	}
	// removing the last action drops the app
	list = RemoveDefinitionAction(list, "ssh", "b")
	if len(list) != 0 {
		t.Fatalf("want empty list, got %#v", list)
	}
}
