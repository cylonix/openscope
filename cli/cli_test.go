// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/policy"
)

func TestBuildCapabilityRendersCommandAndHints(t *testing.T) {
	defs := map[string]appdef.Definition{
		"ssh": {
			Version: 1,
			App:     appdef.App{Name: "ssh", Executor: "ssh", SecurityMode: "protected"},
			Actions: map[string]appdef.Action{
				"read_file": {
					Description: "Read an approved file from a target",
					Parameters: []appdef.Parameter{
						{Name: "target", Type: "string", Required: true, PolicyKey: "target"},
						{Name: "path", Type: "string", Required: true, PolicyKey: "path"},
					},
					Script: "read_file",
				},
				"tail_logs": {
					Description: "Tail logs",
					Parameters: []appdef.Parameter{
						{Name: "target", Type: "string", Required: true, PolicyKey: "target"},
						{Name: "service", Type: "string", Required: true, PolicyKey: "service"},
						{Name: "lines", Type: "integer", Required: false},
					},
					Script: "tail_logs",
				},
			},
		},
	}
	targets := admin.SSHTargets{Targets: []admin.SSHTarget{{
		Alias: "prod", Host: "h", User: "root",
		AllowedServices:     []string{"nginx"},
		AllowedPaths:        []string{"/etc/nginx/nginx.conf"},
		AllowedPathPrefixes: []string{"/var/log/nginx"},
	}}}

	// read_file: target is pinned by the rule; path is free with a prefix hint.
	rf := buildCapability("ag", policy.Rule{Effect: "allow", Agent: "ag", App: "ssh", Action: "read_file",
		Constraints: map[string]string{"target": "prod"}}, defs, targets)
	if want := "openscope ssh read_file --agent ag --target prod --path <path>"; rf.Command != want {
		t.Fatalf("read_file command = %q, want %q", rf.Command, want)
	}
	var pathHint, targetFixed string
	for _, p := range rf.Params {
		switch p.Flag {
		case "--path":
			pathHint = p.Hint
		case "--target":
			targetFixed = p.Fixed
		}
	}
	if targetFixed != "prod" {
		t.Fatalf("--target should be pinned to prod, got %q", targetFixed)
	}
	if !strings.Contains(pathHint, "/etc/nginx/nginx.conf") || !strings.Contains(pathHint, "/var/log/nginx/*") {
		t.Fatalf("path hint missing allowed paths: %q", pathHint)
	}

	// tail_logs: service free (hint = allowed services), optional lines in brackets.
	tl := buildCapability("ag", policy.Rule{Effect: "allow", Agent: "ag", App: "ssh", Action: "tail_logs",
		Constraints: map[string]string{"target": "prod"}}, defs, targets)
	if want := "openscope ssh tail_logs --agent ag --target prod --service <service> [--lines <lines>]"; tl.Command != want {
		t.Fatalf("tail_logs command = %q, want %q", tl.Command, want)
	}

	// An allow rule for an action that no longer exists is rendered inert, not dropped.
	bad := buildCapability("ag", policy.Rule{Effect: "allow", Agent: "ag", App: "ssh", Action: "nope"}, defs, targets)
	if bad.Note == "" {
		t.Fatalf("expected an inert note for an unknown action, got none")
	}
}

func TestRunInitWritesDefaultConfig(t *testing.T) {
	home := t.TempDir()
	paths := config.Paths{
		HomeDir:         home,
		ConfigDir:       filepath.Join(home, ".openscope"),
		AppsDir:         filepath.Join(home, ".openscope", "apps.d"),
		RunDir:          filepath.Join(home, ".openscope", "run"),
		StateDir:        filepath.Join(home, ".openscope", "state"),
		PoliciesFile:    filepath.Join(home, ".openscope", "policies.yaml"),
		AgentsFile:      filepath.Join(home, ".openscope", "agents.yaml"),
		AuditFile:       filepath.Join(home, ".openscope", "audit.jsonl"),
		EnabledAppsFile: filepath.Join(home, ".openscope", "state", "enabled_apps.yaml"),
		SocketPath:      filepath.Join(home, ".openscope", "run", "openscoped.sock"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout returned error: %v", err)
	}

	code := runInit(paths, nil)
	if code != 0 {
		t.Fatalf("runInit returned code %d", code)
	}

	agentsData, err := os.ReadFile(paths.AgentsFile)
	if err != nil {
		t.Fatalf("ReadFile(agents) returned error: %v", err)
	}
	if !strings.Contains(string(agentsData), "openclaw") {
		t.Fatalf("expected openclaw in agents file, got:\n%s", agentsData)
	}

	policyData, err := os.ReadFile(paths.PoliciesFile)
	if err != nil {
		t.Fatalf("ReadFile(policy) returned error: %v", err)
	}
	if strings.Contains(string(policyData), "list_folders") {
		t.Fatalf("did not expect list_folders in default policy, got:\n%s", policyData)
	}
	if !strings.Contains(string(policyData), "app: mail") || !strings.Contains(string(policyData), "mailbox: Inbox") {
		t.Fatalf("expected Inbox-only mail defaults in policy, got:\n%s", policyData)
	}
}

func TestRunInitRequiresForceToOverwriteExistingConfig(t *testing.T) {
	home := t.TempDir()
	paths := config.Paths{
		HomeDir:         home,
		ConfigDir:       filepath.Join(home, ".openscope"),
		AppsDir:         filepath.Join(home, ".openscope", "apps.d"),
		RunDir:          filepath.Join(home, ".openscope", "run"),
		StateDir:        filepath.Join(home, ".openscope", "state"),
		PoliciesFile:    filepath.Join(home, ".openscope", "policies.yaml"),
		AgentsFile:      filepath.Join(home, ".openscope", "agents.yaml"),
		AuditFile:       filepath.Join(home, ".openscope", "audit.jsonl"),
		EnabledAppsFile: filepath.Join(home, ".openscope", "state", "enabled_apps.yaml"),
		SocketPath:      filepath.Join(home, ".openscope", "run", "openscoped.sock"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout returned error: %v", err)
	}
	if err := os.WriteFile(paths.AgentsFile, []byte("version: 1\nagents:\n  - custom\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	code := runInit(paths, nil)
	if code != 3 {
		t.Fatalf("runInit without force returned code %d, want 3", code)
	}

	code = runInit(paths, []string{"--force"})
	if code != 0 {
		t.Fatalf("runInit with force returned code %d", code)
	}
}

func TestApplyBundledPassthroughActivationAddsAndRemovesRules(t *testing.T) {
	home := t.TempDir()
	paths := config.Paths{
		HomeDir:         home,
		ConfigDir:       filepath.Join(home, ".openscope"),
		AppsDir:         filepath.Join(home, ".openscope", "apps.d"),
		RunDir:          filepath.Join(home, ".openscope", "run"),
		StateDir:        filepath.Join(home, ".openscope", "state"),
		PoliciesFile:    filepath.Join(home, ".openscope", "policies.yaml"),
		AgentsFile:      filepath.Join(home, ".openscope", "agents.yaml"),
		AuditFile:       filepath.Join(home, ".openscope", "audit.jsonl"),
		EnabledAppsFile: filepath.Join(home, ".openscope", "state", "enabled_apps.yaml"),
		SocketPath:      filepath.Join(home, ".openscope", "run", "openscoped.sock"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout returned error: %v", err)
	}

	defs := map[string]appdef.Definition{
		"calendar": {
			Bundled: true,
			App: appdef.App{
				Name:         "calendar",
				Executor:     "applescript",
				SecurityMode: "passthrough",
			},
			Actions: map[string]appdef.Action{
				"list_calendars": {},
				"list_events":    {},
			},
		},
	}

	results, exitCode, err := applyBundledPassthroughActivation(paths, defs, "openclaw", []string{"calendar"}, true)
	if err != nil || exitCode != 0 {
		t.Fatalf("activate returned exit=%d err=%v", exitCode, err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one activation result, got %#v", results)
	}

	pf, err := policy.LoadDefault(paths)
	if err != nil {
		t.Fatalf("LoadDefault returned error: %v", err)
	}
	if len(pf.Rules) != 2 {
		t.Fatalf("expected 2 rules after activation, got %#v", pf.Rules)
	}

	_, exitCode, err = applyBundledPassthroughActivation(paths, defs, "openclaw", []string{"calendar"}, false)
	if err != nil || exitCode != 0 {
		t.Fatalf("deactivate returned exit=%d err=%v", exitCode, err)
	}
	pf, err = policy.LoadDefault(paths)
	if err != nil {
		t.Fatalf("LoadDefault returned error: %v", err)
	}
	if len(pf.Rules) != 0 {
		t.Fatalf("expected no rules after deactivation, got %#v", pf.Rules)
	}
}

func TestLoadBundledDefinitionsIncludesSSH(t *testing.T) {
	defs, err := loadBundledDefinitions()
	if err != nil {
		t.Fatalf("loadBundledDefinitions returned error: %v", err)
	}

	found := false
	for _, def := range defs {
		if def.App.Name == "ssh" {
			found = true
			if def.App.Executor != "ssh" {
				t.Fatalf("expected ssh executor, got %#v", def.App)
			}
			if def.App.SecurityMode != "protected" {
				t.Fatalf("expected protected security mode, got %#v", def.App)
			}
			if _, ok := def.Actions["restart_service"]; !ok {
				t.Fatalf("expected restart_service action in ssh manifest")
			}
		}
	}
	if !found {
		t.Fatalf("expected bundled ssh app definition")
	}
}
