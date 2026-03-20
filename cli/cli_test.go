// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/config"
)

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
