// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
	"github.com/openscope/openscope/ipc"
)

type stubExecutor struct {
	result executor.Result
	err    error
}

func (s stubExecutor) Run(def appdef.Definition, actionName string, params map[string]string) (executor.Result, error) {
	return s.result, s.err
}

func TestServiceHandleAllowedRequest(t *testing.T) {
	home := t.TempDir()
	paths := config.Paths{
		ConfigDir:            filepath.Join(home, ".openscope"),
		AppsDir:              filepath.Join(home, ".openscope", "apps.d"),
		RunDir:               filepath.Join(home, ".openscope", "run"),
		StateDir:             filepath.Join(home, ".openscope", "state"),
		PoliciesFile:         filepath.Join(home, ".openscope", "policies.yaml"),
		AgentsFile:           filepath.Join(home, ".openscope", "agents.yaml"),
		AuditFile:            filepath.Join(home, ".openscope", "audit.jsonl"),
		EnabledAppsFile:      filepath.Join(home, ".openscope", "state", "enabled_apps.yaml"),
		SocketPath:           filepath.Join(home, ".openscope", "run", "openscoped.sock"),
		AdminDir:             filepath.Join(home, "admin"),
		ProtectedFoldersFile: filepath.Join(home, "admin", "protected_folders.yaml"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout returned error: %v", err)
	}

	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - demo\n")
	writeFile(t, paths.PoliciesFile, "version: 1\nrules:\n  - effect: allow\n    agent: demo\n    app: notes\n    action: read_note\n    constraints:\n      folder: Work\n")

	service := NewService(paths)
	service.Executors["applescript"] = stubExecutor{
		result: executor.Result{Stdout: "{\"title\":\"Sprint Plan\"}"},
	}

	response := service.Handle(ipc.Request{
		App:    "notes",
		Action: "read_note",
		Agent:  "demo",
		Params: map[string]string{"folder": "Work", "note": "Sprint Plan"},
		Mode:   "json",
	})

	if !response.OK {
		t.Fatalf("expected OK response, got %#v", response)
	}
	data, ok := response.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected map response data, got %#v", response.Data)
	}
	if data["title"] != "Sprint Plan" {
		t.Fatalf("expected decoded JSON output, got %#v", data)
	}
}

func TestServiceHandleProtectedFolderBlacklist(t *testing.T) {
	home := t.TempDir()
	paths := config.Paths{
		ConfigDir:            filepath.Join(home, ".openscope"),
		AppsDir:              filepath.Join(home, ".openscope", "apps.d"),
		RunDir:               filepath.Join(home, ".openscope", "run"),
		StateDir:             filepath.Join(home, ".openscope", "state"),
		PoliciesFile:         filepath.Join(home, ".openscope", "policies.yaml"),
		AgentsFile:           filepath.Join(home, ".openscope", "agents.yaml"),
		AuditFile:            filepath.Join(home, ".openscope", "audit.jsonl"),
		EnabledAppsFile:      filepath.Join(home, ".openscope", "state", "enabled_apps.yaml"),
		SocketPath:           filepath.Join(home, ".openscope", "run", "openscoped.sock"),
		AdminDir:             filepath.Join(home, "admin"),
		ProtectedFoldersFile: filepath.Join(home, "admin", "protected_folders.yaml"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout returned error: %v", err)
	}
	if err := os.MkdirAll(paths.AdminDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) returned error: %v", paths.AdminDir, err)
	}

	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - openclaw\n")
	writeFile(t, paths.PoliciesFile, "version: 1\nrules:\n  - effect: allow\n    agent: openclaw\n    app: notes\n    action: read_note\n")
	writeFile(t, paths.ProtectedFoldersFile, "version: 1\nkeywords:\n  - private\n")

	service := NewService(paths)
	service.Executors["applescript"] = stubExecutor{
		result: executor.Result{Stdout: "{\"title\":\"Private Note\"}"},
	}

	response := service.Handle(ipc.Request{
		App:    "notes",
		Action: "read_note",
		Agent:  "openclaw",
		Params: map[string]string{"folder": "Work Private", "note": "Roadmap"},
		Mode:   "json",
	})

	if response.OK {
		t.Fatalf("expected protected folder request to be denied, got %#v", response)
	}
	if response.ExitCode != ExitDenied {
		t.Fatalf("expected exit code %d, got %#v", ExitDenied, response)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) returned error: %v", path, err)
	}
}
