// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentscope/ascope/appdef"
	"github.com/agentscope/ascope/config"
	"github.com/agentscope/ascope/executor"
	"github.com/agentscope/ascope/ipc"
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
		ConfigDir:       filepath.Join(home, ".agentscope"),
		AppsDir:         filepath.Join(home, ".agentscope", "apps.d"),
		RunDir:          filepath.Join(home, ".agentscope", "run"),
		StateDir:        filepath.Join(home, ".agentscope", "state"),
		PoliciesFile:    filepath.Join(home, ".agentscope", "policies.yaml"),
		AgentsFile:      filepath.Join(home, ".agentscope", "agents.yaml"),
		AuditFile:       filepath.Join(home, ".agentscope", "audit.jsonl"),
		EnabledAppsFile: filepath.Join(home, ".agentscope", "state", "enabled_apps.yaml"),
		SocketPath:      filepath.Join(home, ".agentscope", "run", "ascoped.sock"),
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) returned error: %v", path, err)
	}
}
