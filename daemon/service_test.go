// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"os"
	"path/filepath"
	"strings"
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
		MailFiltersFile:      filepath.Join(home, "admin", "mail_filters.yaml"),
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
		MailFiltersFile:      filepath.Join(home, "admin", "mail_filters.yaml"),
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

func TestServiceHandleMailDomainFiltering(t *testing.T) {
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
		MailFiltersFile:      filepath.Join(home, "admin", "mail_filters.yaml"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout returned error: %v", err)
	}
	if err := os.MkdirAll(paths.AdminDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) returned error: %v", paths.AdminDir, err)
	}

	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - openclaw\n")
	writeFile(t, paths.PoliciesFile, "version: 1\nrules:\n  - effect: allow\n    agent: openclaw\n    app: mail\n    action: list_messages\n    constraints:\n      mailbox: Inbox\n  - effect: allow\n    agent: openclaw\n    app: mail\n    action: read_message\n    constraints:\n      mailbox: Inbox\n")
	writeFile(t, paths.MailFiltersFile, "version: 1\nallowed_sender_domains:\n  - mycompany.com\n")

	service := NewService(paths)
	service.Executors["applescript"] = stubExecutor{
		result: executor.Result{Stdout: `[{"id":"1","mailbox":"Inbox","subject":"Allowed","sender":"alice@mycompany.com"},{"id":"2","mailbox":"Inbox","subject":"Blocked","sender":"mallory@gmail.com"}]`},
	}

	response := service.Handle(ipc.Request{
		App:    "mail",
		Action: "list_messages",
		Agent:  "openclaw",
		Params: map[string]string{"mailbox": "Inbox", "limit": "20", "unread": "true"},
		Mode:   "json",
	})
	if !response.OK {
		t.Fatalf("expected OK response, got %#v", response)
	}

	data, ok := response.Data.([]any)
	if !ok {
		t.Fatalf("expected list response, got %#v", response.Data)
	}
	if len(data) != 1 {
		t.Fatalf("expected 1 filtered message, got %#v", data)
	}

	service.Executors["applescript"] = stubExecutor{
		result: executor.Result{Stdout: `{"id":"2","mailbox":"Inbox","subject":"Blocked","sender":"mallory@gmail.com","body":"hello"}`},
	}
	response = service.Handle(ipc.Request{
		App:    "mail",
		Action: "read_message",
		Agent:  "openclaw",
		Params: map[string]string{"mailbox": "Inbox", "id": "2"},
		Mode:   "json",
	})
	if response.OK {
		t.Fatalf("expected blocked sender domain to be denied, got %#v", response)
	}
}

func TestServiceHandleSSHRequestAuditsTargetAndService(t *testing.T) {
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
		MailFiltersFile:      filepath.Join(home, "admin", "mail_filters.yaml"),
		SSHTargetsFile:       filepath.Join(home, "admin", "ssh_targets.yaml"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout returned error: %v", err)
	}

	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - openclaw\n")
	writeFile(t, paths.PoliciesFile, "version: 1\nrules:\n  - effect: allow\n    agent: openclaw\n    app: ssh\n    action: tail_logs\n    constraints:\n      target: prod-api-1\n      service: web\n")

	service := NewService(paths)
	service.Executors["ssh"] = stubExecutor{
		result: executor.Result{Stdout: `{"target":"prod-api-1","service":"web","lines":20,"output":"ok"}`},
	}

	response := service.Handle(ipc.Request{
		App:    "ssh",
		Action: "tail_logs",
		Agent:  "openclaw",
		Params: map[string]string{"target": "prod-api-1", "service": "web", "lines": "20"},
		Mode:   "json",
	})
	if !response.OK {
		t.Fatalf("expected OK response, got %#v", response)
	}

	auditData, err := os.ReadFile(paths.AuditFile)
	if err != nil {
		t.Fatalf("ReadFile(audit) returned error: %v", err)
	}
	text := string(auditData)
	if !strings.Contains(text, `"target":"prod-api-1"`) || !strings.Contains(text, `"service":"web"`) {
		t.Fatalf("expected audit to include target and service, got:\n%s", text)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) returned error: %v", path, err)
	}
}
