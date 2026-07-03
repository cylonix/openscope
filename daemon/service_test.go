// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/capabilities"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/passport"
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

func TestServiceHandleRefusesWhenAuditUnwritable(t *testing.T) {
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

	// Make the audit log unwritable by pointing it at a directory — an
	// authorized action must be refused rather than executed unlogged.
	auditDir := filepath.Join(home, "audit-as-dir")
	if err := os.Mkdir(auditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	paths.AuditFile = auditDir

	service := NewService(paths)
	// A distinctive output: if the executor had run, the response would carry it
	// instead of the audit-log refusal, proving the guard fires before execution.
	service.Executors["applescript"] = stubExecutor{result: executor.Result{Stdout: "{\"ran\":true}"}}

	response := service.Handle(ipc.Request{
		App: "notes", Action: "read_note", Agent: "demo",
		Params: map[string]string{"folder": "Work", "note": "Sprint Plan"}, Mode: "json",
	})

	if response.OK || response.ExitCode != ExitExecutorError {
		t.Fatalf("expected fail-closed refusal, got %#v", response)
	}
	if !strings.Contains(response.Error, "audit log") {
		t.Fatalf("expected an audit-log error (executor must not have run), got %q", response.Error)
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

// TestServiceHandleReflectorAttenuation proves the deny-only passport overlay:
// a reflected request must fall inside the passport scope AND the issuer's
// policy; the scope can only narrow below policy; the request executes (and is
// audited) as the issuer, tagged with the session + external delegatee.
func TestServiceHandleReflectorAttenuation(t *testing.T) {
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

	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - dev-a\n")
	// Policy lets dev-a tail logs on prod-api-1 for ANY service (no service constraint).
	writeFile(t, paths.PoliciesFile, "version: 1\nrules:\n  - effect: allow\n    agent: dev-a\n    app: ssh\n    action: tail_logs\n    constraints:\n      target: prod-api-1\n")

	service := NewService(paths)
	service.Executors["ssh"] = stubExecutor{result: executor.Result{Stdout: `{"output":"ok"}`}}

	// The passport narrows dev-a's surface to service=web only.
	scope := passport.NewScope([]capabilities.Capability{{
		App: "ssh", Action: "tail_logs",
		Params: []capabilities.Param{{Name: "service", PolicyKey: "service", Pinned: true, Fixed: "web"}},
	}})
	meta := RequestMeta{Transport: "reflector", AuthMethod: "reflector", SessionID: "sess-1", ExternalAgent: "vendor-b", Attenuation: &scope}

	mkReq := func(svc string) ipc.Request {
		return ipc.Request{App: "ssh", Action: "tail_logs", Agent: "dev-a",
			Params: map[string]string{"target": "prod-api-1", "service": svc, "lines": "20"}, Mode: "json"}
	}

	// In scope: service=web → both gates pass.
	if resp := service.HandleWithMeta(mkReq("web"), meta); !resp.OK {
		t.Fatalf("in-scope request should succeed, got %#v", resp)
	}
	// Out of scope: service=db → denied by the overlay even though policy allows it.
	if resp := service.HandleWithMeta(mkReq("db"), meta); resp.OK || resp.ExitCode != ExitDenied {
		t.Fatalf("out-of-scope request should be denied, got %#v", resp)
	}
	// Same request with NO overlay → policy alone allows it, proving the overlay is the blocker.
	if resp := service.HandleWithMeta(mkReq("db"), RequestMeta{}); !resp.OK {
		t.Fatalf("without the overlay, policy allows service=db; got %#v", resp)
	}

	text := string(mustReadFile(t, paths.AuditFile))
	if !strings.Contains(text, `"result":"out_of_scope"`) {
		t.Fatalf("expected an out_of_scope audit result, got:\n%s", text)
	}
	for _, want := range []string{`"transport":"reflector"`, `"external_agent":"vendor-b"`, `"session_id":"sess-1"`, `"agent":"dev-a"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected audit to contain %s, got:\n%s", want, text)
		}
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) returned error: %v", path, err)
	}
	return data
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) returned error: %v", path, err)
	}
}

// TestServiceHandleInspectBypassGate covers the security-relevant, no-network parts of
// the inspect_bypass built-in: it refuses to connect with an identity file outside the
// root-owned broker key dir (so a caller can't make the daemon use an arbitrary key),
// and rejects malformed requests, before any SSH connection is attempted.
func TestServiceHandleInspectBypassGate(t *testing.T) {
	home := t.TempDir()
	paths := config.Paths{
		ConfigDir:       filepath.Join(home, ".openscope"),
		AppsDir:         filepath.Join(home, ".openscope", "apps.d"),
		RunDir:          filepath.Join(home, ".openscope", "run"),
		StateDir:        filepath.Join(home, ".openscope", "state"),
		PoliciesFile:    filepath.Join(home, ".openscope", "policies.yaml"),
		AgentsFile:      filepath.Join(home, ".openscope", "agents.yaml"),
		AuditFile:       filepath.Join(home, ".openscope", "audit.jsonl"),
		EnabledAppsFile: filepath.Join(home, ".openscope", "state", "enabled_apps.yaml"),
		SocketPath:      filepath.Join(home, ".openscope", "run", "openscoped.sock"),
		AdminDir:        filepath.Join(home, "admin"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout: %v", err)
	}
	service := NewService(paths)

	req := func(target admin.SSHTarget) ipc.Request {
		tj, _ := json.Marshal(target)
		return ipc.Request{App: "ssh", Action: "inspect_bypass", Agent: "operator", Params: map[string]string{"target": string(tj), "keys": "[]"}}
	}

	// identity_file outside the broker key dir → denied, no connection attempted.
	resp := service.Handle(req(admin.SSHTarget{Alias: "x", Host: "h.example.com", User: "root", IdentityFile: "/root/.ssh/id_rsa"}))
	if resp.OK || resp.ExitCode != ExitDenied {
		t.Fatalf("non-broker identity_file must be denied, got %#v", resp)
	}

	// missing host → invalid.
	resp = service.Handle(req(admin.SSHTarget{Alias: "x", IdentityFile: "/var/openscope/ssh/x/id_rsa"}))
	if resp.OK || resp.ExitCode != ExitInvalid {
		t.Fatalf("missing host must be invalid, got %#v", resp)
	}

	// malformed target JSON → invalid.
	resp = service.Handle(ipc.Request{App: "ssh", Action: "inspect_bypass", Agent: "operator", Params: map[string]string{"target": "{not json", "keys": "[]"}})
	if resp.OK || resp.ExitCode != ExitInvalid {
		t.Fatalf("malformed target must be invalid, got %#v", resp)
	}
}
