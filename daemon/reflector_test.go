// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/openscope/openscope/capabilities"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/reflector"
)

// fakeOpenTransport satisfies reflector.Transport for the control-path tests:
// CreateSession succeeds, and the serve loop's Fetch blocks until the session
// ctx is cancelled (no external client drives an exchange here).
type fakeOpenTransport struct{}

func (fakeOpenTransport) CreateSession(context.Context, reflector.SessionRequest) (string, error) {
	return "rdv_1", nil
}
func (fakeOpenTransport) Fetch(ctx context.Context, _ string) (reflector.Frame, error) {
	<-ctx.Done()
	return reflector.Frame{}, ctx.Err()
}
func (fakeOpenTransport) Send(context.Context, string, reflector.Frame) error { return nil }
func (fakeOpenTransport) CloseSession(context.Context, string) error          { return nil }

func reflectorPaths(t *testing.T) config.Paths {
	t.Helper()
	home := t.TempDir()
	paths := config.Paths{
		ConfigDir:             filepath.Join(home, ".openscope"),
		AppsDir:               filepath.Join(home, ".openscope", "apps.d"),
		RunDir:                filepath.Join(home, ".openscope", "run"),
		StateDir:              filepath.Join(home, ".openscope", "state"),
		PoliciesFile:          filepath.Join(home, ".openscope", "policies.yaml"),
		AgentsFile:            filepath.Join(home, ".openscope", "agents.yaml"),
		AuditFile:             filepath.Join(home, ".openscope", "audit.jsonl"),
		EnabledAppsFile:       filepath.Join(home, ".openscope", "state", "enabled_apps.yaml"),
		SocketPath:            filepath.Join(home, ".openscope", "run", "openscoped.sock"),
		AdminDir:              filepath.Join(home, "admin"),
		ProtectedFoldersFile:  filepath.Join(home, "admin", "protected_folders.yaml"),
		MailFiltersFile:       filepath.Join(home, "admin", "mail_filters.yaml"),
		SSHTargetsFile:        filepath.Join(home, "admin", "ssh_targets.yaml"),
		ReflectorURL:          "relay://test",
		ReflectorIdentityFile: filepath.Join(home, "admin", "reflector_identity"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout: %v", err)
	}
	return paths
}

func TestHandleReflectorOpenAndSubsetGuard(t *testing.T) {
	paths := reflectorPaths(t)
	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - dev-a\n")
	writeFile(t, paths.PoliciesFile, "version: 1\nrules:\n  - effect: allow\n    agent: dev-a\n    app: ssh\n    action: tail_logs\n    constraints:\n      target: prod-api-1\n")

	service := NewService(paths)
	_, identity, _ := ed25519.GenerateKey(rand.Reader)
	service.Reflector = reflector.NewManager(fakeOpenTransport{}, identity, "relay://test",
		func(sess *reflector.Session, req ipc.Request) ipc.Response {
			return service.reflectorDispatch(sess, req)
		},
		reflector.Options{})

	// Open: requested scope is dev-a's own ssh.tail_logs capability → allowed.
	surf, err := capabilities.BuildFromPaths(paths, "dev-a")
	if err != nil {
		t.Fatal(err)
	}
	scopeJSON, _ := json.Marshal(surf.Capabilities)
	resp := service.Handle(ipc.Request{App: "reflector", Action: "open", Agent: "dev-a",
		Params: map[string]string{"scope": string(scopeJSON), "ttl": "5m"}})
	if !resp.OK {
		t.Fatalf("open should succeed, got %#v", resp)
	}
	data, _ := resp.Data.(map[string]any)
	if data["handle"] == "" || data["id"] == "" || data["fingerprint"] == "" {
		t.Fatalf("open result missing fields: %+v", data)
	}

	// Subset guard: requesting a verb dev-a lacks is denied (not a privilege grant).
	bad, _ := json.Marshal([]capabilities.Capability{{App: "system", Action: "manage_packages"}})
	deny := service.Handle(ipc.Request{App: "reflector", Action: "open", Agent: "dev-a",
		Params: map[string]string{"scope": string(bad)}})
	if deny.OK || deny.ExitCode != ExitDenied {
		t.Fatalf("expected subset denial, got %#v", deny)
	}

	// list reflects the one open session.
	list := service.Handle(ipc.Request{App: "reflector", Action: "list", Agent: "dev-a"})
	if !list.OK {
		t.Fatalf("list failed: %#v", list)
	}
}

// TestReflectorTransportCannotInvokeControlVerbs proves a reflected session
// cannot reach the local-only management/diagnostic verbs (which short-circuit
// before the attenuation gate) — otherwise an external agent could open/list/
// close delegations or run an unscoped diagnostic as the issuer.
func TestReflectorTransportCannotInvokeControlVerbs(t *testing.T) {
	paths := reflectorPaths(t)
	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - dev-a\n")
	service := NewService(paths)

	meta := RequestMeta{Transport: "reflector", AuthMethod: "reflector", SessionID: "s1"}
	for _, req := range []ipc.Request{
		{App: "reflector", Action: "list", Agent: "dev-a"},
		{App: "reflector", Action: "open", Agent: "dev-a", Params: map[string]string{"scope": "[]"}},
		{App: "ssh", Action: "inspect_bypass", Agent: "dev-a"},
	} {
		resp := service.HandleWithMeta(req, meta)
		if resp.OK || resp.ExitCode != ExitDenied {
			t.Fatalf("reflected %s.%s must be denied, got %#v", req.App, req.Action, resp)
		}
	}
}

func TestHandleReflectorDisabled(t *testing.T) {
	paths := reflectorPaths(t)
	service := NewService(paths) // Reflector left nil
	resp := service.Handle(ipc.Request{App: "reflector", Action: "open", Agent: "x",
		Params: map[string]string{"scope": "[]"}})
	if resp.OK || resp.ExitCode != ExitConfigError {
		t.Fatalf("reflector disabled should return config error, got %#v", resp)
	}
}
