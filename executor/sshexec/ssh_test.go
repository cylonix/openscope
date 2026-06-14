// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
)

type stubRunner struct {
	name   string
	args   []string
	stdin  string
	result executor.Result
	err    error
}

func (s *stubRunner) Run(name string, args []string, stdin io.Reader) (executor.Result, error) {
	s.name = name
	s.args = append([]string(nil), args...)
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		s.stdin = string(b)
	}
	return s.result, s.err
}

func TestExecutorTailLogsBuildsFixedSSHCommand(t *testing.T) {
	paths := config.Paths{
		SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"),
	}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias:           "prod-api-1",
			Host:            "prod-api-1.internal",
			User:            "deploy",
			AllowedServices: []string{"web"},
		}},
	}); err != nil {
		t.Fatalf("SaveSSHTargets returned error: %v", err)
	}

	runner := &stubRunner{result: executor.Result{Stdout: "line1\nline2\n", ExitCode: 0}}
	exec := Executor{Paths: paths, Runner: runner}

	result, err := exec.Run(appdef.Definition{}, "tail_logs", map[string]string{
		"target":  "prod-api-1",
		"service": "web",
		"lines":   "25",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if runner.name != "ssh" {
		t.Fatalf("expected ssh binary, got %q", runner.name)
	}
	if len(runner.args) < 8 {
		t.Fatalf("expected ssh args to be populated, got %#v", runner.args)
	}
	// The remote command is one ssh argument: ssh space-joins remote args and
	// the far-side shell re-parses, so each token is shell-quoted and joined
	// into a single string here (not handed to ssh as separate argv elements).
	remoteCommand := runner.args[len(runner.args)-1]
	if remoteCommand != "'journalctl' '-u' 'web' '-n' '25' '--no-pager'" {
		t.Fatalf("unexpected remote command: %q (all args: %#v)", remoteCommand, runner.args)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &payload); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if payload["service"] != "web" {
		t.Fatalf("expected payload to include service, got %#v", payload)
	}
}

// uploadDef builds a load_test_build-style verb: a local file (constraint:
// local_source) streamed to a remote command's stdin.
func uploadDef() appdef.Definition {
	return appdef.Definition{
		Version: 1,
		App:     appdef.App{Name: "ssh", Executor: "ssh", SecurityMode: "protected"},
		Actions: map[string]appdef.Action{
			"load_test_build": {
				StdinFile: "tar",
				Command:   "docker load",
				Parameters: []appdef.Parameter{
					{Name: "target", Type: "string", PolicyKey: "target"},
					{Name: "tar", Type: "string", Constraint: "local_source"},
				},
			},
		},
	}
}

func TestExecutorStreamsLocalFileToStdin(t *testing.T) {
	srcDir := t.TempDir()
	tarPath := filepath.Join(srcDir, "img.tar")
	if err := os.WriteFile(tarPath, []byte("IMAGE-TAR-BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml")}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias: "test", Host: "h", User: "deploy",
			AllowedUploadSources: []string{srcDir},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	runner := &stubRunner{result: executor.Result{Stdout: "Loaded image: x\n"}}
	exec := Executor{Paths: paths, Runner: runner}

	if _, err := exec.Run(uploadDef(), "load_test_build", map[string]string{
		"target": "test", "tar": tarPath,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.stdin != "IMAGE-TAR-BYTES" {
		t.Fatalf("expected the local file streamed to stdin, got %q", runner.stdin)
	}
	if got := runner.args[len(runner.args)-1]; got != "docker load" {
		t.Fatalf("remote command = %q", got)
	}
}

func TestExecutorRefusesUploadSourceOutsideAllowList(t *testing.T) {
	srcDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "evil.tar") // a DIFFERENT temp dir
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml")}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias: "test", Host: "h", User: "deploy",
			AllowedUploadSources: []string{srcDir},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	exec := Executor{Paths: paths, Runner: &stubRunner{}}
	if _, err := exec.Run(uploadDef(), "load_test_build", map[string]string{
		"target": "test", "tar": outside,
	}); err == nil {
		t.Fatal("expected refusal for an upload source outside allowed_upload_sources")
	}
}

// Regression: a host-inspection verb's command must reach the remote host as a
// SINGLE shell-safe argument. It previously went out as separate ssh args
// ("sh", "-lc", "printf '%s\n' ..."); ssh space-joins remote args and the
// far-side login shell re-parses, so `sh -c`'s argument collapsed to just
// "printf" and check_host/host_metrics failed with "printf: usage". The whole
// wrapped command — printf format string included — must now arrive intact in
// one argument.
func TestExecutorCheckHostSendsSingleRemoteCommand(t *testing.T) {
	runner := &stubRunner{result: executor.Result{Stdout: "h\nu\n0\nLinux\n6.1\n", ExitCode: 0}}
	exec := Executor{Paths: writeTargetPaths(t), Runner: runner}

	if _, err := exec.Run(appdef.Definition{}, "check_host", map[string]string{"target": "prod-api-1"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Exactly one remote argument after the host — not split into sh/-lc/printf.
	host := "deploy@prod-api-1.internal"
	hostIdx := -1
	for i, a := range runner.args {
		if a == host {
			hostIdx = i
		}
	}
	if hostIdx == -1 || hostIdx != len(runner.args)-2 {
		t.Fatalf("expected exactly one remote arg after host; args=%#v", runner.args)
	}

	// That one argument carries the whole wrapped command, with the printf
	// format string still attached to printf (losing it was the old symptom).
	// The inner command is shell-quoted, so its own single quotes become '\''.
	remoteCommand := runner.args[len(runner.args)-1]
	for _, want := range []string{"'sh' '-lc'", "printf", "%s\\n", "$(hostname)", "$(uname -r)"} {
		if !strings.Contains(remoteCommand, want) {
			t.Fatalf("remote command missing %q; got single arg %q", want, remoteCommand)
		}
	}
}

func TestExecutorRejectsUnknownTarget(t *testing.T) {
	exec := Executor{
		Paths: config.Paths{SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml")},
	}
	if _, err := exec.Run(appdef.Definition{}, "check_host", map[string]string{"target": "missing"}); err == nil {
		t.Fatalf("expected missing target to fail")
	}
}

func TestExecutorRejectsUnapprovedServiceAndPath(t *testing.T) {
	paths := config.Paths{
		SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"),
	}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias:               "prod-api-1",
			Host:                "prod-api-1.internal",
			User:                "deploy",
			AllowedServices:     []string{"web"},
			AllowedPathPrefixes: []string{"/var/log/app"},
		}},
	}); err != nil {
		t.Fatalf("SaveSSHTargets returned error: %v", err)
	}

	exec := Executor{Paths: paths, Runner: &stubRunner{}}
	if _, err := exec.Run(appdef.Definition{}, "service_status", map[string]string{"target": "prod-api-1", "service": "db"}); err == nil {
		t.Fatalf("expected unapproved service to fail")
	}
	if _, err := exec.Run(appdef.Definition{}, "read_file", map[string]string{"target": "prod-api-1", "path": "/etc/passwd"}); err == nil {
		t.Fatalf("expected unapproved path to fail")
	}
}

func TestExecutorEnforcesTailLineBounds(t *testing.T) {
	paths := config.Paths{
		SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"),
	}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias:           "prod-api-1",
			Host:            "prod-api-1.internal",
			User:            "deploy",
			AllowedServices: []string{"web"},
		}},
	}); err != nil {
		t.Fatalf("SaveSSHTargets returned error: %v", err)
	}

	exec := Executor{Paths: paths, Runner: &stubRunner{}}
	if _, err := exec.Run(appdef.Definition{}, "tail_logs", map[string]string{
		"target":  "prod-api-1",
		"service": "web",
		"lines":   "999",
	}); err == nil {
		t.Fatalf("expected oversized line request to fail")
	}
}

// writeFileDef is the command-template action used by the generic-verb tests.
func writeFileDef() appdef.Definition {
	return appdef.Definition{
		Version: 1,
		App:     appdef.App{Name: "ssh", Executor: "ssh"},
		Actions: map[string]appdef.Action{
			"write_file": {
				Command: "cat > {path}",
				Stdin:   "{content}",
				Parameters: []appdef.Parameter{
					{Name: "target", Type: "string", Required: true, PolicyKey: "target"},
					{Name: "path", Type: "string", Required: true, Constraint: "path"},
					{Name: "content", Type: "string", Required: true},
				},
			},
		},
	}
}

func writeTargetPaths(t *testing.T) config.Paths {
	t.Helper()
	paths := config.Paths{SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml")}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias:               "prod-api-1",
			Host:                "prod-api-1.internal",
			User:                "deploy",
			AllowedPathPrefixes: []string{"/var/log/app"},
		}},
	}); err != nil {
		t.Fatalf("SaveSSHTargets: %v", err)
	}
	return paths
}

// A user-defined write verb (no built-in handler) runs from its command
// template: the path is constrained + quoted, the content is piped to stdin.
func TestExecutorCommandActionWritesViaStdin(t *testing.T) {
	runner := &stubRunner{result: executor.Result{ExitCode: 0}}
	exec := Executor{Paths: writeTargetPaths(t), Runner: runner}

	_, err := exec.Run(writeFileDef(), "write_file", map[string]string{
		"target":  "prod-api-1",
		"path":    "/var/log/app/note.txt",
		"content": "hello\nworld",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	last := runner.args[len(runner.args)-1]
	if last != "cat > '/var/log/app/note.txt'" {
		t.Fatalf("unexpected remote command: %q", last)
	}
	if runner.stdin != "hello\nworld" {
		t.Fatalf("unexpected stdin: %q", runner.stdin)
	}
}

// A path containing shell metacharacters is single-quoted, so it can never
// break out of the template into an injected command.
func TestExecutorCommandActionQuotesAgainstInjection(t *testing.T) {
	runner := &stubRunner{result: executor.Result{ExitCode: 0}}
	exec := Executor{Paths: writeTargetPaths(t), Runner: runner}

	if _, err := exec.Run(writeFileDef(), "write_file", map[string]string{
		"target":  "prod-api-1",
		"path":    "/var/log/app/x;rm -rf /tmp",
		"content": "x",
	}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	last := runner.args[len(runner.args)-1]
	if last != "cat > '/var/log/app/x;rm -rf /tmp'" {
		t.Fatalf("path was not safely quoted: %q", last)
	}
}

// A constrained path outside the target's allow-list is rejected before any ssh.
func TestExecutorCommandActionEnforcesPathConstraint(t *testing.T) {
	runner := &stubRunner{}
	exec := Executor{Paths: writeTargetPaths(t), Runner: runner}

	if _, err := exec.Run(writeFileDef(), "write_file", map[string]string{
		"target":  "prod-api-1",
		"path":    "/etc/passwd",
		"content": "x",
	}); err == nil {
		t.Fatal("expected write to a non-allowed path to be rejected")
	}
	if runner.name != "" {
		t.Fatal("ssh should not have run for a rejected path")
	}
}

// An action with no built-in handler and no command template is a clear error.
func TestExecutorCommandActionRequiresCommand(t *testing.T) {
	def := appdef.Definition{
		App:     appdef.App{Name: "ssh", Executor: "ssh"},
		Actions: map[string]appdef.Action{"frob": {}},
	}
	exec := Executor{Paths: writeTargetPaths(t), Runner: &stubRunner{}}
	if _, err := exec.Run(def, "frob", map[string]string{"target": "prod-api-1"}); err == nil {
		t.Fatal("expected an action with no command to error")
	}
}

func TestExecutorServiceStatusParsesSystemctlFields(t *testing.T) {
	paths := config.Paths{
		SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"),
	}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias:           "prod-api-1",
			Host:            "prod-api-1.internal",
			User:            "deploy",
			AllowedServices: []string{"web"},
		}},
	}); err != nil {
		t.Fatalf("SaveSSHTargets returned error: %v", err)
	}

	runner := &stubRunner{result: executor.Result{
		Stdout:   "Id=web.service\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n",
		ExitCode: 0,
	}}
	exec := Executor{Paths: paths, Runner: runner}

	result, err := exec.Run(appdef.Definition{}, "service_status", map[string]string{
		"target":  "prod-api-1",
		"service": "web",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &payload); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if payload["id"] != "web.service" || payload["active_state"] != "active" || payload["sub_state"] != "running" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

// The ssh executor (root daemon) must REFUSE to run an action when the
// configured key is agent-accessible — a key the agent can read lets it ssh
// directly, bypassing the broker. Refusal happens before any ssh runs.
func TestExecutorRefusesAgentReadableKey(t *testing.T) {
	home := t.TempDir()
	// An agent-readable identity_file: user-owned, world-readable (mode 0644).
	key := filepath.Join(home, "agent_key")
	if err := os.WriteFile(key, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"), HomeDir: home}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias: "prod", Host: "p.internal", User: "deploy", IdentityFile: key,
			AllowedPathPrefixes: []string{"/var/log"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	runner := &stubRunner{}
	exec := Executor{Paths: paths, Runner: runner}

	if _, err := exec.Run(appdef.Definition{}, "check_host", map[string]string{"target": "prod"}); err == nil {
		t.Fatal("expected refusal when the brokered key is agent-readable")
	}
	if runner.name != "" {
		t.Fatal("ssh must not run when the key is refused")
	}
}

// The broker's real ssh uses accept-new + a broker-owned, root-owned
// known_hosts — host-key trust belongs to the broker, and a changed key is
// rejected, without pre-seeding every host.
func TestExecutorUsesAcceptNewAndBrokerKnownHosts(t *testing.T) {
	runner := &stubRunner{result: executor.Result{Stdout: "x\nx\nx\nx\nx\n", ExitCode: 0}}
	exec := Executor{Paths: writeTargetPaths(t), Runner: runner}

	if _, err := exec.Run(appdef.Definition{}, "check_host", map[string]string{"target": "prod-api-1"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	joined := strings.Join(runner.args, " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=accept-new") {
		t.Errorf("expected accept-new, got: %s", joined)
	}
	if !strings.Contains(joined, "UserKnownHostsFile="+brokerSSHDir+"/known_hosts") {
		t.Errorf("expected broker-owned known_hosts, got: %s", joined)
	}
	if strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Error("must not use the brittle =yes anymore")
	}
}
