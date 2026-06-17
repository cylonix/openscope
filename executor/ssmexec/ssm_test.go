// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ssmexec

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
)

// fakeRunner answers `aws ssm send-command` then `aws ssm get-command-invocation`
// without touching AWS — the seam that makes the executor unit-testable.
type fakeRunner struct {
	sendArgs []string
	send     executor.Result
	poll     executor.Result
}

func (f *fakeRunner) Run(_ string, args []string, _ io.Reader) (executor.Result, error) {
	if len(args) >= 2 && args[1] == "send-command" {
		f.sendArgs = args
		return f.send, nil
	}
	return f.poll, nil
}

func testDef() appdef.Definition {
	return appdef.Definition{
		App: appdef.App{Name: "ssm", Executor: "ssm", SecurityMode: "protected"},
		Actions: map[string]appdef.Action{
			"check_host": {Command: "hostname; whoami", Parameters: []appdef.Parameter{
				{Name: "target", PolicyKey: "target"}}},
			"read_file": {Command: "cat -- {path}", Parameters: []appdef.Parameter{
				{Name: "target", PolicyKey: "target"},
				{Name: "path", PolicyKey: "path", Constraint: "path"}}},
			"tail_logs": {Command: "journalctl -u {service} -n 200", Parameters: []appdef.Parameter{
				{Name: "target", PolicyKey: "target"},
				{Name: "service", PolicyKey: "service", Constraint: "service"}}},
		},
	}
}

// testExec writes an ssm_targets.yaml with one target and returns an Executor
// wired to the fake runner. AWS_SHARED_CREDENTIALS_FILE points at a nonexistent
// path so credaudit treats the broker as instance-role (passes) — the dev box's
// real ~/.aws/credentials would otherwise (correctly) make the executor refuse.
func testExec(t *testing.T, runner CommandRunner) Executor {
	t.Helper()
	dir := t.TempDir()
	tf := filepath.Join(dir, "ssm_targets.yaml")
	must(t, os.WriteFile(tf, []byte(`version: 1
targets:
  - alias: prod
    instance_id: i-0123
    region: us-west-2
    allowed_services: [orders-api]
    allowed_paths: [/etc/orders-api/version]
    allowed_path_prefixes: [/var/log]
`), 0o600))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "no-such-credentials"))
	return Executor{Paths: config.Paths{SSMTargetsFile: tf}, Runner: runner}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSSMCheckHostHappyPath(t *testing.T) {
	r := &fakeRunner{
		send: executor.Result{Stdout: "cmd-1\n"},
		poll: executor.Result{Stdout: `{"Status":"Success","StandardOutputContent":"ip-10-0-0-1\nroot\n"}`},
	}
	res, err := testExec(t, r).Run(testDef(), "check_host", map[string]string{"target": "prod"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// send-command targeted the right instance/region via AWS-RunShellScript.
	joined := strings.Join(r.sendArgs, " ")
	for _, want := range []string{"send-command", "i-0123", "us-west-2", "AWS-RunShellScript"} {
		if !strings.Contains(joined, want) {
			t.Errorf("send-command args missing %q: %v", want, r.sendArgs)
		}
	}
	// The fixed command travelled in a JSON --parameters value.
	if !strings.Contains(joined, "hostname; whoami") {
		t.Errorf("send-command did not carry the command: %v", r.sendArgs)
	}
	var out map[string]any
	must(t, json.Unmarshal([]byte(res.Stdout), &out))
	if out["target"] != "prod" || out["action"] != "check_host" || !strings.Contains(out["output"].(string), "ip-10-0-0-1") {
		t.Errorf("output = %v", out)
	}
}

func TestSSMReadFileEnforcesPathAllowList(t *testing.T) {
	r := &fakeRunner{
		send: executor.Result{Stdout: "cmd-2\n"},
		poll: executor.Result{Stdout: `{"Status":"Success","StandardOutputContent":"v1\n"}`},
	}
	e := testExec(t, r)

	// Allowed path → runs; the shell-quoted path is in the command.
	if _, err := e.Run(testDef(), "read_file", map[string]string{"target": "prod", "path": "/etc/orders-api/version"}); err != nil {
		t.Fatalf("allowed path: %v", err)
	}
	if !strings.Contains(strings.Join(r.sendArgs, " "), "cat -- '/etc/orders-api/version'") {
		t.Errorf("command not rendered with quoted path: %v", r.sendArgs)
	}
	// Disallowed path → refused before any send-command.
	if _, err := e.Run(testDef(), "read_file", map[string]string{"target": "prod", "path": "/etc/shadow"}); err == nil {
		t.Error("expected disallowed path to be rejected")
	}
}

func TestSSMTailLogsEnforcesServiceAllowList(t *testing.T) {
	r := &fakeRunner{
		send: executor.Result{Stdout: "cmd-3\n"},
		poll: executor.Result{Stdout: `{"Status":"Success","StandardOutputContent":""}`},
	}
	e := testExec(t, r)
	if _, err := e.Run(testDef(), "tail_logs", map[string]string{"target": "prod", "service": "nginx"}); err == nil {
		t.Error("expected disallowed service to be rejected")
	}
	if _, err := e.Run(testDef(), "tail_logs", map[string]string{"target": "prod", "service": "orders-api"}); err != nil {
		t.Errorf("allowed service: %v", err)
	}
}

func TestSSMSurfacesFailedInvocation(t *testing.T) {
	r := &fakeRunner{
		send: executor.Result{Stdout: "cmd-9\n"},
		poll: executor.Result{Stdout: `{"Status":"Failed","StandardErrorContent":"unit not found"}`},
	}
	_, err := testExec(t, r).Run(testDef(), "check_host", map[string]string{"target": "prod"})
	if err == nil || !strings.Contains(err.Error(), "unit not found") {
		t.Fatalf("want failed-invocation error, got %v", err)
	}
}

func TestSSMSendCommandError(t *testing.T) {
	r := &fakeRunner{send: executor.Result{Stderr: "AccessDenied", ExitCode: 255}}
	_, err := testExec(t, r).Run(testDef(), "check_host", map[string]string{"target": "prod"})
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("want send-command error, got %v", err)
	}
}

func TestSSMRefusesAgentReadableCredentials(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "ssm_targets.yaml")
	must(t, os.WriteFile(tf, []byte("version: 1\ntargets:\n  - {alias: prod, instance_id: i-0123, region: us-west-2}\n"), 0o600))
	// A user-owned (uid != 0) credentials file is agent-readable → refuse.
	creds := filepath.Join(dir, "credentials")
	must(t, os.WriteFile(creds, []byte("[default]\naws_access_key_id=AKIA\n"), 0o600))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)

	e := Executor{Paths: config.Paths{SSMTargetsFile: tf}, Runner: &fakeRunner{}}
	_, err := e.Run(testDef(), "check_host", map[string]string{"target": "prod"})
	if err == nil || !strings.Contains(err.Error(), "agent-accessible") {
		t.Fatalf("want credential-custody refusal, got %v", err)
	}
}
