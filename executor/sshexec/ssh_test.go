// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"encoding/json"
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
	result executor.Result
	err    error
}

func (s *stubRunner) Run(name string, args []string) (executor.Result, error) {
	s.name = name
	s.args = append([]string(nil), args...)
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
	remoteArgs := runner.args[len(runner.args)-6:]
	if strings.Join(remoteArgs, " ") != "journalctl -u web -n 25 --no-pager" {
		t.Fatalf("unexpected ssh args: %#v", runner.args)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &payload); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if payload["service"] != "web" {
		t.Fatalf("expected payload to include service, got %#v", payload)
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
