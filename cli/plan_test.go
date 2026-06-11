// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"path/filepath"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/policy"
	"github.com/openscope/openscope/proposal"
)

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	dir := t.TempDir()
	admDir := t.TempDir()
	return config.Paths{
		ConfigDir:          dir,
		PoliciesFile:       filepath.Join(dir, "policies.yaml"),
		AgentsFile:         filepath.Join(dir, "agents.yaml"),
		AuditFile:          filepath.Join(dir, "audit.jsonl"),
		AdminDir:           admDir,
		SSHTargetsFile:     filepath.Join(admDir, "ssh_targets.yaml"),
		SystemCommandsFile: filepath.Join(admDir, "system_commands.yaml"),
	}
}

const applyProposalYAML = `
version: 1
kind: openscope-proposal
metadata: {name: apply-test}
ssh_targets:
  add:
    - {alias: web, host: web.example.com, user: deploy, allowed_services: [nginx], allowed_path_prefixes: [/var/log/nginx]}
system_commands:
  packages:
    managers: {add: [{name: brew, sudo: false, binary: /opt/homebrew/bin/brew}]}
    allowed: {add: [jq]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: web}}
    - {effect: deny, agent: bot, app: system, action: manage_services, constraints: {service: com.apple.mDNSResponder}}
`

// applyHelper loads the current live system state and applies the proposal,
// mirroring how runApply threads the plan-time snapshot into applyProposal.
func applyHelper(t *testing.T, paths config.Paths, p proposal.Proposal) error {
	t.Helper()
	live, err := admin.LoadSystemCommandsOrDefault(paths)
	if err != nil {
		t.Fatalf("load live system: %v", err)
	}
	return applyProposal(paths, p, live)
}

func TestApplyProposalWritesThroughAdminPaths(t *testing.T) {
	paths := testPaths(t)
	p, err := proposal.Parse([]byte(applyProposalYAML), "apply-test.yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := applyHelper(t, paths, p); err != nil {
		t.Fatalf("applyProposal: %v", err)
	}

	targets, err := admin.LoadSSHTargetsOrDefault(paths)
	if err != nil {
		t.Fatalf("load targets: %v", err)
	}
	if _, ok := admin.FindSSHTarget(targets, "web"); !ok {
		t.Error("ssh target web not written")
	}

	sys, err := admin.LoadSystemCommandsOrDefault(paths)
	if err != nil {
		t.Fatalf("load system: %v", err)
	}
	if _, ok := admin.FindManager(sys, "brew"); !ok {
		t.Error("brew manager not written")
	}
	if !admin.AllowsPackage(sys, "jq") {
		t.Error("jq package not allowed after apply")
	}

	pf, err := policy.LoadDefaultOrEmpty(paths)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if len(pf.Rules) != 2 {
		t.Errorf("expected 2 policy rules, got %d", len(pf.Rules))
	}
}

func TestApplyProposalConflictOnDifferingTarget(t *testing.T) {
	paths := testPaths(t)
	// Pre-seed a target with the same alias but different host.
	if _, _, err := admin.AddSSHTarget(paths, admin.SSHTarget{
		Alias: "web", Host: "OLD.example.com", User: "deploy",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	p, _ := proposal.Parse([]byte(applyProposalYAML), "x")
	err := applyHelper(t, paths, p)
	if err == nil {
		t.Error("expected conflict error when re-adding target with different settings")
	}
}

func TestApplyProposalRollsBackOnError(t *testing.T) {
	paths := testPaths(t)
	// Pre-seed web2 with settings that will conflict with the proposal.
	if _, _, err := admin.AddSSHTarget(paths, admin.SSHTarget{
		Alias: "web2", Host: "OLD.example.com", User: "deploy",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Proposal adds a brand-new target "web" (succeeds) then "web2" (conflicts).
	src := `
version: 1
kind: openscope-proposal
metadata: {name: rollback-test}
ssh_targets:
  add:
    - {alias: web, host: web.example.com, user: deploy, allowed_path_prefixes: [/var/log]}
    - {alias: web2, host: NEW.example.com, user: deploy}
`
	p, _ := proposal.Parse([]byte(src), "x")
	if err := applyHelper(t, paths, p); err == nil {
		t.Fatal("expected conflict error")
	}
	// The successful "web" add must have been rolled back.
	targets, _ := admin.LoadSSHTargetsOrDefault(paths)
	if _, ok := admin.FindSSHTarget(targets, "web"); ok {
		t.Error("partial apply not rolled back: target web still present")
	}
	if t2, ok := admin.FindSSHTarget(targets, "web2"); !ok || t2.Host != "OLD.example.com" {
		t.Error("pre-existing web2 should be unchanged after rollback")
	}
}

func TestApplyProposalIdempotent(t *testing.T) {
	paths := testPaths(t)
	p, _ := proposal.Parse([]byte(applyProposalYAML), "x")
	if err := applyHelper(t, paths, p); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := applyHelper(t, paths, p); err != nil {
		t.Fatalf("second apply should be idempotent: %v", err)
	}
	pf, _ := policy.LoadDefaultOrEmpty(paths)
	if len(pf.Rules) != 2 {
		t.Errorf("idempotent apply changed rule count to %d", len(pf.Rules))
	}
}
