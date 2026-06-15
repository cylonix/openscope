// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
	"github.com/openscope/openscope/policy"
	"github.com/openscope/openscope/proposal"
)

// bypassStub stands in for the ssh runner the parallel-path probe uses.
type bypassStub struct {
	result executor.Result
	err    error
}

func (s bypassStub) Run(name string, args []string, stdin io.Reader) (executor.Result, error) {
	return s.result, s.err
}

// bypassPlanYAML adds a target with a root-owned identity_file (so the static
// SSH-KEY-READABLE check doesn't fire) and a non-root user (no SSH-ROOT-USER) —
// isolating the live parallel-path verdict as the only thing that can block.
const bypassPlanYAML = `
version: 1
kind: openscope-proposal
metadata: {name: bypass-test}
ssh_targets:
  add:
    - {alias: web, host: web.example.com, user: deploy, identity_file: /var/openscope/ssh/web, allowed_path_prefixes: [/var/log/nginx]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: web}}
`

func homeWithKey(t *testing.T) (home, pubLine string) {
	t.Helper()
	home = t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A real public-key line (valid base64 blob, so it fingerprints) plus its
	// private sibling so DiscoverUserKeys picks it up.
	blob := base64.StdEncoding.EncodeToString([]byte("openscope-test-ed25519-keyblob!!"))
	pubLine = "ssh-ed25519 " + blob + " test@host"
	if err := os.WriteFile(filepath.Join(sshDir, "id_test.pub"), []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_test"), []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, pubLine
}

func bypassPlan(t *testing.T, home string) proposal.Plan {
	t.Helper()
	p, err := proposal.Parse([]byte(bypassPlanYAML), "x")
	if err != nil {
		t.Fatal(err)
	}
	return proposal.BuildPlan(p, proposal.LiveState{}, nil, proposal.DefaultBounds(), "d", proposal.MachineInfo{HomeDir: home})
}

func TestRunLiveBypassFoldsVerdictIntoPlan(t *testing.T) {
	home, pubLine := homeWithKey(t)
	paths := testPaths(t)
	paths.HomeDir = home

	oldRunner, oldReadable := parallelPathRunner, brokerKeyReadable
	defer func() { parallelPathRunner = oldRunner; brokerKeyReadable = oldReadable }()
	// The broker key path is fake in tests; force "readable" so inspection runs.
	brokerKeyReadable = func(string) bool { return true }

	// The user's key IS in the target's authorized_keys → bypass → blocking.
	parallelPathRunner = bypassStub{result: executor.Result{Stdout: pubLine + "\n__OPENSCOPE_SSHD__\n"}}
	plan := bypassPlan(t, home)
	runLiveBypass(paths, &plan)
	if !plan.Blocked {
		t.Fatalf("expected plan BLOCKED when a ~/.ssh key is in the target's authorized_keys")
	}

	// A different key authorized, no CA/command → user key absent → not blocked.
	other := base64.StdEncoding.EncodeToString([]byte("an-entirely-different-keyblob!!!!"))
	parallelPathRunner = bypassStub{result: executor.Result{Stdout: "ssh-ed25519 " + other + " other@host\n__OPENSCOPE_SSHD__\n"}}
	plan = bypassPlan(t, home)
	runLiveBypass(paths, &plan)
	if plan.Blocked {
		t.Fatalf("expected plan OK when the user key is absent from authorized_keys")
	}

	// Broker read fails (host unreachable) → inconclusive → fail closed → blocked.
	parallelPathRunner = bypassStub{result: executor.Result{ExitCode: 255, Stderr: "ssh: connect to host x port 22: Operation timed out"}}
	plan = bypassPlan(t, home)
	runLiveBypass(paths, &plan)
	if !plan.Blocked {
		t.Fatalf("expected plan BLOCKED when the broker read is inconclusive (fail closed)")
	}
}

func TestRunLiveBypassNoopWithoutUserKeys(t *testing.T) {
	paths := testPaths(t)
	paths.HomeDir = t.TempDir() // no ~/.ssh → no parallel path possible
	plan := bypassPlan(t, paths.HomeDir)
	runLiveBypass(paths, &plan) // must not block (and must not panic)
	if plan.Blocked {
		t.Fatalf("no ~/.ssh keys → nothing to verify, plan must not be blocked")
	}
}

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	dir := t.TempDir()
	admDir := t.TempDir()
	return config.Paths{
		ConfigDir:          dir,
		AppsDir:            filepath.Join(dir, "apps.d"),
		PoliciesFile:       filepath.Join(dir, "policies.yaml"),
		AgentsFile:         filepath.Join(dir, "agents.yaml"),
		AuditFile:          filepath.Join(dir, "audit.jsonl"),
		AdminDir:           admDir,
		SSHTargetsFile:     filepath.Join(admDir, "ssh_targets.yaml"),
		SystemCommandsFile: filepath.Join(admDir, "system_commands.yaml"),
		AppDefinitionsFile: filepath.Join(admDir, "app_definitions.yaml"),
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

func TestApplyMigratesLegacyPolicyToAdminDir(t *testing.T) {
	paths := testPaths(t)
	// Policy points at the root-owned admin dir, with the legacy user-owned
	// location as the pre-migration fallback.
	paths.PoliciesFile = filepath.Join(paths.AdminDir, "policies.yaml")
	paths.LegacyPoliciesFile = filepath.Join(paths.ConfigDir, "policies.yaml")

	// An upgraded install already has a rule in the legacy location.
	if err := policy.Save(paths.LegacyPoliciesFile, policy.File{Version: 1,
		Rules: []policy.Rule{{Effect: "allow", Agent: "legacy", App: "ssh", Action: "read_file"}}}); err != nil {
		t.Fatal(err)
	}

	p, _ := proposal.Parse([]byte(applyProposalYAML), "x")
	if err := applyHelper(t, paths, p); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if _, err := os.Stat(paths.PoliciesFile); err != nil {
		t.Fatalf("policy not written to the admin dir: %v", err)
	}
	if _, err := os.Stat(paths.LegacyPoliciesFile); !os.IsNotExist(err) {
		t.Errorf("legacy policy file should be removed after migration (stat err = %v)", err)
	}
	pf, err := policy.LoadDefaultOrEmpty(paths)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// The legacy rule is preserved and merged with the proposal's two rules.
	if len(pf.Rules) != 3 {
		t.Errorf("expected legacy(1)+proposal(2)=3 rules, got %d: %+v", len(pf.Rules), pf.Rules)
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
