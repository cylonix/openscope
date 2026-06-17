// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import "testing"

// An ssm verb whose command is a generic runner is arbitrary root via
// AWS-RunShellScript — SSM-RUNSHELL-ARBITRARY, and it blocks unconditionally.
func TestSSMPassthroughBlocks(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: ssm, executor: ssm}
      actions:
        run_anything:
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: cmd, type: string}
          command: "{cmd}"
policy:
  add:
    - {effect: allow, agent: bot, app: ssm, action: run_anything, constraints: {target: prod}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	f, ok := findingByRule(findings, "SSM-RUNSHELL-ARBITRARY")
	if !ok {
		t.Fatal("expected SSM-RUNSHELL-ARBITRARY for a generic-runner ssm command")
	}
	if f.Severity != SevHigh || !isBlocking(DefaultBounds(), f) {
		t.Errorf("SSM-RUNSHELL-ARBITRARY must be HIGH and block unconditionally: %+v", f)
	}
	// It is reported as SSM, not mislabeled as the ssh passthrough.
	if _, ok := findingByRule(findings, "SSH-SHELL-PASSTHROUGH"); ok {
		t.Error("an ssm verb must not be reported as SSH-SHELL-PASSTHROUGH")
	}
}

// A fixed-command ssm verb is not arbitrary; granting it draws the deployment
// reminder but no passthrough block, and (with a target constraint) no broad-scope.
func TestSSMFixedVerbDeployContractOnly(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: ssm, executor: ssm}
      actions:
        tail_logs:
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: service, type: string, policy_key: service, constraint: service}
          command: "journalctl -u {service} -n 200"
policy:
  add:
    - {effect: allow, agent: bot, app: ssm, action: tail_logs, constraints: {target: prod}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	if _, ok := findingByRule(findings, "SSM-RUNSHELL-ARBITRARY"); ok {
		t.Error("a fixed-command ssm verb must not be SSM-RUNSHELL-ARBITRARY")
	}
	if _, ok := findingByRule(findings, "SSM-DEPLOY-CONTRACT"); !ok {
		t.Error("granting an ssm verb should surface the SSM-DEPLOY-CONTRACT reminder")
	}
	if _, ok := findingByRule(findings, "SSM-BROAD-SCOPE"); ok {
		t.Error("a target-constrained grant must not draw SSM-BROAD-SCOPE")
	}
}

// A grant with no target constraint reaches every instance → SSM-BROAD-SCOPE.
func TestSSMBroadScope(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: ssm, executor: ssm}
      actions:
        tail_logs:
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: service, type: string, policy_key: service, constraint: service}
          command: "journalctl -u {service} -n 200"
policy:
  add:
    - {effect: allow, agent: bot, app: ssm, action: tail_logs}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "SSM-BROAD-SCOPE"); !ok {
		t.Error("an unconstrained ssm grant should draw SSM-BROAD-SCOPE")
	}
}

// A proposal that grants no ssm verbs must not surface the SSM reminder.
func TestNoSSMGrantNoContract(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/var/log]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "SSM-DEPLOY-CONTRACT"); ok {
		t.Error("no ssm grant → no SSM-DEPLOY-CONTRACT")
	}
}

func TestProposalParsesSSMTargets(t *testing.T) {
	p := parse(t, `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssm_targets:
  add:
    - {alias: prod, instance_id: i-0abc, region: us-west-2, allowed_services: [orders-api]}
`)
	if len(p.SSMTargets.Add) != 1 || p.SSMTargets.Add[0].InstanceID != "i-0abc" {
		t.Fatalf("ssm_targets not parsed: %+v", p.SSMTargets)
	}
}

func TestProposalRejectsBadSSMTarget(t *testing.T) {
	if _, err := Parse([]byte(`
version: 1
kind: openscope-proposal
metadata: {name: t}
ssm_targets:
  add:
    - {alias: prod, region: us-west-2}
`), "test.yaml"); err == nil {
		t.Error("ssm target missing instance_id should fail to parse")
	}
}
