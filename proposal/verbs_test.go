// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
)

func findingByRule(findings []Finding, ruleID string) (Finding, bool) {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return Finding{}, false
}

const sshTargetBlock = `
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/var/app]}
`

// A verb defined in the SAME proposal must resolve: SSH-WRITE surfaces it (with
// the exact command), and POLICY-DEAD-RULE must NOT fire — the two findings can
// no longer contradict each other on one rule.
func TestVerbAddedInSameProposalResolves(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}` + sshTargetBlock + `
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        gen_promo:
          description: generate a promo code
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: code, type: string}
          command: "/opt/k/gen-promo --code {code}"
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: gen_promo, constraints: {target: prod}}
`
	p := parse(t, src)
	findings := Analyze(p, LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	if _, ok := findingByRule(findings, "POLICY-DEAD-RULE"); ok {
		t.Error("a verb defined in the same proposal must not be a dead rule")
	}
	wr, ok := findingByRule(findings, "SSH-WRITE")
	if !ok {
		t.Fatal("expected SSH-WRITE for the custom verb")
	}
	if wr.Resource != "prod:gen_promo" {
		t.Errorf("SSH-WRITE resource = %q", wr.Resource)
	}
	if !strings.Contains(wr.Fix, "/opt/k/gen-promo --code {code}") {
		t.Errorf("SSH-WRITE should show the exact command, fix = %q", wr.Fix)
	}
}

// A generic-runner command template is blocked unconditionally.
func TestPassthroughVerbIsBlocked(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}` + sshTargetBlock + `
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        run_any:
          description: danger
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: cmd, type: string}
          command: "bash -c {cmd}"
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: run_any, constraints: {target: prod}}
`
	p := parse(t, src)
	plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "d", MachineInfo{HomeDir: "/nonexistent-home"})
	if _, ok := findingByRule(plan.Findings, "SSH-SHELL-PASSTHROUGH"); !ok {
		t.Fatal("expected SSH-SHELL-PASSTHROUGH for a shell -c passthrough")
	}
	if !plan.Blocked {
		t.Error("a generic-runner verb must block apply")
	}
}

// A custom verb under its OWN app name (not literally "ssh") still gets the
// SSH-WRITE review because the finding is keyed on executor: ssh.
func TestCustomAppVerbStillReviewed(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}` + sshTargetBlock + `
apps:
  add:
    - version: 1
      app: {name: kidfence, executor: ssh}
      actions:
        gen_promo:
          description: gen
          parameters:
            - {name: target, type: string, policy_key: target}
          command: "/opt/k/gen"
policy:
  add:
    - {effect: allow, agent: bot, app: kidfence, action: gen_promo, constraints: {target: prod}}
`
	p := parse(t, src)
	findings := Analyze(p, LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	wr, ok := findingByRule(findings, "SSH-WRITE")
	if !ok {
		t.Fatal("a custom-app ssh-executor verb must still be reviewed as SSH-WRITE")
	}
	if wr.Resource != "prod:gen_promo" {
		t.Errorf("SSH-WRITE resource = %q", wr.Resource)
	}
	if _, ok := findingByRule(findings, "POLICY-DEAD-RULE"); ok {
		t.Error("the verb is defined in the proposal — not a dead rule")
	}
}

// A verb definition whose app name collides with an existing app of a different
// executor is a blocking conflict.
func TestVerbConflictWithExistingAppBlocks(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: system, executor: ssh}
      actions:
        rogue:
          description: rogue
          parameters: [{name: x, type: string}]
          command: "echo {x}"
`
	p := parse(t, src)
	// minimalDefs has a "system" app with executor "system" — the ssh overlay
	// conflicts.
	plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "d", MachineInfo{HomeDir: "/nonexistent-home"})
	if _, ok := findingByRule(plan.Findings, "APP-DEF-CONFLICT"); !ok {
		t.Fatal("expected APP-DEF-CONFLICT")
	}
	if !plan.Blocked {
		t.Error("an app-definition conflict must block apply")
	}
}

// An upload source that reaches ~/.ssh is a blocking exfil channel.
func TestUploadSourceSecretBlocks(t *testing.T) {
	home := "/Users/tester"
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: test, host: h, user: deploy, identity_file: /var/openscope/ssh/test, allowed_upload_sources: ["` + home + `/.ssh"]}
`
	p := parse(t, src)
	plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "d", MachineInfo{HomeDir: home})
	if _, ok := findingByRule(plan.Findings, "SSH-UPLOAD-SECRET"); !ok {
		t.Fatal("expected SSH-UPLOAD-SECRET for an upload source under ~/.ssh")
	}
	if !plan.Blocked {
		t.Error("an upload-source exfil channel must block apply")
	}
}

// A fenced build dir is a fine upload source.
func TestUploadSourceFencedOK(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: test, host: h, user: deploy, identity_file: /var/openscope/ssh/test, allowed_upload_sources: ["/srv/build/kidfence"]}
`
	p := parse(t, src)
	findings := Analyze(p, LiveState{}, minimalDefs(), DefaultBounds(), "/Users/tester")
	if _, ok := findingByRule(findings, "SSH-UPLOAD-SECRET"); ok {
		t.Error("a fenced build dir must not be flagged as an exfil channel")
	}
}

// Validation rejects the shapes a proposal verb may not take.
func TestProposalVerbValidation(t *testing.T) {
	cases := map[string]string{
		"script not allowed": `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        x: {description: d, parameters: [{name: a, type: string}], script: foo}
`,
		"unsupported executor": `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: custom, executor: applescript}
      actions:
        x: {description: d, parameters: [{name: a, type: string}], command: "echo {a}"}
`,
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src), "t.yaml"); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// A clean custom system (sudo) verb is acknowledge-to-apply (not blocked), and
// the acknowledgment renders the worst-case command with each <param> marked.
func TestSystemCustomVerbAcknowledged(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: system, executor: system}
      actions:
        restart_fleet:
          description: restart the fleet agent
          parameters: [{name: host, type: string}]
          command: "/usr/local/bin/fleetctl restart {host}"
policy:
  add:
    - {effect: allow, agent: bot, app: system, action: restart_fleet}
`
	p := parse(t, src)
	plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "d", MachineInfo{HomeDir: "/nh"})
	f, ok := findingByRule(plan.Findings, "SYS-CUSTOM-VERB")
	if !ok {
		t.Fatal("expected SYS-CUSTOM-VERB for a custom system verb")
	}
	if !strings.Contains(f.Summary, "/usr/local/bin/fleetctl restart <host>") {
		t.Errorf("worst-case command not rendered: %q", f.Summary)
	}
	if plan.Blocked {
		t.Error("a clean custom system verb must be acknowledge-to-apply, not blocked")
	}
	if _, ok := findingByRule(plan.Acknowledge, "SYS-CUSTOM-VERB"); !ok {
		t.Error("SYS-CUSTOM-VERB must require acknowledgment")
	}
}

// A generic-runner system verb is hard-blocked (SYS-SHELL-PASSTHROUGH) — no
// acknowledgment escape, regardless of bounds.
func TestSystemPassthroughBlocks(t *testing.T) {
	cases := map[string]string{
		"program is a param":  "{prog} --do-it",
		"shell -c":            "/bin/bash -c {script}",
		"interpreter program": "/usr/bin/python3 {script}",
		"not absolute":        "fleetctl {host}",
	}
	for name, cmd := range cases {
		src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: system, executor: system}
      actions:
        danger:
          description: d
          parameters: [{name: prog, type: string}, {name: script, type: string}, {name: host, type: string}]
          command: "` + cmd + `"
policy:
  add:
    - {effect: allow, agent: bot, app: system, action: danger}
`
		p := parse(t, src)
		plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "d", MachineInfo{HomeDir: "/nh"})
		if _, ok := findingByRule(plan.Findings, "SYS-SHELL-PASSTHROUGH"); !ok {
			t.Fatalf("%s: expected SYS-SHELL-PASSTHROUGH", name)
		}
		if !plan.Blocked {
			t.Errorf("%s: a generic-runner system verb must block apply", name)
		}
	}
}

// A privileged custom verb whose program is a general-purpose file writer is
// hard-blocked (SYS-SELF-GOVERN) — it could overwrite OpenScope's own config.
func TestSystemSelfGovernBlocks(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: system, executor: system}
      actions:
        write_any:
          description: d
          parameters: [{name: path, type: string, constraint: path}]
          command: "/usr/bin/tee {path}"
policy:
  add:
    - {effect: allow, agent: bot, app: system, action: write_any}
`
	p := parse(t, src)
	plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "d", MachineInfo{HomeDir: "/nh"})
	if _, ok := findingByRule(plan.Findings, "SYS-SELF-GOVERN"); !ok {
		t.Fatal("expected SYS-SELF-GOVERN for a privileged file-writer verb")
	}
	if !plan.Blocked {
		t.Error("a self-governance-capable system verb must block apply")
	}
}

// manage_apps install from a writable build dir is acknowledge (SYS-APP-INSTALL)
// when a signing team gates it, and hard-blocked (SYS-APP-CODEEXEC) without one.
func TestSystemAppInstallTeamIDGate(t *testing.T) {
	writableSrc := t.TempDir() // owned by the test user → agent-writable
	base := func(apps admin.AppConfig) LiveState {
		return LiveState{System: admin.SystemCommands{Version: 1, Apps: apps}}
	}
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
policy:
  add:
    - {effect: allow, agent: bot, app: system, action: manage_apps}
`
	p := parse(t, src)

	// Writable source + a team-ID gate → acknowledge, not blocked.
	gated := base(admin.AppConfig{
		AllowedInstallDirs:    []string{"/Applications"},
		AllowedSourcePrefixes: []string{writableSrc},
		AllowedTeamIDs:        []string{"P7Y2NJ7JP3"},
	})
	plan := BuildPlan(p, gated, minimalDefs(), DefaultBounds(), "d", MachineInfo{HomeDir: "/nh"})
	if _, ok := findingByRule(plan.Findings, "SYS-APP-INSTALL"); !ok {
		t.Fatal("expected SYS-APP-INSTALL when a team-id gates a writable source")
	}
	if _, ok := findingByRule(plan.Findings, "SYS-APP-CODEEXEC"); ok {
		t.Error("a team-id-gated install must not be SYS-APP-CODEEXEC")
	}
	if plan.Blocked {
		t.Error("a team-id-gated install must be acknowledge-to-apply, not blocked")
	}

	// Writable source + NO provenance gate → blocking SYS-APP-CODEEXEC.
	ungated := base(admin.AppConfig{
		AllowedInstallDirs:    []string{"/Applications"},
		AllowedSourcePrefixes: []string{writableSrc},
	})
	plan = BuildPlan(p, ungated, minimalDefs(), DefaultBounds(), "d", MachineInfo{HomeDir: "/nh"})
	if _, ok := findingByRule(plan.Findings, "SYS-APP-CODEEXEC"); !ok {
		t.Fatal("expected SYS-APP-CODEEXEC for a writable source with no provenance gate")
	}
	if !plan.Blocked {
		t.Error("an ungated writable-source install must block apply")
	}
}
