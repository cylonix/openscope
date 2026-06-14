// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"strings"
	"testing"
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
		"non-ssh executor": `
version: 1
kind: openscope-proposal
metadata: {name: t}
apps:
  add:
    - version: 1
      app: {name: custom, executor: system}
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
