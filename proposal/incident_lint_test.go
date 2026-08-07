// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
)

// registryDefs returns a namespace holding one root-applied (human-approved)
// deploy verb, the way LoadAppliedFile marks entries.
func registryDefs(command string) map[string]appdef.Definition {
	defs := minimalDefs()
	ssh := defs["ssh"]
	actions := make(map[string]appdef.Action, len(ssh.Actions)+1)
	for k, v := range ssh.Actions {
		actions[k] = v
	}
	actions["deploy_web"] = appdef.Action{
		Command:     command,
		RootApplied: true,
		Parameters: []appdef.Parameter{
			{Name: "target", Type: "string", PolicyKey: "target"},
		},
	}
	ssh.Actions = actions
	defs["ssh"] = ssh
	return defs
}

const deployProposalTemplate = `
version: 1
kind: openscope-proposal
metadata: {name: t, authored_by: {tool: test, model: m, session: s}}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        deploy_web:
          description: deploy the web container
          parameters:
            - {name: target, type: string, policy_key: target}
          command: "COMMAND"
`

// Replacing a root-applied command template must be loud: a HIGH finding, a
// VerbDiff carrying old and new, the REPLACES status in the verbs table, and a
// changes line that no longer claims the proposal "only ADDS access".
func TestVerbReplacementIsSurfacedWithDiff(t *testing.T) {
	defs := registryDefs("docker load && docker-compose stop web && docker-compose rm -f web && docker-compose up -d web")
	newCmd := "docker load && docker-compose up -d --force-recreate web"
	p := parse(t, strings.Replace(deployProposalTemplate, "COMMAND", newCmd, 1))

	findings := Analyze(p, LiveState{}, defs, DefaultBounds(), "/nonexistent-home")
	f, ok := findingByRule(findings, "VERB-REPLACES-APPROVED")
	if !ok {
		t.Fatal("expected VERB-REPLACES-APPROVED for a changed root-applied template")
	}
	if f.Severity != SevHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
	if f.Resource != "ssh·deploy_web" {
		t.Errorf("resource = %q", f.Resource)
	}

	plan := BuildPlan(p, LiveState{}, defs, DefaultBounds(), "test", MachineInfo{})
	if len(plan.VerbDiffs) != 1 {
		t.Fatalf("VerbDiffs = %d, want 1", len(plan.VerbDiffs))
	}
	d := plan.VerbDiffs[0]
	if !strings.Contains(d.OldCommand, "stop web") || d.NewCommand != newCmd {
		t.Errorf("diff old/new = %q / %q", d.OldCommand, d.NewCommand)
	}
	if plan.Changes.VerbsReplaced != 1 {
		t.Errorf("VerbsReplaced = %d, want 1", plan.Changes.VerbsReplaced)
	}

	text := RenderText(plan)
	if !strings.Contains(text, "VERB REPLACEMENTS") {
		t.Error("text render should include the VERB REPLACEMENTS section")
	}
	if !strings.Contains(text, "REPLACES") {
		t.Error("verbs table should mark the action REPLACES")
	}
	if strings.Contains(text, "only ADDS access") {
		t.Error("changes line must not claim only-adds when a verb is replaced")
	}
	if len(plan.JSON().VerbDiffs) != 1 {
		t.Error("JSON view should carry the verb replacement")
	}
}

// Re-stating the approved verb verbatim is idempotent — no replacement noise.
func TestIdenticalVerbReAddIsNotAReplacement(t *testing.T) {
	cmd := "docker load && docker-compose up -d web"
	defs := registryDefs(cmd)
	p := parse(t, strings.Replace(deployProposalTemplate, "COMMAND", cmd, 1))

	findings := Analyze(p, LiveState{}, defs, DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "VERB-REPLACES-APPROVED"); ok {
		t.Error("an identical re-add must not be flagged as a replacement")
	}
	plan := BuildPlan(p, LiveState{}, defs, DefaultBounds(), "test", MachineInfo{})
	if len(plan.VerbDiffs) != 0 {
		t.Errorf("VerbDiffs = %d, want 0", len(plan.VerbDiffs))
	}
}

// Redefining a bundled curated action never runs (built-in dispatch wins) — a
// medium correctness signal, not a silent merge.
func TestBundledShadowIsFlagged(t *testing.T) {
	defs := minimalDefs()
	ssh := defs["ssh"]
	ssh.Bundled = true
	defs["ssh"] = ssh

	src := `
version: 1
kind: openscope-proposal
metadata: {name: t, authored_by: {tool: test, model: m, session: s}}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        read_file:
          description: custom read
          parameters:
            - {name: target, type: string, policy_key: target}
          command: "cat /etc/hostname"
`
	findings := Analyze(parse(t, src), LiveState{}, defs, DefaultBounds(), "/nonexistent-home")
	f, ok := findingByRule(findings, "VERB-SHADOWS-BUNDLED")
	if !ok {
		t.Fatal("expected VERB-SHADOWS-BUNDLED")
	}
	if f.Severity != SevMedium {
		t.Errorf("severity = %v, want medium", f.Severity)
	}
}

const hazardProposal = `
version: 1
kind: openscope-proposal
metadata: {name: t, authored_by: {tool: test, model: m, session: s}}
ssh_targets:
  add:
    - {alias: origin, host: o.example.com, user: deploy}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        deploy_web:
          description: deploy
          stdin_file: image
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: image, type: string, constraint: local_source}
          command: "docker load && docker-compose up -d --force-recreate web"
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: deploy_web, constraints: {target: origin}}
`

func TestOperationalHazards(t *testing.T) {
	p := parse(t, hazardProposal)
	findings := Analyze(p, LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	var hazards []Finding
	for _, f := range findings {
		if f.RuleID == "SSH-OPS-HAZARD" {
			hazards = append(hazards, f)
		}
	}
	if len(hazards) != 2 {
		t.Fatalf("hazards = %d (%#v), want force-recreate + ungated docker load", len(hazards), hazards)
	}
	var sawRecreate, sawUngated bool
	for _, f := range hazards {
		if strings.Contains(f.Summary, "force-recreate") {
			sawRecreate = true
			if f.Severity != SevWarn {
				t.Errorf("unconfirmed force-recreate should be WARN, got %v", f.Severity)
			}
		}
		if strings.Contains(f.Summary, "stdin_media") {
			sawUngated = true
		}
	}
	if !sawRecreate || !sawUngated {
		t.Errorf("missing hazard: recreate=%v ungated=%v", sawRecreate, sawUngated)
	}
}

// Pinned facts confirming compose v1 on the constrained target escalate the
// force-recreate hazard from advisory WARN to MEDIUM with the version named.
func TestForceRecreateEscalatesOnComposeV1Facts(t *testing.T) {
	live := LiveState{SSHTargets: admin.SSHTargets{Version: 1, Targets: []admin.SSHTarget{{
		Alias: "origin", Host: "o.example.com", User: "deploy",
		Facts: &admin.TargetFacts{OS: "Linux", Arch: "x86_64", Compose: "docker-compose version 1.29.2, build 5becea4c"},
	}}}}
	src := strings.Replace(hazardProposal, "ssh_targets:\n  add:\n    - {alias: origin, host: o.example.com, user: deploy}\n", "", 1)
	findings := Analyze(parse(t, src), live, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	found := false
	for _, f := range findings {
		if f.RuleID == "SSH-OPS-HAZARD" && strings.Contains(f.Summary, "1.29.2") {
			found = true
			if f.Severity != SevMedium {
				t.Errorf("fact-confirmed hazard severity = %v, want medium", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected the fact-escalated compose-v1 hazard")
	}
}

// A down-window chain (stop/rm before up) gets its own advisory note.
func TestDownWindowHazard(t *testing.T) {
	if !downWindowHazard("docker-compose stop web && docker-compose rm -f web && docker-compose up -d web") {
		t.Error("stop && rm && up is a down-window")
	}
	if downWindowHazard("docker-compose up -d web") {
		t.Error("plain up is not a down-window")
	}
	if downWindowHazard("docker-compose stop web") {
		t.Error("stop without a later up is not a down-window")
	}
}

// A mutating verb without verify: draws the advisory; adding verify clears it.
func TestSSHWriteNoVerify(t *testing.T) {
	p := parse(t, hazardProposal)
	findings := Analyze(p, LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "SSH-WRITE-NO-VERIFY"); !ok {
		t.Fatal("expected SSH-WRITE-NO-VERIFY for a verb without verify")
	}
	wr, ok := findingByRule(findings, "SSH-WRITE")
	if !ok {
		t.Fatal("expected SSH-WRITE")
	}
	if !strings.Contains(wr.Fix, "AUTHORITY, not correctness") {
		t.Errorf("SSH-WRITE fix should carry the reviewer checklist, got %q", wr.Fix)
	}

	withVerify := strings.Replace(hazardProposal,
		`          command: "docker load && docker-compose up -d --force-recreate web"`,
		`          command: "docker load && docker-compose up -d --force-recreate web"
          verify: "curl -sf localhost:8003/"
          verify_delay_seconds: 5`, 1)
	findings = Analyze(parse(t, withVerify), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "SSH-WRITE-NO-VERIFY"); ok {
		t.Error("verify: declared — the advisory must clear")
	}
}

func TestMetaUnstamped(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "META-UNSTAMPED"); !ok {
		t.Fatal("expected META-UNSTAMPED for an empty authored_by")
	}

	stamped := parse(t, strings.Replace(src, "metadata: {name: t}", "metadata: {name: t, authored_by: {tool: cc, model: m, session: s}}", 1))
	findings = Analyze(stamped, LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "META-UNSTAMPED"); ok {
		t.Error("stamped proposal must not warn")
	}
}
