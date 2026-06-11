// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"os"
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"gopkg.in/yaml.v3"
)

const minimalProposal = `
version: 1
kind: openscope-proposal
metadata:
  name: test
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
`

func TestParseAndValidate(t *testing.T) {
	p, err := Parse([]byte(minimalProposal), "test.yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.SHA256 == "" {
		t.Error("expected sha256 to be computed")
	}
	if len(p.SSHTargets.Add) != 1 || p.SSHTargets.Add[0].Alias != "web" {
		t.Errorf("ssh target not parsed: %+v", p.SSHTargets.Add)
	}
	if len(p.Policy.Add) != 1 || p.Policy.Add[0].Action != "read_file" {
		t.Errorf("policy rule not parsed: %+v", p.Policy.Add)
	}
	if got := p.Agents(); len(got) != 1 || got[0] != "bot" {
		t.Errorf("agents = %v, want [bot]", got)
	}
}

func TestParseRejectsWrongKind(t *testing.T) {
	_, err := Parse([]byte("version: 1\nkind: other\n"), "x")
	if err == nil || !strings.Contains(err.Error(), "kind") {
		t.Errorf("expected kind error, got %v", err)
	}
}

func TestParseRejectsBadRule(t *testing.T) {
	src := "version: 1\nkind: openscope-proposal\npolicy:\n  add:\n    - {effect: maybe, agent: a, app: b, action: c}\n"
	if _, err := Parse([]byte(src), "x"); err == nil {
		t.Error("expected effect validation error")
	}
}

func TestEffectiveSystemMerges(t *testing.T) {
	p, _ := Parse([]byte(minimalProposal), "x")
	live := admin.SystemCommands{Version: 1}
	live.Packages.Allowed = []string{"ripgrep"}
	eff := p.EffectiveSystem(live)
	if !contains(eff.Packages.Allowed, "jq") || !contains(eff.Packages.Allowed, "ripgrep") {
		t.Errorf("merge lost entries: %v", eff.Packages.Allowed)
	}
	if _, ok := admin.FindManager(eff, "brew"); !ok {
		t.Error("brew manager not merged")
	}
}

func TestEffectiveTargetsKeepsLiveOnCollision(t *testing.T) {
	p, _ := Parse([]byte(minimalProposal), "x")
	live := admin.SSHTargets{Version: 1, Targets: []admin.SSHTarget{
		{Alias: "web", Host: "OLD.example.com", User: "root"},
	}}
	eff := p.effectiveTargets(live)
	if len(eff) != 1 || eff[0].Host != "OLD.example.com" {
		t.Errorf("collision should keep live target, got %+v", eff)
	}
}

// minimalDefs provides just enough appdef for dead-rule and action lookups.
func minimalDefs() map[string]appdef.Definition {
	return map[string]appdef.Definition{
		"ssh": {App: appdef.App{Name: "ssh", Executor: "ssh", SecurityMode: "protected"}, Actions: map[string]appdef.Action{
			"read_file":       {Parameters: []appdef.Parameter{{Name: "target", PolicyKey: "target"}, {Name: "path", PolicyKey: "path"}}},
			"list_dir":        {Parameters: []appdef.Parameter{{Name: "target", PolicyKey: "target"}, {Name: "path", PolicyKey: "path"}}},
			"restart_service": {Parameters: []appdef.Parameter{{Name: "target", PolicyKey: "target"}, {Name: "service", PolicyKey: "service"}}},
			"service_status":  {Parameters: []appdef.Parameter{{Name: "target", PolicyKey: "target"}, {Name: "service", PolicyKey: "service"}}},
		}},
		"system": {App: appdef.App{Name: "system", Executor: "system", SecurityMode: "protected"}, Actions: map[string]appdef.Action{
			"manage_apps": {Parameters: []appdef.Parameter{{Name: "name", PolicyKey: "app"}}},
		}},
	}
}

func parse(t *testing.T, src string) Proposal {
	t.Helper()
	p, err := Parse([]byte(src), "test.yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func hasFinding(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestLintRootUserAndKey(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: root, allowed_path_prefixes: [/var/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds())
	if !hasFinding(findings, "SSH-ROOT-USER") {
		t.Error("expected SSH-ROOT-USER")
	}
	if !hasFinding(findings, "SSH-KEY-EXPOSED") {
		t.Error("expected SSH-KEY-EXPOSED")
	}
}

func TestLintSecretPathBlocks(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, allowed_path_prefixes: [/etc/nginx]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	b := DefaultBounds()
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), b)
	if !hasFinding(findings, "SSH-SECRET-PATH") {
		t.Fatal("expected SSH-SECRET-PATH (/etc/nginx reaches /etc/nginx/ssl)")
	}
	if !b.blocks("SSH-SECRET-PATH") {
		t.Error("default bounds should block SSH-SECRET-PATH")
	}
}

func TestLintCodeExecOnWritableSource(t *testing.T) {
	// /tmp is world-writable; install dir + manage_apps grant = code exec.
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
system_commands:
  apps:
    allowed_source_prefixes: {add: [/tmp]}
    allowed_install_dirs: {add: [/Applications]}
    allowed_names: {add: [Foo]}
policy:
  add:
    - {effect: allow, agent: bot, app: system, action: manage_apps}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds())
	if !hasFinding(findings, "SYS-APP-CODEEXEC") {
		t.Error("expected SYS-APP-CODEEXEC for writable /tmp source")
	}
}

func TestLintDeadServiceRule(t *testing.T) {
	// restart_service on a target that declares no services = dead rule.
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: web, host: w.example.com, user: deploy, allowed_path_prefixes: [/var/log]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: restart_service, constraints: {target: web}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds())
	if !hasFinding(findings, "POLICY-DEAD-RULE") {
		t.Error("expected POLICY-DEAD-RULE for service action on service-less target")
	}
}

func TestBuildPlanVerdictBlocked(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, allowed_path_prefixes: [/etc/nginx]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	plan := BuildPlan(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "default", MachineInfo{})
	if !plan.Blocked {
		t.Error("expected plan to be blocked by secret-path finding")
	}
	if plan.JSON().Verdict != "blocked" {
		t.Errorf("json verdict = %q", plan.JSON().Verdict)
	}
}

func TestBuildPlanCleanWhenScoped(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: web, host: w.example.com, user: deploy, identity_file: /var/openscope/ssh/web, allowed_paths: [/var/app/logs/app.log]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: web}}
`
	plan := BuildPlan(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "default", MachineInfo{})
	if plan.Blocked {
		t.Errorf("expected clean plan, blocking=%+v", plan.Blocking)
	}
	if len(plan.Acknowledge) != 0 {
		t.Errorf("expected no acknowledgements, got %+v", plan.Acknowledge)
	}
}

func TestRenderTextRunsAndTabulates(t *testing.T) {
	p := parse(t, minimalProposal)
	plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "default", MachineInfo{User: "u", Host: "h", OS: "darwin"})
	out := RenderText(plan)
	for _, want := range []string{"OpenScope plan", "FINDINGS", "BOUNDS", "VERDICT", "+--", "✅"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q", want)
		}
	}
}

func TestTableEmojiAlignment(t *testing.T) {
	// Rows whose first cell mixes emoji and plain text must produce equal-length
	// border lines (display-width-aware padding).
	out := table([]string{"SEV", "X"}, [][]string{{"⛔ BLOCK", "a"}, {"plainlong", "b"}}, 5, 20)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	first := displayWidth(lines[0])
	for i, l := range lines {
		if displayWidth(l) != first {
			t.Errorf("line %d display width %d != %d:\n%s", i, displayWidth(l), first, out)
		}
	}
}

func TestDisplayWidth(t *testing.T) {
	cases := map[string]int{"abc": 3, "⛔": 2, "🔴": 2, "⚠️": 2, "✅ pass": 7}
	for s, want := range cases {
		if got := displayWidth(s); got != want {
			t.Errorf("displayWidth(%q) = %d, want %d", s, got, want)
		}
	}
}

func TestRenderHTML(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, allowed_path_prefixes: [/etc/nginx]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	plan := BuildPlan(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "default", MachineInfo{User: "u", Host: "h", OS: "darwin"})
	out := RenderHTML(plan)
	for _, want := range []string{"<!doctype html>", "<title>OpenScope plan", `class="verdict blocked"`, "SSH-SECRET-PATH", "</html>"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	// Untrusted metadata must be HTML-escaped, never raw.
	evil := parse(t, "version: 1\nkind: openscope-proposal\nmetadata: {name: t, description: \"<script>x</script>\"}\n")
	html := RenderHTML(BuildPlan(evil, LiveState{}, minimalDefs(), DefaultBounds(), "d", MachineInfo{}))
	if strings.Contains(html, "<script>x</script>") {
		t.Error("description was not HTML-escaped — injection risk")
	}
}

func TestRootUserDenyBlocks(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: root, identity_file: /var/openscope/ssh/k, allowed_paths: [/var/app/logs/a.log]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	b := DefaultBounds()
	b.SSH.RootUser = "deny"
	plan := BuildPlan(parse(t, src), LiveState{}, minimalDefs(), b, "x", MachineInfo{})
	if !plan.Blocked {
		t.Error("root_user: deny must block a root target, not merely acknowledge")
	}
	// Same proposal with acknowledge must NOT block.
	b.SSH.RootUser = "acknowledge"
	plan = BuildPlan(parse(t, src), LiveState{}, minimalDefs(), b, "x", MachineInfo{})
	if plan.Blocked {
		t.Error("root_user: acknowledge should not block")
	}
	if len(plan.Acknowledge) == 0 {
		t.Error("expected a root-user acknowledgement")
	}
}

func TestMaxTargetsBlocks(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: a, host: a.example.com, user: deploy, identity_file: /k, allowed_paths: [/srv/a/x]}
    - {alias: b, host: b.example.com, user: deploy, identity_file: /k, allowed_paths: [/srv/b/x]}
    - {alias: c, host: c.example.com, user: deploy, identity_file: /k, allowed_paths: [/srv/c/x]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: a}}
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: b}}
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: c}}
`
	b := DefaultBounds()
	b.MaxTargetsPerAgent = 2
	plan := BuildPlan(parse(t, src), LiveState{}, minimalDefs(), b, "x", MachineInfo{})
	if !plan.Blocked {
		t.Error("3 targets for one agent must block under max_targets_per_agent: 2")
	}
	if !hasFinding(plan.Findings, "POLICY-MAX-TARGETS") {
		t.Error("expected POLICY-MAX-TARGETS finding")
	}
}

func TestTargetConflictBlocks(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: web, host: NEW.example.com, user: deploy, identity_file: /k, allowed_paths: [/srv/x]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: web}}
`
	live := LiveState{SSHTargets: admin.SSHTargets{Version: 1, Targets: []admin.SSHTarget{
		{Alias: "web", Host: "OLD.example.com", User: "deploy"},
	}}}
	plan := BuildPlan(parse(t, src), live, minimalDefs(), DefaultBounds(), "x", MachineInfo{})
	if !hasFinding(plan.Findings, "SSH-TARGET-CONFLICT") {
		t.Fatal("expected SSH-TARGET-CONFLICT for differing live target")
	}
	if !plan.Blocked {
		t.Error("a target conflict (apply would error) should block the plan")
	}
}

func TestWildcardServiceDeadRule(t *testing.T) {
	// restart_service with NO target constraint, and no target declares services.
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: web, host: w.example.com, user: deploy, identity_file: /k, allowed_path_prefixes: [/srv/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: restart_service}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds())
	if !hasFinding(findings, "POLICY-DEAD-RULE") {
		t.Error("expected POLICY-DEAD-RULE for wildcard service action with no service-bearing target")
	}
}

func TestUnknownAppDenyFlagged(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
policy:
  add:
    - {effect: deny, agent: bot, app: postgress, action: query}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds())
	var found *Finding
	for i := range findings {
		if findings[i].RuleID == "POLICY-DEAD-RULE" {
			found = &findings[i]
		}
	}
	if found == nil {
		t.Fatal("expected POLICY-DEAD-RULE for typo'd app in a deny rule")
	}
	if found.Severity != SevMedium {
		t.Errorf("dead DENY should be escalated to MEDIUM, got %v", found.Severity)
	}
}

func TestExampleBoundsMatchesDefault(t *testing.T) {
	const path = "../docs/examples/claude-code/bounds.yaml"
	if _, err := os.Stat(path); err != nil {
		t.Skip("example bounds not present")
	}
	data, _ := os.ReadFile(path)
	var fromFile Bounds
	if err := yaml.Unmarshal(data, &fromFile); err != nil {
		t.Fatal(err)
	}
	if fromFile.Version != DefaultBounds().Version || len(fromFile.BlockingRules) != len(DefaultBounds().BlockingRules) {
		t.Errorf("example bounds.yaml diverged from DefaultBounds()\nfile blocking=%v\ndflt blocking=%v",
			fromFile.BlockingRules, DefaultBounds().BlockingRules)
	}
}

func TestDefaultBoundsParses(t *testing.T) {
	b := DefaultBounds()
	if b.Version == 0 {
		t.Fatal("default bounds did not parse")
	}
	if !b.blocks("SYS-APP-CODEEXEC") || !b.blocks("SSH-SECRET-PATH") {
		t.Error("default bounds should block code-exec and secret-path")
	}
}
