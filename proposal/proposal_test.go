// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/executor/sshexec"
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

// The manage_apps provenance gates (allowed_team_ids, require_root_owned_source)
// must survive EffectiveSystem — a proposal that sets them is how the team-ID
// trust anchor gets configured. Regression: these were added to AppConfig + the
// executor/lint but not the proposal merge, so a proposal's team-id was silently
// dropped (the gate never took effect).
func TestEffectiveSystemMergesAppGates(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: app-gates}
system_commands:
  apps:
    allowed_source_prefixes: {add: [/private/tmp/cylonix-staged-apps]}
    allowed_team_ids:        {add: [P7Y2NJ7JP3]}
    require_root_owned_source: true
`
	p, err := Parse([]byte(src), "x")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	eff := p.EffectiveSystem(admin.SystemCommands{Version: 1})
	if !contains(eff.Apps.AllowedTeamIDs, "P7Y2NJ7JP3") {
		t.Errorf("apps.allowed_team_ids not merged: %v", eff.Apps.AllowedTeamIDs)
	}
	if !eff.Apps.RequireRootOwnedSource {
		t.Error("apps.require_root_owned_source not merged")
	}
	if !contains(eff.Apps.AllowedSourcePrefixes, "/private/tmp/cylonix-staged-apps") {
		t.Errorf("apps.allowed_source_prefixes not merged: %v", eff.Apps.AllowedSourcePrefixes)
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
			"write_file":      {Command: "cat > {path}", Parameters: []appdef.Parameter{{Name: "target", PolicyKey: "target"}, {Name: "path", PolicyKey: "path", Constraint: "path"}, {Name: "content"}}},
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
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "")
	if !hasFinding(findings, "SSH-ROOT-USER") {
		t.Error("expected SSH-ROOT-USER")
	}
	// Default bounds require an explicit root-owned identity_file, so a target
	// with none (ssh would fall back to agent-readable ~/.ssh) blocks.
	if !hasFinding(findings, "SSH-KEY-READABLE") {
		t.Error("expected SSH-KEY-READABLE for a target with no identity_file")
	}
}

func TestLintKeyReadableBlocks(t *testing.T) {
	// An identity_file the agent's user can read (mode 0644) lets the agent ssh
	// directly with that key, bypassing every policy rule — must hard-fail apply.
	dir := t.TempDir()
	key := filepath.Join(dir, "prod_key")
	if err := os.WriteFile(key, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: ` + key + `, allowed_path_prefixes: [/var/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	b := DefaultBounds()
	p := parse(t, src)
	if !hasFinding(Analyze(p, LiveState{}, minimalDefs(), b, "/nonexistent-home"), "SSH-KEY-READABLE") {
		t.Fatal("expected SSH-KEY-READABLE for an agent-readable identity file")
	}
	if !b.blocks("SSH-KEY-READABLE") {
		t.Error("default bounds should block SSH-KEY-READABLE")
	}
	plan := BuildPlan(p, LiveState{}, minimalDefs(), b, "default", MachineInfo{HomeDir: "/nonexistent-home"})
	if !plan.Blocked {
		t.Error("a proposal with an agent-readable ssh key should be blocked")
	}
}

func TestLintRequireIdentityFile(t *testing.T) {
	// No identity_file means ssh falls back to ~/.ssh (agent-readable). It is
	// advisory by default, but blocks once bounds.require_identity_file is set.
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, allowed_path_prefixes: [/var/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	p := parse(t, src)

	// Default (require_identity_file: true): a missing key blocks.
	plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "x", MachineInfo{})
	if !hasFinding(plan.Findings, "SSH-KEY-READABLE") {
		t.Fatalf("default bounds should escalate a missing identity_file to SSH-KEY-READABLE, got %v", plan.Findings)
	}
	if !plan.Blocked {
		t.Error("a missing identity_file should block apply under default bounds")
	}

	// Personal opt-out (require_identity_file: false): advisory only.
	relaxed := DefaultBounds()
	relaxed.SSH.RequireIdentityFile = false
	def := Analyze(p, LiveState{}, minimalDefs(), relaxed, "")
	if !hasFinding(def, "SSH-KEY-EXPOSED") {
		t.Error("expected advisory SSH-KEY-EXPOSED when the opt-out is set")
	}
	if hasFinding(def, "SSH-KEY-READABLE") {
		t.Error("opt-out should not block a missing identity_file")
	}
}

func TestLintSetButAbsentKeyIsMissingNotExposed(t *testing.T) {
	// identity_file is set but the file isn't there (not provisioned yet, or a
	// 0700 root dir the user-vantage planner can't read). It must be reported as
	// SSH-KEY-MISSING, not the misleading SSH-KEY-EXPOSED.
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/nope/id_rsa, allowed_path_prefixes: [/var/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	p := parse(t, src)
	def := Analyze(p, LiveState{}, minimalDefs(), DefaultBounds(), "")
	if !hasFinding(def, "SSH-KEY-MISSING") {
		t.Fatalf("a set-but-absent identity_file should be SSH-KEY-MISSING, got %v", def)
	}
	if hasFinding(def, "SSH-KEY-EXPOSED") {
		t.Error("a missing key file should not be reported as SSH-KEY-EXPOSED")
	}
	if hasFinding(def, "SSH-KEY-READABLE") {
		t.Error("a set-but-absent identity_file should not block as readable")
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
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), b, "")
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
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "")
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
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "")
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
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "")
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
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "")
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

func TestLintWriteActionFlaggedButNotBlocked(t *testing.T) {
	// A non-inspection ssh verb (write_file) must surface in review as SSH-WRITE,
	// but per "broker, not limiter" it is acknowledge-by-default, not blocking.
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/var/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: write_file, constraints: {target: prod}}
`
	p := parse(t, src)
	b := DefaultBounds()
	findings := Analyze(p, LiveState{}, minimalDefs(), b, "/nonexistent-home")
	if !hasFinding(findings, "SSH-WRITE") {
		t.Fatal("expected SSH-WRITE for a non-inspection ssh action")
	}
	if b.blocks("SSH-WRITE") {
		t.Error("SSH-WRITE must not block by default (broker, not limiter)")
	}
	plan := BuildPlan(p, LiveState{}, minimalDefs(), b, "d", MachineInfo{HomeDir: "/nonexistent-home"})
	if plan.Blocked {
		t.Error("a write action alone should not block apply")
	}
	if len(plan.Acknowledge) == 0 {
		t.Error("SSH-WRITE (HIGH) should require typed acknowledgment at apply")
	}
}

func TestLintReadOnlyActionNotFlaggedAsWrite(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/var/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	p := parse(t, src)
	if hasFinding(Analyze(p, LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home"), "SSH-WRITE") {
		t.Fatal("read_file is inspection — must not be flagged SSH-WRITE")
	}
}

func TestLintParallelPathWhenUserKeysPresent(t *testing.T) {
	// A proposal that adds an ssh target, evaluated with a home dir that has a
	// readable ~/.ssh key, must surface SSH-PARALLEL-PATH (MEDIUM, not blocking).
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"id_ed25519", "id_ed25519.pub"} {
		if err := os.WriteFile(filepath.Join(sshDir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/var/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	p := parse(t, src)
	b := DefaultBounds()
	if !hasFinding(Analyze(p, LiveState{}, minimalDefs(), b, home), "SSH-PARALLEL-PATH") {
		t.Fatal("expected SSH-PARALLEL-PATH when ~/.ssh has keys and a target is added")
	}
	// Deterministic local signal — must not block apply (the live probe does that).
	plan := BuildPlan(p, LiveState{}, minimalDefs(), b, "d", MachineInfo{HomeDir: home})
	if plan.Blocked {
		t.Error("SSH-PARALLEL-PATH must not block plan (apply/check-bypass verify live)")
	}
}

func TestLintNoParallelPathFindingWithoutUserKeys(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/var/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: read_file, constraints: {target: prod}}
`
	p := parse(t, src)
	// home with no ~/.ssh → no parallel path possible
	if hasFinding(Analyze(p, LiveState{}, minimalDefs(), DefaultBounds(), t.TempDir()), "SSH-PARALLEL-PATH") {
		t.Fatal("no ~/.ssh keys → SSH-PARALLEL-PATH must not fire")
	}
}

func TestLintPkgInstallStrongVsWeak(t *testing.T) {
	b := DefaultBounds()

	// Strong scope (a signing team ID) → SYS-PKG-INSTALL, acknowledge not block.
	strong := `
version: 1
kind: openscope-proposal
metadata: {name: t}
system_commands:
  pkg:
    allowed_team_ids: {add: [P7Y2NJ7JP3]}
policy:
  add:
    - {effect: allow, agent: bot, app: system, action: install_pkg}
`
	p := parse(t, strong)
	fs := Analyze(p, LiveState{}, minimalDefs(), b, "")
	if !hasFinding(fs, "SYS-PKG-INSTALL") {
		t.Fatal("expected SYS-PKG-INSTALL for a team-id-scoped install_pkg")
	}
	if hasFinding(fs, "SYS-PKG-CODEEXEC") {
		t.Fatal("team-id-scoped install_pkg must not be flagged SYS-PKG-CODEEXEC")
	}
	if BuildPlan(p, LiveState{}, minimalDefs(), b, "d", MachineInfo{}).Blocked {
		t.Error("a well-scoped install_pkg should not block")
	}

	// Weak scope (only an agent-writable prefix) → SYS-PKG-CODEEXEC, blocking.
	wdir := t.TempDir() // user-owned + writable
	weak := `
version: 1
kind: openscope-proposal
metadata: {name: t}
system_commands:
  pkg:
    allowed_prefixes: {add: [` + wdir + `]}
policy:
  add:
    - {effect: allow, agent: bot, app: system, action: install_pkg}
`
	pw := parse(t, weak)
	if !hasFinding(Analyze(pw, LiveState{}, minimalDefs(), b, ""), "SYS-PKG-CODEEXEC") {
		t.Fatal("expected SYS-PKG-CODEEXEC for a writable-prefix-only install_pkg")
	}
	if !BuildPlan(pw, LiveState{}, minimalDefs(), b, "d", MachineInfo{}).Blocked {
		t.Error("a weakly-scoped install_pkg must block apply")
	}
}

func TestEffectiveSystemHonorsRemove(t *testing.T) {
	// A proposal's `remove:` on a system_commands list must drop live entries
	// (previously silently ignored), so scope migrations don't need a manual reset.
	live := admin.SystemCommands{}
	live.Pkg.AllowedPrefixes = []string{"/Volumes/ext/dist", "/private/tmp"}
	live.Ports.Allowed = []int{8080, 9090}

	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
system_commands:
  pkg:
    allowed_prefixes:
      add: [/var/openscope/pkgs]
      remove: [/Volumes/ext/dist]
  ports:
    allowed:
      remove: [8080]
`
	eff := parse(t, src).EffectiveSystem(live)

	if contains(eff.Pkg.AllowedPrefixes, "/Volumes/ext/dist") {
		t.Error("remove should drop /Volumes/ext/dist")
	}
	if !contains(eff.Pkg.AllowedPrefixes, "/private/tmp") || !contains(eff.Pkg.AllowedPrefixes, "/var/openscope/pkgs") {
		t.Errorf("kept + added prefixes should remain, got %v", eff.Pkg.AllowedPrefixes)
	}
	if containsInt(eff.Ports.Allowed, 8080) {
		t.Error("remove should drop port 8080")
	}
	if !containsInt(eff.Ports.Allowed, 9090) {
		t.Error("port 9090 should remain")
	}
}

// TestApplyBypassResultsRouting pins two behaviors of the live-verdict fold:
// distinct failure classes each produce their own finding (a broker-key
// rejection must not mask an inconclusive target), and a HIGH finding that
// bounds no longer block still lands in Acknowledge — never a clean verdict.
func TestApplyBypassResultsRouting(t *testing.T) {
	rejected := []sshexec.BypassResult{{Target: "a", Host: "a.example.com", Outcome: sshexec.BypassBrokerKeyRejected}}
	unknown := []sshexec.BypassResult{{Target: "b", Host: "b.example.com", Key: "/home/u/.ssh/id", Outcome: sshexec.BypassUnknown}}

	plan := Plan{Bounds: DefaultBounds()}
	plan.ApplyBypassResults(nil, rejected, unknown)
	if n := len(plan.Blocking); n != 2 {
		t.Fatalf("both failure classes must block under default bounds, got %d blocking", n)
	}
	var sawRejected, sawUnknown bool
	for _, f := range plan.Findings {
		sawRejected = sawRejected || strings.Contains(f.Summary, "broker key was REJECTED")
		sawUnknown = sawUnknown || strings.Contains(f.Summary, "could not be confirmed absent")
	}
	if !sawRejected || !sawUnknown {
		t.Errorf("each failure class needs its own finding (rejected=%v unknown=%v)", sawRejected, sawUnknown)
	}

	// Bounds widened to not block SSH-BYPASS: the HIGH finding must demand
	// typed acknowledgment instead of yielding a clean plan.
	relaxed := DefaultBounds()
	relaxed.BlockingRules = nil
	plan = Plan{Bounds: relaxed}
	plan.ApplyBypassResults([]sshexec.BypassResult{{Target: "a", Host: "a.example.com", Key: "/home/u/.ssh/id", Outcome: sshexec.BypassFound}}, nil, nil)
	if plan.Blocked {
		t.Fatal("with SSH-BYPASS unblocked the plan must not hard-block")
	}
	if len(plan.Acknowledge) != 1 {
		t.Fatalf("a live-confirmed bypass must require acknowledgment, got %d", len(plan.Acknowledge))
	}
}
