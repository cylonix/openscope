// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"strings"
	"testing"
	"time"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/audit"
)

func TestCommandEffectsClassifiesTheIncidentChain(t *testing.T) {
	effects := commandEffects("docker load && cd /root && docker-compose stop cylonix-web && docker-compose rm -f cylonix-web && docker-compose up -d cylonix-web && docker-compose ps cylonix-web")
	want := []struct {
		class, object string
	}{
		{"load", "docker image store"},
		{"noop", ""},
		{"stop", "container cylonix-web"},
		{"delete", "container cylonix-web"},
		{"start", "container cylonix-web"},
		{"read", "container cylonix-web"},
	}
	if len(effects) != len(want) {
		t.Fatalf("effects = %d steps (%#v), want %d", len(effects), effects, len(want))
	}
	for i, w := range want {
		if effects[i].Class != w.class || effects[i].Object != w.object {
			t.Errorf("step %d = %s/%q, want %s/%q", i+1, effects[i].Class, effects[i].Object, w.class, w.object)
		}
	}
}

func TestCommandEffectsMisc(t *testing.T) {
	cases := []struct {
		cmd, class, object string
	}{
		{"docker-compose up -d --force-recreate web", "recreate", "container web"},
		{"systemctl restart nginx", "restart", "service nginx"},
		{"systemctl status nginx", "read", "service nginx"},
		{"tee {path}", "overwrite", ""}, // {path} placeholder is not a concrete object
		{"rm -rf /var/cache/app", "delete", "path /var/cache/app"},
		{"/opt/kidfence/bin/load-test-build.sh v3", "exec-opaque", "/opt/kidfence/bin/load-test-build.sh"},
		{"journalctl -u web -n 50", "read", ""},
		{"frobnicate --hard", "unknown", ""},
	}
	for _, tc := range cases {
		effects := commandEffects(tc.cmd)
		if len(effects) != 1 {
			t.Fatalf("%q: got %d effects", tc.cmd, len(effects))
		}
		if effects[0].Class != tc.class || effects[0].Object != tc.object {
			t.Errorf("%q = %s/%q, want %s/%q", tc.cmd, effects[0].Class, effects[0].Object, tc.class, tc.object)
		}
	}
}

// The failure walk must predict the incident: a failure during the up leaves
// the container REMOVED; after a successful up nothing is stranded.
func TestFailureWalkPredictsStrandedStates(t *testing.T) {
	effects := commandEffects("docker load && docker-compose stop web && docker-compose rm -f web && docker-compose up -d web && docker-compose ps web")
	walk := failureWalk(effects)
	joined := strings.Join(walk, "\n")
	if !strings.Contains(joined, "left STOPPED") {
		t.Errorf("walk should flag the stopped window: %q", joined)
	}
	if !strings.Contains(joined, "left DELETED") {
		t.Errorf("walk should flag the removed window: %q", joined)
	}
	// The final read step comes after the up restored the container — no line.
	for _, w := range walk {
		if strings.Contains(w, "docker-compose ps") {
			t.Errorf("nothing is stranded once the up completed: %q", w)
		}
	}
}

const proxyProposal = `
version: 1
kind: openscope-proposal
metadata: {name: t, authored_by: {tool: cc, model: m, session: s}}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        fix_proxy:
          description: recreate traefik
          parameters:
            - {name: target, type: string, policy_key: target}
          command: "docker-compose up -d --force-recreate traefik"
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: fix_proxy, constraints: {target: origin}}
`

func TestFrontingProxyHazardNamesCoTenants(t *testing.T) {
	live := LiveState{SSHTargets: admin.SSHTargets{Version: 1, Targets: []admin.SSHTarget{{
		Alias: "origin", Host: "o", User: "root",
		Facts: &admin.TargetFacts{OS: "Linux", Arch: "x86_64",
			Containers: []string{"traefik", "cylonix-web", "openscope-web"}},
	}}}}
	findings := Analyze(parse(t, proxyProposal), live, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	found := false
	for _, f := range findings {
		if f.RuleID == "SSH-OPS-HAZARD" && strings.Contains(f.Summary, "fronting proxy") {
			found = true
			if f.Severity != SevMedium {
				t.Errorf("with co-tenant facts the proxy hazard should be MEDIUM, got %v", f.Severity)
			}
			if !strings.Contains(f.Summary, "cylonix-web") || !strings.Contains(f.Summary, "openscope-web") {
				t.Errorf("hazard should name the co-tenants: %q", f.Summary)
			}
		}
	}
	if !found {
		t.Fatal("expected the fronting-proxy hazard")
	}
}

const prodProposal = `
version: 1
kind: openscope-proposal
metadata: {name: t, authored_by: {tool: cc, model: m, session: s}}
ssh_targets:
  add:
    - {alias: origin, host: o.example.com, user: deploy, criticality: prod}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        deploy_web:
          description: deploy
          parameters:
            - {name: target, type: string, policy_key: target}
          command: "docker-compose stop web && docker-compose up -d web"
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: deploy_web, constraints: {target: origin}}
`

func TestProdTierEscalation(t *testing.T) {
	findings := Analyze(parse(t, prodProposal), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	if f, ok := findingByRule(findings, "SSH-PROD-WRITE"); !ok {
		t.Fatal("expected SSH-PROD-WRITE on a prod-tier target")
	} else if f.Severity != SevHigh {
		t.Errorf("SSH-PROD-WRITE severity = %v", f.Severity)
	}
	if f, ok := findingByRule(findings, "SSH-WRITE-NO-VERIFY"); !ok {
		t.Fatal("expected SSH-WRITE-NO-VERIFY")
	} else if f.Severity != SevMedium {
		t.Errorf("NO-VERIFY on prod should escalate to MEDIUM, got %v", f.Severity)
	}
	if f, ok := findingByRule(findings, "SSH-WRITE"); ok {
		if !strings.Contains(f.Summary, "criticality: prod") {
			t.Errorf("SSH-WRITE should name the tier: %q", f.Summary)
		}
	}
}

const impactProposal = `
version: 1
kind: openscope-proposal
metadata: {name: t, authored_by: {tool: cc, model: m, session: s}}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        deploy_web:
          description: deploy
          parameters:
            - {name: target, type: string, policy_key: target}
          command: "docker-compose stop web && docker-compose stop traefik && docker-compose up -d web && docker-compose up -d traefik"
          impact: {services: [web], downtime: momentary, rollback: "redeploy the previous image tar"}
`

func TestImpactMismatchAndNoImpact(t *testing.T) {
	findings := Analyze(parse(t, impactProposal), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	f, ok := findingByRule(findings, "SSH-IMPACT-MISMATCH")
	if !ok {
		t.Fatal("expected SSH-IMPACT-MISMATCH: the command also touches traefik")
	}
	if !strings.Contains(f.Summary, "traefik") {
		t.Errorf("mismatch should name the omitted service: %q", f.Summary)
	}
	if _, ok := findingByRule(findings, "SSH-WRITE-NO-IMPACT"); ok {
		t.Error("impact is declared — NO-IMPACT must not fire")
	}

	noImpact := strings.Replace(impactProposal,
		"\n          impact: {services: [web], downtime: momentary, rollback: \"redeploy the previous image tar\"}", "", 1)
	findings = Analyze(parse(t, noImpact), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "SSH-WRITE-NO-IMPACT"); !ok {
		t.Fatal("expected SSH-WRITE-NO-IMPACT when no impact is declared")
	}
}

func TestApplyVerbHistory(t *testing.T) {
	p := parse(t, prodProposal)
	plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "test", MachineInfo{})
	now := time.Now()
	plan.ApplyVerbHistory(map[string][]audit.Outcome{
		"ssh·deploy_web": {
			{Timestamp: now, Result: "executor_error", Reason: `action "deploy_web": command succeeded but verify failed`},
			{Timestamp: now.Add(-time.Hour), Result: "success"},
			{Timestamp: now.Add(-2 * time.Hour), Result: "executor_failure", Reason: "exit 1"},
		},
	})
	if len(plan.VerbHistories) != 1 {
		t.Fatalf("VerbHistories = %d", len(plan.VerbHistories))
	}
	h := plan.VerbHistories[0]
	if h.Total != 3 || h.Failures != 2 || h.LastResult != "executor_error" {
		t.Errorf("history = %+v", h)
	}
	f, ok := findingByRule(plan.Findings, "SSH-VERB-HISTORY")
	if !ok {
		t.Fatal("expected SSH-VERB-HISTORY when the last run failed")
	}
	if !strings.Contains(f.Summary, "2 of its last 3") {
		t.Errorf("summary = %q", f.Summary)
	}
	text := RenderText(plan)
	if !strings.Contains(text, "VERB HISTORY") {
		t.Error("render should include the VERB HISTORY section")
	}
	if !strings.Contains(text, "DERIVED EFFECTS") {
		t.Error("render should include the effects section")
	}
}

// A last-run success is history worth showing but not a finding.
func TestVerbHistoryQuietOnSuccess(t *testing.T) {
	p := parse(t, prodProposal)
	plan := BuildPlan(p, LiveState{}, minimalDefs(), DefaultBounds(), "test", MachineInfo{})
	plan.ApplyVerbHistory(map[string][]audit.Outcome{
		"ssh·deploy_web": {{Timestamp: time.Now(), Result: "success"}},
	})
	if _, ok := findingByRule(plan.Findings, "SSH-VERB-HISTORY"); ok {
		t.Error("a successful last run must not warn")
	}
	if len(plan.VerbHistories) != 1 {
		t.Error("history should still render")
	}
}
