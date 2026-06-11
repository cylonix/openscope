// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/policy"
)

type Severity int

const (
	SevPass Severity = iota
	SevWarn
	SevMedium
	SevHigh
)

func (s Severity) String() string {
	switch s {
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevWarn:
		return "WARN"
	default:
		return "PASS"
	}
}

type Finding struct {
	RuleID   string
	Severity Severity
	Resource string
	Summary  string
	Fix      string
}

// Read-class ssh actions whose reach is bounded by the target's allowed paths.
var readActions = []string{"read_file", "list_dir"}

// Service-class ssh actions whose reach is bounded by allowed_services.
var serviceActions = []string{"service_status", "tail_logs", "restart_service"}

// Analyze runs every deterministic lint over the EFFECTIVE post-apply state
// (live ⊕ proposal) and returns findings sorted by severity (highest first).
func Analyze(p Proposal, live LiveState, defs map[string]appdef.Definition, b Bounds) []Finding {
	var out []Finding

	effTargets := p.effectiveTargets(live.SSHTargets)
	effSystem := p.EffectiveSystem(live.System)
	targetByAlias := map[string]admin.SSHTarget{}
	for _, t := range effTargets {
		targetByAlias[t.Alias] = t
	}

	allows := allowRules(p.Policy.Add)
	readTargets := targetsForActions(allows, effTargets, readActions)

	// SSH-ROOT-USER + SSH-KEY-EXPOSED: per proposed target.
	for _, t := range p.SSHTargets.Add {
		if t.User == "root" {
			out = append(out, Finding{
				RuleID: "SSH-ROOT-USER", Severity: SevHigh,
				Resource: t.Alias + " (" + t.Host + ")",
				Summary:  "logs in as root — every action runs with full root on this host",
				Fix:      "use a least-privilege account where the host allows it",
			})
		}
		if t.IdentityFile == "" {
			out = append(out, Finding{
				RuleID: "SSH-KEY-EXPOSED", Severity: SevWarn,
				Resource: t.Alias,
				Summary:  "no identity_file — ssh uses ~/.ssh, readable by the agent",
				Fix:      "move the key to a root-owned dir and set identity_file to it",
			})
		}
	}

	// SSH-SECRET-PATH / BROAD-PREFIX / WEBROOT / FILE-SECRET: per readable target.
	for _, alias := range readTargets {
		t, ok := targetByAlias[alias]
		if !ok {
			continue
		}
		for _, p := range append(append([]string{}, t.AllowedPaths...), t.AllowedPathPrefixes...) {
			if hit, sec := reachesSecret(p, b.SSH.SecretAbsolutePaths); hit {
				out = append(out, Finding{
					RuleID: "SSH-SECRET-PATH", Severity: SevHigh,
					Resource: alias + ":" + p,
					Summary:  "read access reaches secrets at " + sec,
					Fix:      "narrow to specific non-secret files instead of this prefix",
				})
			} else if base := secretConfigFile(p, b.SSH.ConfigSecretFiles); base != "" {
				out = append(out, Finding{
					RuleID: "SSH-FILE-SECRET", Severity: SevMedium,
					Resource: alias + ":" + p,
					Summary:  base + " commonly inlines secrets/env — read grant exposes them",
					Fix:      "confirm the file holds no credentials, or drop it",
				})
			} else if web := underAny(p, b.SSH.WebrootPrefixes); web != "" {
				out = append(out, Finding{
					RuleID: "SSH-WEBROOT-CONFIG", Severity: SevMedium,
					Resource: alias + ":" + p,
					Summary:  "web root — read may expose app config such as .env",
					Fix:      "scope to the specific files the agent needs",
				})
			} else if slices.Contains(b.SSH.BroadReadPrefixes, filepath.Clean(p)) {
				out = append(out, Finding{
					RuleID: "SSH-BROAD-PREFIX", Severity: SevMedium,
					Resource: alias + ":" + p,
					Summary:  "broad read prefix — credentials can leak into files here",
					Fix:      "scope to the specific subtree or files the agent needs",
				})
			}
		}
	}

	// SSH-DISRUPTIVE: restart_service grants.
	for _, alias := range targetsForActions(allows, effTargets, []string{"restart_service"}) {
		out = append(out, Finding{
			RuleID: "SSH-DISRUPTIVE", Severity: SevHigh,
			Resource: alias,
			Summary:  "may restart services — a one-command outage on a production host",
			Fix:      "keep, but confirm the blast radius; pair with a TTL when supported",
		})
	}

	// SYS-APP-CODEEXEC: install + writable source = arbitrary code execution.
	if hasAllow(allows, "system", "manage_apps") && len(effSystem.Apps.AllowedInstallDirs) > 0 {
		var writable []string
		for _, src := range effSystem.Apps.AllowedSourcePrefixes {
			if w, reason, _ := pathAgentWritable(src); w {
				writable = append(writable, fmt.Sprintf("%s (%s)", src, reason))
			}
		}
		if len(writable) > 0 {
			out = append(out, Finding{
				RuleID: "SYS-APP-CODEEXEC", Severity: SevHigh,
				Resource: fmt.Sprintf("%d agent-writable source(s)", len(writable)),
				Summary: fmt.Sprintf("manage_apps installs+launches into %s from %s — arbitrary code execution as your user",
					strings.Join(effSystem.Apps.AllowedInstallDirs, ", "), strings.Join(writable, "; ")),
				Fix: "remove manage_apps install/launch, or use a root-owned source prefix",
			})
		}
	}

	// SYS-DISRUPTIVE: kill-by-PID and port release.
	if hasAllow(allows, "system", "manage_processes") && effSystem.Processes.AllowKillByPID {
		out = append(out, Finding{
			RuleID: "SYS-DISRUPTIVE", Severity: SevMedium,
			Resource: "manage_processes",
			Summary:  "kill-by-PID enabled with broad process names — local DoS surface",
			Fix:      "set allow_kill_by_pid: false, or narrow allowed_names",
		})
	}

	// SYS-SUDO-MANAGER: any sudo-enabled package manager.
	for _, m := range effSystem.Packages.Managers {
		if m.Sudo {
			out = append(out, Finding{
				RuleID: "SYS-SUDO-MANAGER", Severity: SevHigh,
				Resource: m.Name,
				Summary:  "sudo-enabled manager generates a NOPASSWD '" + m.Binary + " install *' sudoers wildcard",
				Fix:      "keep brew/pip/npm non-sudo, or constrain the package allow-list tightly",
			})
		}
	}

	// SSH-TARGET-CONFLICT: a proposed target collides with a live one whose
	// settings differ. AddSSHTarget keeps the live target, so apply would error
	// — surface it in the plan so the verdict predicts the apply-time failure.
	liveByAlias := map[string]admin.SSHTarget{}
	for _, t := range live.SSHTargets.Targets {
		liveByAlias[t.Alias] = t
	}
	for _, t := range p.SSHTargets.Add {
		if ex, ok := liveByAlias[t.Alias]; ok && !sshTargetSemEqual(ex, admin.NormalizeSSHTarget(t)) {
			out = append(out, Finding{
				RuleID: "SSH-TARGET-CONFLICT", Severity: SevHigh,
				Resource: t.Alias,
				Summary:  "alias already exists with different settings — apply will refuse (live target is kept)",
				Fix:      "remove the existing target first, or align the proposal with the live settings",
			})
		}
	}

	// POLICY-MAX-TARGETS: per-agent breadth cap from bounds.
	if b.MaxTargetsPerAgent > 0 {
		for agent, n := range agentTargetCounts(allows, effTargets) {
			if n > b.MaxTargetsPerAgent {
				out = append(out, Finding{
					RuleID: "POLICY-MAX-TARGETS", Severity: SevHigh,
					Resource: agent,
					Summary:  fmt.Sprintf("%d targets exceeds the per-agent bound of %d", n, b.MaxTargetsPerAgent),
					Fix:      "grant fewer targets, or raise max_targets_per_agent in bounds.yaml",
				})
			}
		}
	}

	out = append(out, deadRuleFindings(p, targetByAlias, defs)...)
	out = append(out, passFindings(p, effSystem)...)

	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// deadRuleFindings flags allow/deny rules that can never fire — a dead allow is
// noise, but a dead DENY silently disables a guardrail, so it is escalated.
func deadRuleFindings(p Proposal, targets map[string]admin.SSHTarget, defs map[string]appdef.Definition) []Finding {
	var out []Finding
	deadSev := func(effect string) Severity {
		if effect == "deny" {
			return SevMedium
		}
		return SevWarn
	}
	add := func(r policy.Rule, resource, summary string) {
		out = append(out, Finding{RuleID: "POLICY-DEAD-RULE", Severity: deadSev(r.Effect),
			Resource: resource, Summary: summary})
	}

	for _, r := range p.Policy.Add {
		if r.App == "ssh" {
			alias := r.Constraints["target"]
			svc := r.Constraints["service"]
			isSvc := slices.Contains(serviceActions, r.Action)
			if alias != "" {
				t, ok := targets[alias]
				if !ok {
					add(r, r.App+"/"+r.Action+" target="+alias, "references a target that will not exist after apply")
					continue
				}
				if isSvc && len(t.AllowedServices) == 0 {
					add(r, r.App+"/"+r.Action+" target="+alias, "target declares no services — this rule can never succeed")
					continue
				}
				if svc != "" && !admin.SSHTargetAllowsService(t, svc) {
					add(r, r.App+"/"+r.Action+" service="+svc, "service not in the target's allowed_services — dead rule")
				}
			} else {
				// Wildcard target (no constraint) — applies to every target.
				if isSvc && !anyTargetHasServices(targets) {
					add(r, r.App+"/"+r.Action, "no target declares any services — this rule can never succeed")
					continue
				}
				if svc != "" && !anyTargetAllowsService(targets, svc) {
					add(r, r.App+"/"+r.Action+" service="+svc, "no target allows this service — dead rule")
				}
			}
		}
		// Unknown app or action: a dead allow (noise) vs a dead deny (dangerous).
		def, ok := defs[r.App]
		if !ok {
			add(r, r.App+"/"+r.Action, "no such app — rule will never match")
			continue
		}
		if _, ok := def.Action(r.Action); !ok {
			add(r, r.App+"/"+r.Action, "no such action for this app — rule will never match")
		}
	}
	return out
}

func anyTargetHasServices(targets map[string]admin.SSHTarget) bool {
	for _, t := range targets {
		if len(t.AllowedServices) > 0 {
			return true
		}
	}
	return false
}

func anyTargetAllowsService(targets map[string]admin.SSHTarget, svc string) bool {
	for _, t := range targets {
		if admin.SSHTargetAllowsService(t, svc) {
			return true
		}
	}
	return false
}

// agentTargetCounts returns, per agent, the number of distinct SSH targets its
// allow rules can reach (a rule with no target constraint reaches all).
func agentTargetCounts(allows []policy.Rule, effTargets []admin.SSHTarget) map[string]int {
	perAgent := map[string]map[string]struct{}{}
	for _, r := range allows {
		if r.App != "ssh" {
			continue
		}
		set := perAgent[r.Agent]
		if set == nil {
			set = map[string]struct{}{}
			perAgent[r.Agent] = set
		}
		if alias := r.Constraints["target"]; alias != "" {
			set[alias] = struct{}{}
		} else {
			for _, t := range effTargets {
				set[t.Alias] = struct{}{}
			}
		}
	}
	counts := map[string]int{}
	for agent, set := range perAgent {
		counts[agent] = len(set)
	}
	return counts
}

func sshTargetSemEqual(a, b admin.SSHTarget) bool {
	a = admin.NormalizeSSHTarget(a)
	return a.Host == b.Host && a.User == b.User && a.Port == b.Port &&
		a.IdentityFile == b.IdentityFile && a.ProxyJump == b.ProxyJump &&
		strings.Join(a.AllowedServices, ",") == strings.Join(b.AllowedServices, ",") &&
		strings.Join(a.AllowedPaths, ",") == strings.Join(b.AllowedPaths, ",") &&
		strings.Join(a.AllowedPathPrefixes, ",") == strings.Join(b.AllowedPathPrefixes, ",")
}

func passFindings(p Proposal, sys admin.SystemCommands) []Finding {
	var out []Finding
	sudo := false
	for _, m := range sys.Packages.Managers {
		if m.Sudo {
			sudo = true
		}
	}
	if !sudo && len(sys.Packages.Managers) > 0 {
		out = append(out, Finding{RuleID: "SYS-NO-SUDO", Severity: SevPass,
			Resource: "packages", Summary: "no sudo-enabled managers — no NOPASSWD sudoers wildcards generated"})
	}
	denies := 0
	for _, r := range p.Policy.Add {
		if r.Effect == "deny" {
			denies++
		}
	}
	if denies > 0 {
		out = append(out, Finding{RuleID: "POLICY-DENY-PRESENT", Severity: SevPass,
			Resource: "policy", Summary: fmt.Sprintf("%d defense-in-depth deny rules present (deny overrides allow)", denies)})
	}
	return out
}

// --- helpers ----------------------------------------------------------------

func allowRules(rules []policy.Rule) []policy.Rule {
	var out []policy.Rule
	for _, r := range rules {
		if r.Effect == "allow" {
			out = append(out, r)
		}
	}
	return out
}

func hasAllow(allows []policy.Rule, app, action string) bool {
	for _, r := range allows {
		if r.App == app && r.Action == action {
			return true
		}
	}
	return false
}

// targetsForActions returns the set of target aliases an allow rule grants the
// given ssh actions on. A rule with no target constraint applies to every
// effective target (a wildcard), so all aliases are included.
func targetsForActions(allows []policy.Rule, effTargets []admin.SSHTarget, actions []string) []string {
	set := map[string]struct{}{}
	all := func() {
		for _, t := range effTargets {
			set[t.Alias] = struct{}{}
		}
	}
	for _, r := range allows {
		if r.App != "ssh" || !slices.Contains(actions, r.Action) {
			continue
		}
		if alias := r.Constraints["target"]; alias != "" {
			set[alias] = struct{}{}
		} else {
			all()
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// reachesSecret reports whether a granted abs path/prefix overlaps any secret
// location: equal, an ancestor of, or sitting under it.
func reachesSecret(grant string, secrets []string) (bool, string) {
	g := filepath.Clean(grant)
	for _, s := range secrets {
		s = filepath.Clean(s)
		if g == s || isUnder(g, s) || isUnder(s, g) {
			return true, s
		}
	}
	return false, ""
}

func underAny(grant string, prefixes []string) string {
	g := filepath.Clean(grant)
	for _, p := range prefixes {
		p = filepath.Clean(p)
		if g == p || isUnder(g, p) {
			return p
		}
	}
	return ""
}

func secretConfigFile(grant string, names []string) string {
	base := filepath.Base(filepath.Clean(grant))
	if slices.Contains(names, base) {
		return base
	}
	return ""
}

// isUnder reports whether child is strictly under parent.
func isUnder(child, parent string) bool {
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}
