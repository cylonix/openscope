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
	"github.com/openscope/openscope/executor/sshexec"
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

// inspectionActions are the curated, read-only ssh verbs. Any allowed ssh
// action outside this set (and outside restart_service, flagged separately) is
// a mutating/custom verb the executor will run from its command template —
// SSH-WRITE surfaces it for review. This is a review signal, not an execution
// limit: the executor runs whatever the app YAML declares and policy allows.
var inspectionActions = []string{"check_host", "host_metrics", "service_status", "tail_logs", "read_file", "list_dir"}

// Analyze runs every deterministic lint over the EFFECTIVE post-apply state
// (live ⊕ proposal) and returns findings sorted by severity (highest first).
// homeDir is the home directory ssh resolves ~/.ssh against (the user the agent
// runs as); it is used to detect identity files the agent could read directly.
func Analyze(p Proposal, live LiveState, defs map[string]appdef.Definition, b Bounds, homeDir string) []Finding {
	var out []Finding

	effTargets := p.effectiveTargets(live.SSHTargets)
	effSystem := p.EffectiveSystem(live.System)
	targetByAlias := map[string]admin.SSHTarget{}
	for _, t := range effTargets {
		targetByAlias[t.Alias] = t
	}

	allows := allowRules(p.Policy.Add)
	readTargets := targetsForActions(allows, effTargets, readActions)

	// SSH-ROOT-USER + SSH-KEY-{READABLE,EXPOSED}: per proposed target. Live
	// targets are audited by `openscope doctor`; the plan gates what the
	// proposal introduces.
	for _, t := range p.SSHTargets.Add {
		if t.User == "root" {
			out = append(out, Finding{
				RuleID: "SSH-ROOT-USER", Severity: SevHigh,
				Resource: t.Alias + " (" + t.Host + ")",
				Summary:  "logs in as root — every action runs with full root on this host",
				Fix:      "use a least-privilege account where the host allows it",
			})
		}
		out = append(out, keyExposureFindings(t, homeDir, b)...)
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

	// SSH-WRITE: any allowed ssh action that is neither read-only inspection nor
	// the already-flagged restart_service is a mutating/custom verb. The broker
	// runs whatever the app definition declares; the review must make a write
	// grant visible so the operator confirms it with full awareness.
	for _, action := range customSSHActions(allows) {
		desc := ""
		if def, ok := defs["ssh"]; ok {
			if a, ok := def.Action(action); ok && a.Description != "" {
				desc = " — " + a.Description
			}
		}
		for _, alias := range targetsForActions(allows, effTargets, []string{action}) {
			out = append(out, Finding{
				RuleID: "SSH-WRITE", Severity: SevHigh,
				Resource: alias + ":" + action,
				Summary:  "non-inspection ssh action; runs an approved command that can modify " + alias + desc,
				Fix:      "confirm the command this action runs (see its app definition) and keep its path/service constraints tight; add SSH-WRITE to bounds.blocking_rules to forbid",
			})
		}
	}

	// SSH-PARALLEL-PATH: the proposal adds ssh target(s) AND the agent's user has
	// readable private keys in ~/.ssh. Those keys are a POTENTIAL direct path to
	// any reachable host, which would bypass the broker no matter how well the
	// broker's own root-owned key is custodied. This static finding is the
	// UNVERIFIED placeholder: plan and apply replace it with a definitive
	// SSH-BYPASS (blocking) or SSH-NO-BYPASS (pass) once the live probe runs (it
	// runs by default — this MEDIUM only survives under --skip-bypass-check).
	if len(p.SSHTargets.Add) > 0 {
		if keys := sshexec.DiscoverUserKeys(homeDir); len(keys) > 0 {
			out = append(out, Finding{
				RuleID: "SSH-PARALLEL-PATH", Severity: SevMedium,
				Resource: fmt.Sprintf("%d key(s) in ~/.ssh", len(keys)),
				Summary:  "agent-readable ~/.ssh keys are a potential direct path to the new target(s) — the live bypass probe was SKIPPED (--skip-bypass-check), so this is unverified",
				Fix:      "re-run without --skip-bypass-check to verify live (plan probes by default), or run `openscope ssh check-bypass`; ensure no ~/.ssh key authenticates to these hosts",
			})
		}
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

	// SYS-PKG-INSTALL / SYS-PKG-CODEEXEC: install_pkg runs a pkg's pre/postinstall
	// scripts as root. A strong scope (a signing team ID, require_root_owned, or
	// only root-owned prefixes) is HIGH/acknowledge; a weak scope (an agent-
	// writable prefix, or nothing) is blocking SYS-PKG-CODEEXEC — the agent could
	// drop any pkg there and run arbitrary root code, just like SYS-APP-CODEEXEC.
	if hasAllow(allows, "system", "install_pkg") {
		pk := effSystem.Pkg
		var writablePrefix []string
		for _, p := range pk.AllowedPrefixes {
			if w, reason, _ := pathAgentWritable(p); w {
				writablePrefix = append(writablePrefix, fmt.Sprintf("%s (%s)", p, reason))
			}
		}
		strong := len(pk.AllowedTeamIDs) > 0 || pk.RequireRootOwned ||
			(len(pk.AllowedPrefixes) > 0 && len(writablePrefix) == 0)
		if strong {
			out = append(out, Finding{
				RuleID: "SYS-PKG-INSTALL", Severity: SevHigh, Resource: "install_pkg",
				Summary: "installs .pkg as root (its scripts run as root); a pkg must satisfy " + pkgScopeDesc(pk),
				Fix:     "confirm this is intended; a signing team ID (pkg.allowed_team_ids) is the strongest gate",
			})
		} else {
			out = append(out, Finding{
				RuleID: "SYS-PKG-CODEEXEC", Severity: SevHigh, Resource: "install_pkg",
				Summary: "install_pkg is scoped only by an agent-writable location (or not at all) — the agent can drop any pkg there and run arbitrary root code via its install scripts",
				Fix:     "add pkg.allowed_team_ids (signing team) or pkg.require_root_owned; a writable prefix alone is not a boundary",
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

// keyExposureFindings audits a proposed target's SSH identity file. A key the
// agent's own (non-root) user can read voids the entire brokering premise: the
// agent can ssh directly with that key and bypass every policy rule. Those
// conditions become a blocking SSH-KEY-READABLE (HIGH). Weaker hygiene issues
// the file mode alone does not expose (loose containing dir, a missing file we
// cannot verify) stay advisory as SSH-KEY-EXPOSED (WARN).
//
// A missing identity_file means ssh falls back to ~/.ssh, which is itself
// agent-readable; whether that blocks is governed by bounds.require_identity_file
// so a personal install (no uid separation) is not forced to set one.
func keyExposureFindings(t admin.SSHTarget, homeDir string, b Bounds) []Finding {
	const readableFix = "store the key in a root-owned dir (e.g. /var/openscope/ssh/) with mode 0600 owned by root"
	var out []Finding
	var readable []string // codes proving the agent can read the key
	for _, w := range sshexec.AuditKeyProtection(t, homeDir) {
		switch w.Code {
		case sshexec.KeyNoIdentityFile:
			if b.SSH.RequireIdentityFile {
				out = append(out, Finding{
					RuleID: "SSH-KEY-READABLE", Severity: SevHigh, Resource: t.Alias,
					Summary: "no identity_file — ssh falls back to ~/.ssh, readable by the agent (bounds require_identity_file is set)",
					Fix:     "set identity_file to a root-owned key (e.g. /var/openscope/ssh/" + t.Alias + ", mode 0600 owned by root)",
				})
			} else {
				out = append(out, Finding{
					RuleID: "SSH-KEY-EXPOSED", Severity: SevWarn, Resource: t.Alias,
					Summary: "no identity_file — ssh falls back to ~/.ssh, readable by the agent",
					Fix:     "set identity_file to a root-owned key the agent cannot read (e.g. /var/openscope/ssh/" + t.Alias + ")",
				})
			}
		case sshexec.KeyNotRegularFile:
			// identity_file is a directory/non-file: invalid for ssh and not
			// verifiable from the planner (a 0700 dir is unreadable by the user).
			// This is a config error, NOT a claim that the agent can read it.
			out = append(out, Finding{
				RuleID: "SSH-KEY-INVALID", Severity: SevHigh, Resource: t.Alias,
				Summary: w.Message,
				Fix:     "point identity_file at a single root-owned 0600 key FILE (e.g. /var/openscope/ssh/" + t.Alias + "), not a directory",
			})
		case sshexec.KeyUnderDotSSH, sshexec.KeyModeTooOpen, sshexec.KeyNotRootOwned:
			readable = append(readable, w.Message)
		default: // KeyLooseDir, KeyMissing — advisory hygiene
			out = append(out, Finding{
				RuleID: "SSH-KEY-EXPOSED", Severity: SevWarn, Resource: t.Alias,
				Summary: w.Message, Fix: readableFix,
			})
		}
	}
	if len(readable) > 0 {
		out = append(out, Finding{
			RuleID: "SSH-KEY-READABLE", Severity: SevHigh, Resource: t.Alias,
			Summary: strings.Join(readable, "; ") + " — the agent can read this key and ssh directly, bypassing the broker",
			Fix:     readableFix,
		})
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

// pkgScopeDesc spells out the install_pkg gating logic so the reviewer is not
// left guessing: the gates are ANDed (a pkg must satisfy every configured one),
// while entries within a gate are ORed (any one matches).
func pkgScopeDesc(pk admin.PkgConfig) string {
	var gates []string
	if len(pk.AllowedTeamIDs) > 0 {
		gates = append(gates, "signed by "+anyOf(pk.AllowedTeamIDs))
	}
	if pk.RequireRootOwned {
		gates = append(gates, "root-owned (pkg + its dir)")
	}
	if len(pk.AllowedPrefixes) > 0 {
		gates = append(gates, "under "+anyOf(pk.AllowedPrefixes))
	}
	switch len(gates) {
	case 0:
		return "NOTHING configured — install_pkg refuses (fail closed)"
	case 1:
		return gates[0]
	default:
		return "ALL of {" + strings.Join(gates, "  AND  ") + "}"
	}
}

// anyOf renders a within-gate OR list. A single entry needs no "any of".
func anyOf(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return "any of [" + strings.Join(items, ", ") + "]"
}

// customSSHActions returns the sorted, distinct ssh actions in the allow rules
// that are neither curated read-only inspection verbs nor restart_service
// (which has its own SSH-DISRUPTIVE finding) — i.e. the mutating/custom verbs.
func customSSHActions(allows []policy.Rule) []string {
	set := map[string]struct{}{}
	for _, r := range allows {
		if r.App != "ssh" || r.Action == "restart_service" {
			continue
		}
		if slices.Contains(inspectionActions, r.Action) {
			continue
		}
		set[r.Action] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
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
