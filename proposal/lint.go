// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/executor/sshexec"
	"github.com/openscope/openscope/policy"
)

// placeholderRE matches a {name} substitution point in a command template.
var placeholderRE = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

// systemBundledVerbs are the system app's vetted Go-backed verbs (the runAction
// switch in executor/systemexec). An allowed system action OUTSIDE this set is a
// custom command-template verb — SYS-CUSTOM-VERB surfaces it. Keep in sync with
// that switch.
var systemBundledVerbs = []string{
	"manage_packages", "manage_services", "manage_processes", "check_port",
	"release_port", "manage_files", "manage_apps", "install_pkg", "build",
}

// systemDeputies re-introduce arbitrary execution even behind a fixed argv[0]:
// shells, interpreters, and exec-delegating wrappers. A custom sudo verb whose
// program is any of these is a generic root runner.
var systemDeputies = []string{
	"sh", "bash", "zsh", "dash", "ksh", "ash", "fish",
	"env", "xargs", "eval", "nohup", "timeout", "nice", "stdbuf", "setsid", "script",
	"python", "python2", "python3", "perl", "ruby", "node", "deno", "bun", "php", "lua",
	"osascript", "awk", "gawk", "sed", "find", "sudo", "doas", "ssh", "open",
}

// systemWriters can clobber arbitrary files; as a privileged custom verb they can
// overwrite OpenScope's own root-owned control surface (SYS-SELF-GOVERN).
var systemWriters = []string{
	"tee", "dd", "cp", "mv", "ln", "install", "rsync", "chmod", "chown", "chgrp",
	"rm", "mkfifo", "truncate",
}

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

	// effDefs is the namespace map as it will be after apply (live ⊕ the verbs
	// this proposal adds), so a rule pointing at a verb the same proposal defines
	// resolves — and SSH-WRITE and POLICY-DEAD-RULE agree on what exists instead
	// of contradicting each other.
	effDefs, defConflicts := p.EffectiveDefs(defs)
	for _, msg := range defConflicts {
		out = append(out, Finding{
			RuleID: "APP-DEF-CONFLICT", Severity: SevHigh, Resource: "apps.add",
			Summary: msg,
			Fix:     "give the verb its own app name, or match the existing app's executor and security_mode",
		})
	}

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

		// SSH-UPLOAD-SECRET: an allowed_upload_sources prefix is a LOCAL path the
		// root daemon reads and streams off-box. If it reaches the home dir,
		// ~/.ssh, a secret path, or a broad system root, it's a data-exfil channel
		// — block it (no escape hatch; scope the source to a build/artifact dir).
		for _, src := range t.AllowedUploadSources {
			if reason := uploadSourceRisk(src, homeDir, b); reason != "" {
				out = append(out, Finding{
					RuleID: "SSH-UPLOAD-SECRET", Severity: SevHigh,
					Resource: t.Alias + ":" + src,
					Summary:  "upload source the root daemon reads and ships off-box " + reason + " — a data-exfil channel",
					Fix:      "scope allowed_upload_sources to a dedicated build/artifact dir; never the home dir, ~/.ssh, or a secret/system path",
				})
			}
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

	// SSH-WRITE: any allowed ssh-EXECUTOR action that is a defined, mutating
	// custom verb (not a curated read-only inspection verb, and not
	// restart_service, which has its own SSH-DISRUPTIVE finding). Keyed on the
	// resolved executor — not the literal app name "ssh" — so a custom verb under
	// any app name is reviewed. Undefined actions are left to POLICY-DEAD-RULE; a
	// rule can't be both "runs a command that modifies the host" and "never
	// matches". The exact command is shown so the operator confirms what they
	// authorize in this same view.
	writes := customSSHWrites(allows, effTargets, effDefs)
	for _, wr := range writes {
		out = append(out, Finding{
			RuleID: "SSH-WRITE", Severity: SevHigh,
			Resource: wr.alias + ":" + wr.action,
			Summary:  "non-inspection ssh action; runs an approved command that can modify " + wr.alias + wr.desc,
			Fix:      "confirm the command this action runs" + wr.cmdHint + " and keep its path/service constraints tight; add SSH-WRITE to bounds.blocking_rules to forbid",
		})
		// SSH-SCRIPT-OPAQUE: the verb invokes a server-side script plan cannot
		// inspect. This is ALLOWED (it's how existing daily scripts get wrapped
		// without rewriting them into typed verbs) — but the approver owns the
		// script's behavior, and it is only safe if the agent cannot alter it.
		if wr.scriptPath != "" {
			out = append(out, Finding{
				RuleID: "SSH-SCRIPT-OPAQUE", Severity: SevWarn,
				Resource: wr.alias + ":" + wr.action,
				Summary:  "runs server-side script " + wr.scriptPath + " — plan cannot inspect its behavior",
				Fix:      "approve only if " + wr.scriptPath + " is root-owned and not agent-writable on the target, and treats parameters as data not code (you accept responsibility for its behavior); add SSH-SCRIPT-OPAQUE to bounds.blocking_rules to forbid opaque server-side scripts",
			})
		}
	}
	// SSH-SCRIPT-WRITABLE: a write-capable verb on a target can overwrite a script
	// another verb runs there — the agent could swap the code before running it.
	out = append(out, scriptWritableFindings(writes, targetByAlias)...)

	// SSH-PARALLEL-PATH: the proposal adds ssh target(s) AND the agent's user has
	// readable private keys in ~/.ssh. Those keys are a POTENTIAL direct path to
	// any reachable host, which would bypass the broker no matter how well the
	// broker's own root-owned key is custodied. This static finding is the
	// UNVERIFIED placeholder: the live inspection replaces it with a definitive
	// SSH-BYPASS (blocking) or SSH-NO-BYPASS (pass). That inspection reads the
	// target's authorized_keys over the broker's root-owned key (no auth attempt),
	// so it runs at apply (root, where the key is readable) and DEFERS at plan when
	// run as the user. This MEDIUM survives whenever it hasn't run yet — deferred to
	// apply, or skipped with --skip-bypass-check.
	if len(p.SSHTargets.Add) > 0 {
		if keys := sshexec.DiscoverUserKeys(homeDir); len(keys) > 0 {
			out = append(out, Finding{
				RuleID: "SSH-PARALLEL-PATH", Severity: SevMedium,
				Resource: fmt.Sprintf("%d key(s) in ~/.ssh", len(keys)),
				Summary:  "agent-readable ~/.ssh keys are a potential direct path to the new target(s) — the live bypass inspection has not run here (deferred to apply, or skipped), so this is unverified",
				Fix:      "let `sudo openscope apply` run the inspection (it reads the targets' authorized_keys via the root-owned broker key — no failed-auth probe), or run `openscope ssh check-bypass` as root; ensure no ~/.ssh key is authorized on these hosts",
			})
		}
	}

	// SYS-APP-CODEEXEC / SYS-APP-INSTALL: manage_apps install copies a .app into an
	// install dir and can launch it — code execution as the user. A source the
	// agent can write with NO provenance gate is blocking SYS-APP-CODEEXEC (it can
	// drop any bundle there); a strong gate (a signing team ID, root-owned source,
	// or only non-writable source prefixes) is HIGH/acknowledge SYS-APP-INSTALL,
	// mirroring install_pkg. The strong path is what lets a test app install from a
	// writable build dir WHEN its signature proves its origin.
	if hasAllow(allows, "system", "manage_apps") && len(effSystem.Apps.AllowedInstallDirs) > 0 {
		ap := effSystem.Apps
		var writable []string
		for _, src := range ap.AllowedSourcePrefixes {
			if w, reason, _ := pathAgentWritable(src); w {
				writable = append(writable, fmt.Sprintf("%s (%s)", src, reason))
			}
		}
		strong := len(ap.AllowedTeamIDs) > 0 || ap.RequireRootOwnedSource ||
			(len(ap.AllowedSourcePrefixes) > 0 && len(writable) == 0)
		switch {
		case len(writable) > 0 && !strong:
			out = append(out, Finding{
				RuleID: "SYS-APP-CODEEXEC", Severity: SevHigh,
				Resource: fmt.Sprintf("%d agent-writable source(s)", len(writable)),
				Summary: fmt.Sprintf("manage_apps installs+launches into %s from %s — arbitrary code execution as your user",
					strings.Join(ap.AllowedInstallDirs, ", "), strings.Join(writable, "; ")),
				Fix: "add apps.allowed_team_ids (signing team) or apps.require_root_owned_source; a writable source prefix alone is not a boundary",
			})
		case len(writable) > 0:
			out = append(out, Finding{
				RuleID: "SYS-APP-INSTALL", Severity: SevHigh, Resource: "manage_apps",
				Summary: "installs a .app from a writable build dir, gated by " + appScopeDesc(ap),
				Fix:     "confirm this is intended; a signing team ID (apps.allowed_team_ids) is the strongest gate",
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

	// SYS-CUSTOM-VERB: an allow rule grants a NON-bundled system verb — it runs
	// from a root-applied command template, not a vetted Go handler. HIGH and
	// acknowledge-to-apply (the operator signs off on the rendered worst case);
	// escape-hatch SHAPES are hard-blocked separately by SYS-SHELL-PASSTHROUGH /
	// SYS-SELF-GOVERN above.
	for _, v := range customSystemVerbs(allows, effDefs) {
		out = append(out, Finding{
			RuleID: "SYS-CUSTOM-VERB", Severity: SevHigh,
			Resource: v.app + "·" + v.action,
			Summary:  "custom system (sudo) verb runs an approved command template as root" + v.cmdHint,
			Fix:      "confirm the program and where each <param> lands; keep argv[0] a fixed trusted binary and arguments typed — this requires typed acknowledgment to apply",
		})
	}

	out = append(out, passthroughFindings(p, effDefs)...)
	out = append(out, passthroughModeFindings(p)...)
	out = append(out, deadRuleFindings(p, targetByAlias, effDefs)...)
	out = append(out, ssmGrantFindings(allows, effDefs)...)
	out = append(out, passFindings(p, effSystem)...)

	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// ssmGrantFindings covers the SSM deployment contract plan cannot verify from the
// proposal alone, and flags over-broad grants. The arbitrary-execution gate is
// handled by SSM-RUNSHELL-ARBITRARY (passthroughFindings).
func ssmGrantFindings(allows []policy.Rule, defs map[string]appdef.Definition) []Finding {
	var out []Finding
	granted := false
	for _, r := range allows {
		def, ok := defs[r.App]
		if !ok || def.App.Executor != "ssm" {
			continue
		}
		if _, ok := def.Action(r.Action); !ok {
			continue // POLICY-DEAD-RULE owns undefined verbs
		}
		granted = true
		if strings.TrimSpace(r.Constraints["target"]) == "" {
			out = append(out, Finding{
				RuleID: "SSM-BROAD-SCOPE", Severity: SevWarn,
				Resource: r.App + "/" + r.Action,
				Summary:  "ssm grant has no target constraint — it applies to every configured instance",
				Fix:      "add constraints.target to scope the verb to a specific instance",
			})
		}
	}
	if granted {
		// One reminder: the binding controls (credential custody + the agent IAM
		// deny) live outside the proposal, so plan reminds rather than verifies.
		out = append(out, Finding{
			RuleID: "SSM-DEPLOY-CONTRACT", Severity: SevWarn, Resource: "ssm",
			Summary: "ssm verbs require the broker's AWS credentials custodied and the agent's own AWS identity denied SSM",
			Fix:     "give the broker a least-privilege identity via the EC2 instance role (or a root-owned credentials file the executor accepts), and deny the agent ssm:SendCommand/StartSession in an IAM permission boundary or SCP — plan cannot verify the IAM side",
		})
	}
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
		action, ok := def.Action(r.Action)
		if !ok {
			add(r, r.App+"/"+r.Action, "no such action for this app — rule will never match")
			continue
		}
		// A constraint key that is not a declared policy_key for this action can
		// never appear in the request context (PolicyContext keys by policy_key,
		// or the parameter name when unset), so the constraint never matches: a
		// dead allow is only noise, but a dead deny silently GRANTS because the
		// carve-out is inert. Flag it, escalated for denies via deadSev.
		valid := map[string]struct{}{}
		for _, prm := range action.Parameters {
			key := prm.PolicyKey
			if key == "" {
				key = prm.Name
			}
			valid[key] = struct{}{}
		}
		for k := range r.Constraints {
			if _, ok := valid[k]; !ok {
				add(r, fmt.Sprintf("%s/%s %s=…", r.App, r.Action, k),
					fmt.Sprintf("constraint key %q is not a parameter of this action — it never matches, so the rule is dead", k))
			}
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
		strings.Join(a.AllowedPathPrefixes, ",") == strings.Join(b.AllowedPathPrefixes, ",") &&
		strings.Join(a.AllowedUploadSources, ",") == strings.Join(b.AllowedUploadSources, ",")
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
// conditions become a blocking SSH-KEY-READABLE (HIGH). Weaker issues stay
// advisory (WARN): a loose containing dir is SSH-KEY-EXPOSED; a key not yet
// provisioned (or unverifiable from the user-vantage planner) is SSH-KEY-MISSING.
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
		case sshexec.KeyMissing:
			// Not an exposure — the key just isn't provisioned yet (or the
			// planner, running as the user, can't see inside a 0700 root dir).
			// Use a rule ID that matches the "does not exist" message.
			out = append(out, Finding{
				RuleID: "SSH-KEY-MISSING", Severity: SevWarn, Resource: t.Alias,
				Summary: w.Message,
				Fix:     "provision " + t.IdentityFile + " (root-owned, mode 0600) before this target is used",
			})
		default: // KeyLooseDir — advisory hygiene
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

// appScopeDesc spells out the manage_apps source-provenance gates (ANDed), the
// same way pkgScopeDesc does for install_pkg.
func appScopeDesc(ap admin.AppConfig) string {
	var gates []string
	if len(ap.AllowedTeamIDs) > 0 {
		gates = append(gates, "signed by "+anyOf(ap.AllowedTeamIDs))
	}
	if ap.RequireRootOwnedSource {
		gates = append(gates, "root-owned source")
	}
	switch len(gates) {
	case 0:
		return "its source prefix only"
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

// sshWrite is one (target, custom-verb) pair SSH-WRITE surfaces, with the verb's
// description and the exact command it runs for the operator to confirm.
type sshWrite struct{ alias, action, desc, cmdHint, command, scriptPath string }

// scriptInvoked returns the absolute-path program a command template runs as its
// first token — a server-side script/binary whose behavior plan cannot inspect —
// or "" for an inline command built from standard tools the reviewer can read in
// full.
func scriptInvoked(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	if strings.HasPrefix(fields[0], "/") {
		return fields[0]
	}
	return ""
}

var redirectToPlaceholderRE = regexp.MustCompile(`>\s*\{`)

// isPathWriter reports whether a command template writes to a {path}-style
// parameter — the write_file shape (`cat > {path}`, `tee {path}`, `dd of={path}`).
// Such a verb can overwrite any file within the target's path allow-list.
func isPathWriter(command string) bool {
	if redirectToPlaceholderRE.MatchString(command) {
		return true
	}
	fields := strings.Fields(command)
	if len(fields) > 0 && placeholderRE.MatchString(command) {
		switch filepath.Base(fields[0]) {
		case "tee", "dd":
			return true
		}
	}
	return false
}

type scriptRef struct{ action, path string }

// scriptWritableFindings flags SSH-SCRIPT-WRITABLE: on a target that grants both a
// script-running verb and a path-writer verb, if the script lives within the
// target's writable path allow-list, the agent can overwrite the script through
// the write verb and then run it — arbitrary execution behind a "safe" verb. This
// is the code-custody analog of an agent-readable SSH key: the executed code must
// be agent-immutable.
func scriptWritableFindings(writes []sshWrite, targetByAlias map[string]admin.SSHTarget) []Finding {
	type info struct {
		scripts   []scriptRef
		hasWriter bool
	}
	byTarget := map[string]*info{}
	for _, wr := range writes {
		ti := byTarget[wr.alias]
		if ti == nil {
			ti = &info{}
			byTarget[wr.alias] = ti
		}
		if wr.scriptPath != "" {
			ti.scripts = append(ti.scripts, scriptRef{action: wr.action, path: wr.scriptPath})
		}
		if isPathWriter(wr.command) {
			ti.hasWriter = true
		}
	}
	aliases := make([]string, 0, len(byTarget))
	for a := range byTarget {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)

	var out []Finding
	for _, alias := range aliases {
		ti := byTarget[alias]
		if !ti.hasWriter {
			continue
		}
		t := targetByAlias[alias]
		allowed := append(append([]string{}, t.AllowedPaths...), t.AllowedPathPrefixes...)
		for _, s := range ti.scripts {
			if underAny(s.path, allowed) == "" {
				continue
			}
			out = append(out, Finding{
				RuleID: "SSH-SCRIPT-WRITABLE", Severity: SevHigh,
				Resource: alias + ":" + s.action,
				Summary:  "a write-capable verb on " + alias + " can overwrite " + s.path + " — the agent could swap the script before running it (arbitrary execution)",
				Fix:      "place " + s.path + " outside the target's writable allowed_paths/allowed_path_prefixes (a root-owned path the write verbs can't reach), or drop the write grant on " + alias,
			})
		}
	}
	return out
}

// customSSHWrites returns the (target, action) pairs an allow rule grants on a
// defined ssh-executor verb that is mutating (not a curated read-only inspection
// verb, not restart_service). It resolves the executor and the command from the
// effective defs, so it covers custom verbs under any app name and skips
// undefined actions (POLICY-DEAD-RULE owns those).
func customSSHWrites(allows []policy.Rule, effTargets []admin.SSHTarget, defs map[string]appdef.Definition) []sshWrite {
	seen := map[string]struct{}{}
	var out []sshWrite
	for _, r := range allows {
		def, ok := defs[r.App]
		if !ok || def.App.Executor != "ssh" {
			continue
		}
		action, ok := def.Action(r.Action)
		if !ok {
			continue // undefined verb → POLICY-DEAD-RULE, not SSH-WRITE
		}
		if r.Action == "restart_service" || slices.Contains(inspectionActions, r.Action) {
			continue
		}
		desc := ""
		if action.Description != "" {
			desc = " — " + action.Description
		}
		command := strings.TrimSpace(action.Command)
		cmdHint := " (see its app definition)"
		if command != "" {
			cmdHint = "; it runs: " + command
		}
		scriptPath := scriptInvoked(command)
		for _, alias := range targetsForRule(r, effTargets) {
			key := alias + "\x00" + r.Action
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, sshWrite{alias: alias, action: r.Action, desc: desc, cmdHint: cmdHint, command: command, scriptPath: scriptPath})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].alias != out[j].alias {
			return out[i].alias < out[j].alias
		}
		return out[i].action < out[j].action
	})
	return out
}

// targetsForRule returns the target aliases a single allow rule reaches: its
// `target` constraint, or every effective target when unconstrained.
func targetsForRule(r policy.Rule, effTargets []admin.SSHTarget) []string {
	if alias := r.Constraints["target"]; alias != "" {
		return []string{alias}
	}
	out := make([]string, 0, len(effTargets))
	for _, t := range effTargets {
		out = append(out, t.Alias)
	}
	return out
}

// passthroughModeFindings flags a proposal-added app declared
// security_mode: passthrough. Policy evaluates a passthrough app with an EMPTY
// constraint context (see appdef PolicyContext), so every constrained rule on
// it is silently voided: a scoped allow stops matching, and — more dangerously
// — a scoped deny carve-out never fires. A reviewer who writes constraints
// against such an app gets no enforcement, so it demands typed acknowledgment.
func passthroughModeFindings(p Proposal) []Finding {
	var out []Finding
	for _, d := range p.Apps.Add {
		if d.App.SecurityMode == "passthrough" {
			out = append(out, Finding{
				RuleID: "APP-PASSTHROUGH-UNSCOPED", Severity: SevHigh, Resource: d.App.Name,
				Summary: "app is security_mode: passthrough — policy is evaluated with no constraint context, so every constrained allow/deny on it is silently ignored (target/path/service scoping and deny carve-outs do not apply)",
				Fix:     "use security_mode: protected so parameter constraints are enforced; keep passthrough only if the verbs are meant to be unscoped, acknowledging that no policy constraint will bind",
			})
		}
	}
	return out
}

// passthroughFindings flags a proposal-added verb whose command template is a
// generic runner rather than a fixed program with typed arguments. For ssh verbs
// (bounded by the remote host) the existing shape check applies. For SYSTEM
// (sudo) verbs the bar is higher — a generic runner there is arbitrary ROOT
// execution on the broker host, and a privileged writer can rewrite OpenScope's
// own rules — so a stricter analysis runs and its findings hard-fail apply (see
// isBlocking). The executor is resolved from the effective defs so an extension
// that omits `executor:` is judged by the namespace it joins.
func passthroughFindings(p Proposal, effDefs map[string]appdef.Definition) []Finding {
	var out []Finding
	for _, d := range p.Apps.Add {
		exec := d.App.Executor
		if ed, ok := effDefs[d.App.Name]; ok && ed.App.Executor != "" {
			exec = ed.App.Executor
		}
		names := make([]string, 0, len(d.Actions))
		for name := range d.Actions {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			cmd := d.Actions[name].Command
			if strings.TrimSpace(cmd) == "" {
				continue
			}
			res := d.App.Name + "·" + name
			if exec == "system" {
				if reason := systemPassthrough(cmd); reason != "" {
					out = append(out, Finding{
						RuleID: "SYS-SHELL-PASSTHROUGH", Severity: SevHigh, Resource: res,
						Summary: "system command template is a generic root runner (" + reason + ") — it turns a sudo verb into arbitrary root execution",
						Fix:     "make the command a fixed absolute program with typed {param} arguments; never a parameter as the program, a shell/interpreter, or an exec-delegating wrapper",
					})
				} else if reason := systemSelfGovern(cmd); reason != "" {
					out = append(out, Finding{
						RuleID: "SYS-SELF-GOVERN", Severity: SevHigh, Resource: res,
						Summary: "privileged system verb can overwrite root-owned files (" + reason + ") — it could rewrite the rules that confine the agent",
						Fix:     "use a bundled verb (manage_files has prefix gates); never let a custom sudo verb run a general-purpose file writer",
					})
				}
				continue
			}
			if exec == "ssm" {
				// SSM verbs run via AWS-RunShellScript, so a generic-runner template
				// is arbitrary ROOT execution on the instance — the SSM twin of a
				// passthrough ssh verb. Blocks unconditionally (see isBlocking).
				if reason := shellPassthrough(cmd); reason != "" {
					out = append(out, Finding{
						RuleID: "SSM-RUNSHELL-ARBITRARY", Severity: SevHigh, Resource: res,
						Summary: "ssm command template is a generic runner (" + reason + ") — via AWS-RunShellScript that is arbitrary root execution on the instance",
						Fix:     "make the command a fixed program with typed {param} arguments (or pin a custom SSM document); never pass a parameter as the command, an eval, or a shell -c body",
					})
				}
				continue
			}
			if reason := shellPassthrough(cmd); reason != "" {
				out = append(out, Finding{
					RuleID: "SSH-SHELL-PASSTHROUGH", Severity: SevHigh, Resource: res,
					Summary: "command template is a generic runner (" + reason + ") — that turns a typed verb into arbitrary remote execution",
					Fix:     "make the command a fixed program with typed {param} arguments; never pass a parameter as the command, an eval, or a shell -c body",
				})
			}
		}
	}
	return out
}

// systemPassthrough returns a non-empty reason when a SYSTEM command template is
// a generic root runner: its program is a parameter, not an absolute path, or a
// shell/interpreter/exec-delegating deputy. This is what keeps a custom sudo verb
// from degrading into "run arbitrary root command".
func systemPassthrough(cmd string) string {
	fields := strings.Fields(strings.TrimSpace(cmd))
	if len(fields) == 0 {
		return ""
	}
	prog := fields[0]
	if containsPlaceholder(prog) || isBarePlaceholder(prog) {
		return "the program is a parameter"
	}
	if !filepath.IsAbs(prog) {
		return "the program is not an absolute path"
	}
	if base := filepath.Base(prog); slices.Contains(systemDeputies, base) {
		return base + " is a shell/interpreter/wrapper that re-enables arbitrary execution"
	}
	return ""
}

// systemSelfGovern flags a system verb whose program is a general-purpose file
// writer — as a privileged verb it can target AdminDir, sudoers, or the daemon's
// own plist/binary, rewriting the control plane that confines the agent.
func systemSelfGovern(cmd string) string {
	fields := strings.Fields(strings.TrimSpace(cmd))
	if len(fields) == 0 {
		return ""
	}
	if base := filepath.Base(fields[0]); slices.Contains(systemWriters, base) {
		return base + " can overwrite arbitrary root-owned files including OpenScope's own config"
	}
	return ""
}

// customSystemVerbs returns (app, action) pairs an allow rule grants on a defined
// system-executor verb that is NOT one of the vetted bundled verbs — i.e. a
// command-template verb that runs as root. Mirrors customSSHWrites; the worst-
// case rendered command is shown so the operator acknowledges eyes-open.
func customSystemVerbs(allows []policy.Rule, defs map[string]appdef.Definition) []sysVerb {
	seen := map[string]struct{}{}
	var out []sysVerb
	for _, r := range allows {
		def, ok := defs[r.App]
		if !ok || def.App.Executor != "system" {
			continue
		}
		if slices.Contains(systemBundledVerbs, r.Action) {
			continue // vetted Go verb, gated by its own SYS-* rules
		}
		action, ok := def.Action(r.Action)
		if !ok {
			continue // undefined verb → POLICY-DEAD-RULE owns it
		}
		key := r.App + "\x00" + r.Action
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		hint := " (see its app definition)"
		if c := strings.TrimSpace(action.Command); c != "" {
			hint = "; worst case it runs: " + renderWorstCase(c)
		}
		out = append(out, sysVerb{app: r.App, action: r.Action, cmdHint: hint})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].app != out[j].app {
			return out[i].app < out[j].app
		}
		return out[i].action < out[j].action
	})
	return out
}

// renderWorstCase shows a command template with every {param} marked as
// agent-controlled, so the acknowledgment names the literal worst case.
func renderWorstCase(cmd string) string {
	return placeholderRE.ReplaceAllString(strings.TrimSpace(cmd), "<$1>")
}

type sysVerb struct{ app, action, cmdHint string }

var shellInterpreters = []string{"sh", "bash", "zsh", "dash", "ksh", "ash"}

// shellPassthrough returns a non-empty reason when cmd is a generic-runner shape.
func shellPassthrough(cmd string) string {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return ""
	}
	fields := strings.Fields(c)
	if len(fields) == 1 && isBarePlaceholder(fields[0]) {
		return "the whole command is a parameter"
	}
	if fields[0] == "eval" {
		return "eval of a parameter"
	}
	base := filepath.Base(fields[0])
	if slices.Contains(shellInterpreters, base) {
		for i := 1; i < len(fields); i++ {
			f := fields[i]
			// -c / -lc / -ec etc. — the next field is the script body.
			if strings.HasPrefix(f, "-") && strings.ContainsRune(f, 'c') {
				if i+1 < len(fields) && containsPlaceholder(fields[i+1]) {
					return base + " -c with a parameter as the script body"
				}
			}
		}
	}
	return ""
}

func isBarePlaceholder(s string) bool {
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") &&
		len(s) > 2 && !strings.ContainsAny(s[1:len(s)-1], "{}")
}

func containsPlaceholder(s string) bool {
	i := strings.IndexByte(s, '{')
	if i < 0 {
		return false
	}
	return strings.IndexByte(s[i:], '}') > 1
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

// uploadSourceRisk returns a non-empty reason when a LOCAL upload-source prefix
// is dangerous for the root daemon to read and ship off-box: it reaches a secret
// path, the home dir / ~/.ssh, or a broad system root.
func uploadSourceRisk(src, homeDir string, b Bounds) string {
	s := filepath.Clean(src)
	if hit, sec := reachesSecret(s, b.SSH.SecretAbsolutePaths); hit {
		return "reaches secrets at " + sec
	}
	if homeDir != "" {
		h := filepath.Clean(homeDir)
		ssh := filepath.Join(h, ".ssh")
		// equal/ancestor/descendant of either the home dir or ~/.ssh
		if s == h || isUnder(h, s) {
			return "is or contains the home directory"
		}
		if s == ssh || isUnder(ssh, s) || isUnder(s, ssh) {
			return "reaches ~/.ssh"
		}
	}
	for _, broad := range []string{"/", "/etc", "/Users", "/home", "/var", "/private", "/root"} {
		if s == filepath.Clean(broad) {
			return "is a broad system root"
		}
	}
	return ""
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
