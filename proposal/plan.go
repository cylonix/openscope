// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/executor/sshexec"
	"github.com/openscope/openscope/policy"
)

// MachineInfo is the host context shown in the plan header; the CLI fills it.
type MachineInfo struct {
	User          string
	Host          string
	OS            string
	DaemonRunning bool
	// HomeDir is the home ssh resolves ~/.ssh against (the user the agent runs
	// as); the lint uses it to flag identity files the agent could read.
	HomeDir string
}

type Changes struct {
	SSHTargetsAdded   int
	SSHTargetsRemoved int
	SystemFirstWrite  bool
	NewManagers       int
	NewPackages       int
	NewServices       int
	NewProcNames      int
	NewPorts          int
	VerbsAdded        int
	PolicyAllowNew    int
	PolicyDenyNew     int
}

type Capability struct {
	Agent  string
	Action string // "app·action"
	Scope  string // constraint summary or "ALL"
}

type BoundsResult struct {
	Name   string
	Status string // "pass" | "FAIL" | "acknowledge"
	Detail string
}

type Plan struct {
	Proposal     Proposal
	Bounds       Bounds
	BoundsSource string
	Machine      MachineInfo

	Findings     []Finding
	Blocking     []Finding // findings whose rule ID the bounds file blocks
	Acknowledge  []Finding // High findings to confirm at apply
	Capabilities []Capability
	Changes      Changes
	BoundsTable  []BoundsResult

	Blocked bool
}

func BuildPlan(p Proposal, live LiveState, defs map[string]appdef.Definition, b Bounds, boundsSource string, machine MachineInfo) Plan {
	findings := Analyze(p, live, defs, b, machine.HomeDir)

	plan := Plan{
		Proposal: p, Bounds: b, BoundsSource: boundsSource, Machine: machine,
		Findings: findings,
	}

	for _, f := range findings {
		switch {
		case isBlocking(b, f):
			plan.Blocking = append(plan.Blocking, f)
			plan.Blocked = true
		case f.Severity == SevHigh:
			plan.Acknowledge = append(plan.Acknowledge, f)
		}
	}

	plan.Capabilities = capabilities(p)
	plan.Changes = changes(p, live)
	plan.BoundsTable = boundsTable(b, findings)
	return plan
}

// ApplyBypassResults folds a live parallel-path probe (run by the CLI — plan
// can't connect on its own) into the plan, replacing the offline MEDIUM
// SSH-PARALLEL-PATH "unverified" finding with a definitive verdict:
//   - any key authenticated, OR any probe was inconclusive → SSH-BYPASS (HIGH,
//     blocking per bounds). Fail closed: the check must CONFIRM rejection, not
//     merely fail to find a bypass.
//   - every key conclusively rejected → SSH-NO-BYPASS (PASS).
//
// It then recomputes Blocked and the bounds table. The CLI calls this only after
// actually running the probe (targets added + ~/.ssh keys present).
func (p *Plan) ApplyBypassResults(bypass, unknown []sshexec.BypassResult) {
	p.Findings = removeFindings(p.Findings, "SSH-PARALLEL-PATH") // had a live answer now

	var f Finding
	switch {
	case len(bypass) > 0:
		f = Finding{
			RuleID: "SSH-BYPASS", Severity: SevHigh,
			Resource: bypassKeyList(bypass),
			Summary:  fmt.Sprintf("%d ~/.ssh key(s) authenticate to the new target(s) — the agent can ssh directly, bypassing the broker", len(bypass)),
			Fix:      "de-authorize these keys on the host (edit its authorized_keys) or move them out of ~/.ssh, then re-run",
		}
	case len(unknown) > 0:
		f = Finding{
			RuleID: "SSH-BYPASS", Severity: SevHigh,
			Resource: "unverified",
			Summary:  fmt.Sprintf("%d key(s) could not be confirmed absent from the target(s)' authorized_keys (broker key could not read them, or CA/command-based auth is configured) — fail closed: rejection must be proven before access is granted", len(unknown)),
			Fix:      "make the target's authorized_keys readable via the broker key and re-run, or run `openscope ssh check-bypass --live-auth` to attempt a real auth; or pass --skip-bypass-check to override deliberately",
		}
	default:
		f = Finding{
			RuleID: "SSH-NO-BYPASS", Severity: SevPass,
			Resource: "~/.ssh",
			Summary:  "no ~/.ssh key reaches the new target(s) — verified live; the broker boundary holds",
		}
	}
	p.Findings = append(p.Findings, f)
	if isBlocking(p.Bounds, f) {
		p.Blocking = append(p.Blocking, f)
	}
	p.Blocked = len(p.Blocking) > 0
	sort.SliceStable(p.Findings, func(i, j int) bool { return p.Findings[i].Severity > p.Findings[j].Severity })
	p.BoundsTable = boundsTable(p.Bounds, p.Findings)
}

func removeFindings(findings []Finding, ruleID string) []Finding {
	out := findings[:0]
	for _, f := range findings {
		if f.RuleID != ruleID {
			out = append(out, f)
		}
	}
	return out
}

func bypassKeyList(results []sshexec.BypassResult) string {
	seen := map[string]bool{}
	var names []string
	for _, r := range results {
		base := filepath.Base(r.Key)
		if !seen[base] {
			seen[base] = true
			names = append(names, base)
		}
	}
	return strings.Join(names, ", ")
}

// isBlocking decides whether a finding hard-fails apply: either its rule ID is
// in the bounds blocking list, or it is a root-user finding under a bounds
// root_user: deny policy.
func isBlocking(b Bounds, f Finding) bool {
	if b.blocks(f.RuleID) {
		return true
	}
	// These guard the integrity of the verb mechanism and block unconditionally
	// — independent of bounds, since a legacy bounds.yaml predates them and there
	// is deliberately no escape hatch for a generic-runner verb (it would defeat
	// the typed-broker model) or a verb definition that collides with an app.
	switch f.RuleID {
	case "SSH-SHELL-PASSTHROUGH", "SYS-SHELL-PASSTHROUGH", "SYS-SELF-GOVERN", "APP-DEF-CONFLICT", "SSH-UPLOAD-SECRET":
		return true
	}
	if f.RuleID == "SSH-ROOT-USER" && b.SSH.RootUser == "deny" {
		return true
	}
	return false
}

func capabilities(p Proposal) []Capability {
	var caps []Capability
	for _, r := range allowRules(p.Policy.Add) {
		caps = append(caps, Capability{
			Agent:  r.Agent,
			Action: r.App + "·" + r.Action,
			Scope:  scopeString(r),
		})
	}
	sort.SliceStable(caps, func(i, j int) bool {
		if caps[i].Agent != caps[j].Agent {
			return caps[i].Agent < caps[j].Agent
		}
		return caps[i].Action < caps[j].Action
	})
	return caps
}

// verbRows returns the custom verbs a proposal adds as [app·action, command,
// params] rows, sorted, for the plan's "custom verbs" section. The command is
// the exact template the operator is authorizing; params show each name and its
// constraint (path/service) so the scope is visible alongside the command.
func verbRows(p Proposal) [][]string {
	var rows [][]string
	for _, d := range p.Apps.Add {
		names := make([]string, 0, len(d.Actions))
		for name := range d.Actions {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			a := d.Actions[name]
			parts := make([]string, 0, len(a.Parameters))
			for _, pm := range a.Parameters {
				s := pm.Name
				if pm.Constraint != "" {
					s += ":" + pm.Constraint
				}
				parts = append(parts, s)
			}
			rows = append(rows, []string{d.App.Name + "·" + name, a.Command, strings.Join(parts, ", ")})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return rows
}

func scopeString(r policy.Rule) string {
	if len(r.Constraints) == 0 {
		return "ALL (scoped by admin allow-lists)"
	}
	keys := make([]string, 0, len(r.Constraints))
	for k := range r.Constraints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+r.Constraints[k])
	}
	return strings.Join(parts, " ")
}

func changes(p Proposal, live LiveState) Changes {
	c := Changes{
		SSHTargetsAdded:   len(p.SSHTargets.Add),
		SSHTargetsRemoved: len(p.SSHTargets.Remove),
		SystemFirstWrite:  len(live.System.Packages.Managers) == 0 && len(live.System.Packages.Allowed) == 0,
		NewManagers:       len(p.SystemCommands.Packages.Managers.Add),
		NewPackages:       len(p.SystemCommands.Packages.Allowed.Add),
		NewServices:       len(p.SystemCommands.Services.Allowed.Add),
		NewProcNames:      len(p.SystemCommands.Processes.AllowedNames.Add),
		NewPorts:          len(p.SystemCommands.Ports.Allowed.Add),
		VerbsAdded:        len(p.Apps.Add),
	}
	liveKeys := map[string]struct{}{}
	for _, r := range live.Policy.Rules {
		liveKeys[ruleKey(r)] = struct{}{}
	}
	for _, r := range p.Policy.Add {
		if _, ok := liveKeys[ruleKey(r)]; ok {
			continue
		}
		if r.Effect == "deny" {
			c.PolicyDenyNew++
		} else {
			c.PolicyAllowNew++
		}
	}
	return c
}

func boundsTable(b Bounds, findings []Finding) []BoundsResult {
	count := func(id string) int {
		n := 0
		for _, f := range findings {
			if f.RuleID == id {
				n++
			}
		}
		return n
	}
	var rows []BoundsResult

	sudo := count("SYS-SUDO-MANAGER")
	rows = append(rows, BoundsResult{"no_sudo_managers", passFail(sudo == 0, b.blocks("SYS-SUDO-MANAGER")), fmt.Sprintf("%d found", sudo)})

	secret := count("SSH-SECRET-PATH")
	rows = append(rows, BoundsResult{"ssh.read_path_reaches_secret", passFail(secret == 0, b.blocks("SSH-SECRET-PATH")), fmt.Sprintf("%d found", secret)})

	keyReadable := count("SSH-KEY-READABLE")
	rows = append(rows, BoundsResult{"ssh.key_readable_by_agent", passFail(keyReadable == 0, b.blocks("SSH-KEY-READABLE")), fmt.Sprintf("%d found", keyReadable)})

	// Parallel path: a confirmed/unconfirmable bypass fails; a live-clear probe
	// passes; an un-probed (offline) proposal with ~/.ssh keys shows "unverified".
	switch {
	case count("SSH-BYPASS") > 0:
		rows = append(rows, BoundsResult{"ssh.no_parallel_path", passFail(false, b.blocks("SSH-BYPASS")), "a ~/.ssh key reaches the host (or could not be verified)"})
	case count("SSH-NO-BYPASS") > 0:
		rows = append(rows, BoundsResult{"ssh.no_parallel_path", "pass", "verified live — no ~/.ssh key reaches the target(s)"})
	case count("SSH-PARALLEL-PATH") > 0:
		rows = append(rows, BoundsResult{"ssh.no_parallel_path", "warn", "unverified — inspection deferred to apply (root), or skipped"})
	}

	code := count("SYS-APP-CODEEXEC")
	rows = append(rows, BoundsResult{"system.app_install_from_writable_source", passFail(code == 0, b.blocks("SYS-APP-CODEEXEC")), fmt.Sprintf("%d found", code)})

	conflict := count("SSH-TARGET-CONFLICT")
	if conflict > 0 {
		rows = append(rows, BoundsResult{"ssh.target_conflict", passFail(false, b.blocks("SSH-TARGET-CONFLICT")), fmt.Sprintf("%d found", conflict)})
	}

	maxT := count("POLICY-MAX-TARGETS")
	if maxT > 0 {
		rows = append(rows, BoundsResult{"max_targets_per_agent", passFail(false, b.blocks("POLICY-MAX-TARGETS")), fmt.Sprintf("%d agent(s) over cap", maxT)})
	} else if b.MaxTargetsPerAgent > 0 {
		rows = append(rows, BoundsResult{"max_targets_per_agent", "pass", fmt.Sprintf("≤ %d", b.MaxTargetsPerAgent)})
	}

	root := count("SSH-ROOT-USER")
	if root > 0 {
		switch b.SSH.RootUser {
		case "deny":
			rows = append(rows, BoundsResult{"ssh.root_user", "FAIL", fmt.Sprintf("%d blocked (root_user: deny)", root)})
		case "allow":
			rows = append(rows, BoundsResult{"ssh.root_user", "pass", fmt.Sprintf("%d allowed", root)})
		default:
			rows = append(rows, BoundsResult{"ssh.root_user", "acknowledge", fmt.Sprintf("%d to confirm", root)})
		}
	}
	return rows
}

func passFail(ok, blocking bool) string {
	if ok {
		return "pass"
	}
	if blocking {
		return "FAIL"
	}
	return "warn"
}

func ruleKey(r policy.Rule) string {
	keys := make([]string, 0, len(r.Constraints))
	for k := range r.Constraints {
		keys = append(keys, k+"="+r.Constraints[k])
	}
	sort.Strings(keys)
	return r.Effect + "|" + r.Agent + "|" + r.App + "|" + r.Action + "|" + strings.Join(keys, ",")
}
