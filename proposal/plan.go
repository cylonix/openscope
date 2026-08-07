// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/audit"
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
	SSMTargetsAdded   int
	SSMTargetsRemoved int
	SystemFirstWrite  bool
	NewManagers       int
	NewPackages       int
	NewServices       int
	NewProcNames      int
	NewPorts          int
	VerbsAdded        int
	VerbsReplaced     int
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
	// VerbDiffs are proposed actions that REPLACE an existing definition —
	// rendered as an old → new diff so re-review reads the changed clause, not
	// the whole template.
	VerbDiffs []VerbDiff
	// VerbEffects are the per-verb consequence summaries derived from command
	// templates (effect chain, failure walk, co-tenants, declared impact).
	VerbEffects []VerbEffects
	// VerbHistories are recent audit-log outcomes for the verbs this proposal
	// grants — filled by the CLI via ApplyVerbHistory (the log may be
	// root-owned, so plan-as-user may not be able to read it).
	VerbHistories []VerbHistory

	Blocked bool
}

// VerbHistory summarizes the recent recorded runs of one app·action.
type VerbHistory struct {
	AppAction  string `json:"app_action"`
	Total      int    `json:"total"`
	Failures   int    `json:"failures"`
	LastResult string `json:"last_result"`
	LastReason string `json:"last_reason,omitempty"`
	LastAt     string `json:"last_at,omitempty"`
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
	plan.VerbDiffs = verbDiffs(p, defs)
	plan.Changes.VerbsReplaced = len(plan.VerbDiffs)
	plan.VerbEffects = verbEffects(p, allowRules(p.Policy.Add), p.effectiveTargets(live.SSHTargets))
	plan.BoundsTable = boundsTable(b, findings)
	return plan
}

// ApplyVerbHistory folds the audit log's recent outcomes into the plan for the
// verbs this proposal defines or grants — the CLI supplies them (like the
// bypass probe) because the root-owned log may be unreadable at plan-as-user.
// A verb whose most recent run failed gets a WARN: the past run is the
// cheapest, most honest risk predictor there is.
func (p *Plan) ApplyVerbHistory(outcomes map[string][]audit.Outcome) {
	for _, key := range proposalVerbKeys(p.Proposal) {
		list := outcomes[key]
		if len(list) == 0 {
			continue
		}
		h := VerbHistory{
			AppAction:  key,
			Total:      len(list),
			LastResult: list[0].Result,
			LastReason: list[0].Reason,
			LastAt:     list[0].Timestamp.UTC().Format(time.RFC3339),
		}
		for _, o := range list {
			if o.Failed() {
				h.Failures++
			}
		}
		p.VerbHistories = append(p.VerbHistories, h)
		if list[0].Failed() {
			p.Findings = append(p.Findings, Finding{
				RuleID: "SSH-VERB-HISTORY", Severity: SevWarn,
				Resource: key,
				Summary: fmt.Sprintf("the LAST recorded run of this verb FAILED (%s: %s) — %d of its last %d run(s) failed",
					list[0].Result, truncate(list[0].Reason, 90), h.Failures, h.Total),
				Fix: "understand the previous failure before granting/running again; the audit log holds the full reason",
			})
		}
	}
	sort.SliceStable(p.Findings, func(i, j int) bool { return p.Findings[i].Severity > p.Findings[j].Severity })
}

// proposalVerbKeys returns the "app·action" keys this proposal defines
// (apps.add) or grants (policy.add allow rules), deduped and sorted.
func proposalVerbKeys(p Proposal) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(key string) {
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	for _, d := range p.Apps.Add {
		for name := range d.Actions {
			add(d.App.Name + "·" + name)
		}
	}
	for _, r := range allowRules(p.Policy.Add) {
		add(r.App + "·" + r.Action)
	}
	sort.Strings(out)
	return out
}

// ApplyBypassResults folds a live parallel-path probe (run by the CLI — plan
// can't connect on its own) into the plan, replacing the offline MEDIUM
// SSH-PARALLEL-PATH "unverified" finding with a definitive verdict. Each
// failure class present gets its OWN finding (they have different fixes, and
// one must not mask another when a proposal adds several targets):
//   - a key authenticated → SSH-BYPASS: de-authorize the personal key.
//   - the target rejected the broker's own key → SSH-BYPASS: the brokered
//     connection is broken; install the broker key.
//   - a probe was inconclusive → SSH-BYPASS: fail closed, rejection must be
//     proven before access is granted.
//   - none of the above → SSH-NO-BYPASS (PASS).
//
// All three failure findings share rule ID SSH-BYPASS so the existing bounds
// blocking_rules entry keeps hard-failing apply on installs whose root-owned
// bounds.yaml predates the finer-grained outcomes.
//
// It then recomputes Blocked and the bounds table. The CLI calls this only after
// actually running the probe (targets added + ~/.ssh keys present).
func (p *Plan) ApplyBypassResults(bypass, brokerRejected, unknown []sshexec.BypassResult) {
	p.Findings = removeFindings(p.Findings, "SSH-PARALLEL-PATH") // had a live answer now

	var found []Finding
	if len(bypass) > 0 {
		found = append(found, Finding{
			RuleID: "SSH-BYPASS", Severity: SevHigh,
			Resource: bypassKeyList(bypass),
			Summary:  fmt.Sprintf("%d ~/.ssh key(s) authenticate to the new target(s) — the agent can ssh directly, bypassing the broker", len(bypass)),
			Fix:      "de-authorize these keys on the host (edit its authorized_keys) or move them out of ~/.ssh, then re-run",
		})
	}
	if len(brokerRejected) > 0 {
		found = append(found, Finding{
			RuleID: "SSH-BYPASS", Severity: SevHigh,
			Resource: bypassTargetList(brokerRejected),
			Summary:  fmt.Sprintf("the broker key was REJECTED by %d target(s) — the brokered connection itself does not work, so the grant would be dead on arrival and the bypass boundary cannot be verified", len(brokerRejected)),
			Fix:      "install the broker's public key in the target user's authorized_keys (or fix the target's user/identity_file), then re-run",
		})
	}
	if len(unknown) > 0 {
		found = append(found, Finding{
			RuleID: "SSH-BYPASS", Severity: SevHigh,
			Resource: "unverified",
			Summary:  fmt.Sprintf("%d key(s) could not be confirmed absent from the target(s)' authorized_keys (broker key could not read them, or CA/command-based auth is configured) — fail closed: rejection must be proven before access is granted", len(unknown)),
			Fix:      "make the target's authorized_keys readable via the broker key and re-run, or run `openscope ssh check-bypass --live-auth` to attempt a real auth; or pass --skip-bypass-check to override deliberately",
		})
	}
	if len(found) == 0 {
		found = append(found, Finding{
			RuleID: "SSH-NO-BYPASS", Severity: SevPass,
			Resource: "~/.ssh",
			Summary:  "no ~/.ssh key reaches the new target(s) — verified live; the broker boundary holds",
		})
	}
	for _, f := range found {
		p.Findings = append(p.Findings, f)
		// Same routing as BuildPlan: blocking per bounds, else a HIGH finding
		// still demands typed acknowledgment — widening bounds.yaml to unblock
		// SSH-BYPASS must not turn a live-confirmed bypass into a clean verdict.
		switch {
		case isBlocking(p.Bounds, f):
			p.Blocking = append(p.Blocking, f)
		case f.Severity == SevHigh:
			p.Acknowledge = append(p.Acknowledge, f)
		}
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

// bypassTargetList names the affected targets — results are per (target, key)
// pairs, but a broker-key rejection is a per-target failure, so keys are dropped
// and targets deduped.
func bypassTargetList(results []sshexec.BypassResult) string {
	seen := map[string]bool{}
	var names []string
	for _, r := range results {
		name := r.Target
		if name == "" {
			name = r.Host
		} else if r.Host != "" {
			name += " (" + r.Host + ")"
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
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
	// SSH-SCRIPT-WRITABLE joins them: if a write verb can overwrite the script
	// another verb runs, the agent has arbitrary execution behind a "safe" verb —
	// the code-custody analog of an agent-readable key, equally un-approvable.
	switch f.RuleID {
	case "SSH-SHELL-PASSTHROUGH", "SYS-SHELL-PASSTHROUGH", "SSM-RUNSHELL-ARBITRARY", "SYS-SELF-GOVERN", "APP-DEF-CONFLICT", "SSH-UPLOAD-SECRET", "SSH-SCRIPT-WRITABLE":
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

// verbRows returns the custom verbs a proposal adds as [app·action, status,
// command, params] rows, sorted, for the plan's "custom verbs" section. The
// command is the exact template the operator is authorizing; params show each
// name and its constraint (path/service) so the scope is visible alongside the
// command. replaced marks actions that overwrite an existing definition — those
// read "REPLACES" so a rewrite of an approved verb can't render like a new one.
func verbRows(p Proposal, replaced map[string]bool) [][]string {
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
			key := d.App.Name + "·" + name
			status := "new"
			if replaced[key] {
				status = "REPLACES"
			}
			verify := strings.TrimSpace(a.Verify)
			if verify == "" {
				verify = "—"
			}
			rows = append(rows, []string{key, status, a.Command, verify, strings.Join(parts, ", ")})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return rows
}

// verbChangeCell renders the "custom verbs" changes cell, calling out how many
// of the added definitions replace an existing approved command.
func verbChangeCell(c Changes) string {
	if c.VerbsReplaced > 0 {
		return fmt.Sprintf("+%d defined — %d REPLACE existing approved command(s)", c.VerbsAdded, c.VerbsReplaced)
	}
	return fmt.Sprintf("+%d defined (command templates)", c.VerbsAdded)
}

// replacedSet keys the plan's verb diffs by app·action for the verbs table.
func replacedSet(diffs []VerbDiff) map[string]bool {
	out := make(map[string]bool, len(diffs))
	for _, d := range diffs {
		out[d.AppAction] = true
	}
	return out
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
		SSMTargetsAdded:   len(p.SSMTargets.Add),
		SSMTargetsRemoved: len(p.SSMTargets.Remove),
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
		rows = append(rows, BoundsResult{"ssh.no_parallel_path", passFail(false, b.blocks("SSH-BYPASS")), "a ~/.ssh key reaches the host, the broker key was rejected, or the check was inconclusive"})
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
