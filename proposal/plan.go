// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/policy"
)

// MachineInfo is the host context shown in the plan header; the CLI fills it.
type MachineInfo struct {
	User          string
	Host          string
	OS            string
	DaemonRunning bool
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
	findings := Analyze(p, live, defs, b)

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

// isBlocking decides whether a finding hard-fails apply: either its rule ID is
// in the bounds blocking list, or it is a root-user finding under a bounds
// root_user: deny policy.
func isBlocking(b Bounds, f Finding) bool {
	if b.blocks(f.RuleID) {
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
