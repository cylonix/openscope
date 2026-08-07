// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/policy"
)

// VerbDiff records that a proposed action collides with one that already exists
// (root-applied registry or bundled) with a DIFFERENT definition — an apply
// would replace behavior a human already approved, so the reviewer must see the
// old and new templates side by side, not just the new one.
type VerbDiff struct {
	AppAction   string `json:"app_action"`
	OldCommand  string `json:"old_command"`
	NewCommand  string `json:"new_command"`
	OldVerify   string `json:"old_verify,omitempty"`
	NewVerify   string `json:"new_verify,omitempty"`
	RootApplied bool   `json:"root_applied"` // old came from the approved registry
	Bundled     bool   `json:"bundled"`      // old is a bundled curated action
}

// verbDiffs compares each proposal-added action against the loaded namespace
// (bundled ⊕ apps.d ⊕ root registry). An IDENTICAL re-add is not a diff — a
// proposal that re-states an approved verb verbatim stays idempotent.
func verbDiffs(p Proposal, defs map[string]appdef.Definition) []VerbDiff {
	var out []VerbDiff
	for _, d := range p.Apps.Add {
		existing, ok := defs[d.App.Name]
		if !ok {
			continue
		}
		names := make([]string, 0, len(d.Actions))
		for name := range d.Actions {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			old, ok := existing.Actions[name]
			if !ok {
				continue
			}
			proposed := d.Actions[name]
			if actionSignature(old) == actionSignature(proposed) {
				continue
			}
			out = append(out, VerbDiff{
				AppAction:   d.App.Name + "·" + name,
				OldCommand:  old.Command,
				NewCommand:  proposed.Command,
				OldVerify:   old.Verify,
				NewVerify:   proposed.Verify,
				RootApplied: old.RootApplied,
				Bundled:     existing.Bundled && !old.RootApplied,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AppAction < out[j].AppAction })
	return out
}

// actionSignature canonicalizes every behavior-bearing field of an action so
// "differs" means "apply would change what runs", never formatting noise.
func actionSignature(a appdef.Action) string {
	params := make([]string, 0, len(a.Parameters))
	for _, p := range a.Parameters {
		params = append(params, p.Name+":"+p.Type+":"+p.Constraint+":"+p.PolicyKey)
	}
	impact := ""
	if a.Impact != nil {
		impact = strings.Join(a.Impact.Services, ",") + "|" + a.Impact.Downtime + "|" + a.Impact.Rollback
	}
	return strings.Join([]string{
		a.Command, a.Script, a.Stdin, a.StdinFile, a.StdinMedia, a.StdinPlatform,
		a.Verify, fmt.Sprint(a.VerifyRetries), fmt.Sprint(a.VerifyDelaySeconds),
		impact, strings.Join(params, ","),
	}, "\x00")
}

// verbReplacementFindings turns each diff into a finding: replacing a
// root-applied (human-approved) template demands typed acknowledgment;
// shadowing a bundled action is a medium correctness signal (for the curated
// ssh verbs the built-in dispatch wins and the custom template never runs).
func verbReplacementFindings(diffs []VerbDiff) []Finding {
	var out []Finding
	for _, d := range diffs {
		switch {
		case d.RootApplied:
			out = append(out, Finding{
				RuleID: "VERB-REPLACES-APPROVED", Severity: SevHigh,
				Resource: d.AppAction,
				Summary:  "REPLACES a human-approved command template — apply overwrites the pinned verb; review the old → new diff in the VERB REPLACEMENTS section",
				Fix:      "confirm the changed clause is intended; to keep the approved template, drop this apps.add entry",
			})
		case d.Bundled:
			out = append(out, Finding{
				RuleID: "VERB-SHADOWS-BUNDLED", Severity: SevMedium,
				Resource: d.AppAction,
				Summary:  "redefines a bundled action — for curated ssh verbs the built-in dispatch wins and this template will NOT run",
				Fix:      "give the verb its own action name instead of a curated one",
			})
		default:
			out = append(out, Finding{
				RuleID: "VERB-REPLACES-APPROVED", Severity: SevHigh,
				Resource: d.AppAction,
				Summary:  "replaces an existing verb definition with different behavior — review the old → new diff in the VERB REPLACEMENTS section",
				Fix:      "confirm the changed clause is intended",
			})
		}
	}
	return out
}

var composeV1RecreateRE = regexp.MustCompile(`docker-compose\b[^|;&]*\bup\b[^|;&]*--force-recreate|docker-compose\b[^|;&]*--force-recreate[^|;&]*\bup\b`)
var stopVerbRE = regexp.MustCompile(`\b(stop|rm|down)\b`)
var upVerbRE = regexp.MustCompile(`\bup\b|\bstart\b`)

// operationalHazardFindings attaches KNOWN-footgun notes to proposed command
// templates. These are advisory (never blocking): plan verifies authority, not
// correctness — but when a template matches a hazard the project has already
// been burned by, the reviewer deserves the note next to the command. A hazard
// confirmed by pinned target facts (e.g. the constrained target actually runs
// compose v1) escalates from WARN to MEDIUM.
func operationalHazardFindings(p Proposal, allows []policy.Rule, effTargets []admin.SSHTarget) []Finding {
	targetByAlias := map[string]admin.SSHTarget{}
	for _, t := range effTargets {
		targetByAlias[t.Alias] = t
	}
	var out []Finding
	for _, d := range p.Apps.Add {
		if d.App.Executor != "ssh" {
			continue
		}
		names := make([]string, 0, len(d.Actions))
		for name := range d.Actions {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			a := d.Actions[name]
			cmd := a.Command
			if strings.TrimSpace(cmd) == "" {
				continue
			}
			res := d.App.Name + "·" + name

			if composeV1RecreateRE.MatchString(cmd) {
				sev := SevWarn
				summary := "`docker-compose up --force-recreate` crashes compose v1 (KeyError 'ContainerConfig') on images saved by modern Docker, mid-recreate — the container is left REMOVED"
				for _, alias := range verbTargets(allows, effTargets, d.App.Name, name) {
					if t, ok := targetByAlias[alias]; ok && t.Facts != nil && t.Facts.ComposeMajorV1() {
						sev = SevMedium
						summary = "target " + alias + " runs " + t.Facts.Compose + ": `up --force-recreate` there crashes mid-recreate (KeyError 'ContainerConfig') on images saved by modern Docker, leaving the container REMOVED"
						break
					}
				}
				out = append(out, Finding{
					RuleID: "SSH-OPS-HAZARD", Severity: sev, Resource: res,
					Summary: summary,
					Fix:     "use the stop && rm -f && up -d sequence (fresh-create path) instead of --force-recreate, and declare a verify:",
				})
			}

			if downWindowHazard(cmd) {
				out = append(out, Finding{
					RuleID: "SSH-OPS-HAZARD", Severity: SevWarn, Resource: res,
					Summary: "the command stops/removes before it starts — a failure in the middle of the chain leaves the service DOWN (the broker call errors, but nothing restores the host)",
					Fix:     "declare a verify: so the unhealthy end-state is loud, and document the rollback in the action description",
				})
			}

			if strings.Contains(cmd, "docker load") && strings.TrimSpace(a.StdinFile) != "" && a.StdinMedia == "" {
				out = append(out, Finding{
					RuleID: "SSH-OPS-HAZARD", Severity: SevWarn, Resource: res,
					Summary: "streams an artifact into `docker load` without a stdin_media gate — a wrong-architecture image is only discovered on the host, as a crash-looping container",
					Fix:     "add `stdin_media: docker-image` (and `stdin_platform: <os/arch>`, or pin target facts) so the broker refuses a mismatched artifact locally",
				})
			}
		}
	}
	return out
}

// downWindowHazard reports whether an &&-chain runs a stop/rm/down step before
// a later up/start step — the shape whose mid-chain failure strands the host in
// the stopped state.
func downWindowHazard(cmd string) bool {
	segs := strings.Split(cmd, "&&")
	sawStop := false
	for _, s := range segs {
		if sawStop && upVerbRE.MatchString(s) {
			return true
		}
		if stopVerbRE.MatchString(s) {
			sawStop = true
		}
	}
	return false
}

// verbTargets resolves which target aliases the allow rules grant app·action on.
func verbTargets(allows []policy.Rule, effTargets []admin.SSHTarget, app, action string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range allows {
		if r.App != app || r.Action != action {
			continue
		}
		for _, alias := range targetsForRule(r, effTargets) {
			if _, dup := seen[alias]; dup {
				continue
			}
			seen[alias] = struct{}{}
			out = append(out, alias)
		}
	}
	sort.Strings(out)
	return out
}
