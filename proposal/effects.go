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

// Effect is one derived consequence of one step in a command template's
// &&/;-chain. The calculus is deliberately small and honest: it classifies the
// handful of program shapes broker verbs actually use, and everything it cannot
// classify stays "unknown" (treated as mutating) rather than guessed at. Plan
// cannot prove a command correct — but it can BOUND its consequence: what it
// touches (scope), what a mid-chain failure strands (failure walk), and what
// cannot be inspected at all (exec-opaque).
type Effect struct {
	Step    int    `json:"step"`    // 1-based position in the chain
	Command string `json:"command"` // the trimmed segment
	Class   string `json:"class"`   // read | noop | load | start | restart | recreate | stop | delete | overwrite | create | exec-opaque | unknown
	Object  string `json:"object,omitempty"`
}

// mutating reports whether the effect changes host state. Unknown counts as
// mutating — the calculus fails toward caution, never toward "probably fine".
func (e Effect) mutating() bool {
	switch e.Class {
	case "read", "noop":
		return false
	}
	return true
}

// readOnlyPrograms classify as pure inspection when they carry no output
// redirect. Kept small on purpose: an unlisted program is "unknown", not read.
var readOnlyPrograms = map[string]bool{
	"cat": true, "ls": true, "grep": true, "head": true, "tail": true,
	"printf": true, "echo": true, "df": true, "du": true, "uptime": true,
	"journalctl": true, "uname": true, "hostname": true, "whoami": true,
	"id": true, "date": true, "true": true, "test": true, "sleep": true,
	"curl": true, "wget": true,
}

var redirectRE = regexp.MustCompile(`>>?\s*\S`)

// chainSegments splits a command template into its sequential steps on && and
// ; (| stays within a step — a pipe is one pipeline with one outcome).
func chainSegments(cmd string) []string {
	var segs []string
	for _, andSeg := range strings.Split(cmd, "&&") {
		for _, seg := range strings.Split(andSeg, ";") {
			if s := strings.TrimSpace(seg); s != "" {
				segs = append(segs, s)
			}
		}
	}
	return segs
}

// commandEffects derives the effect chain of a command template.
func commandEffects(cmd string) []Effect {
	var out []Effect
	for i, seg := range chainSegments(cmd) {
		e := classifySegment(seg)
		e.Step = i + 1
		e.Command = seg
		out = append(out, e)
	}
	return out
}

// classifySegment maps one chain step onto an effect class + object.
func classifySegment(seg string) Effect {
	fields := strings.Fields(seg)
	if len(fields) == 0 {
		return Effect{Class: "noop"}
	}
	prog := fields[0]
	base := prog[strings.LastIndex(prog, "/")+1:]

	// docker compose / docker-compose subcommands.
	if base == "docker-compose" || (base == "docker" && len(fields) > 1 && fields[1] == "compose") {
		sub, rest := composeSubcommand(fields)
		obj := lastNonFlag(rest)
		if obj != "" {
			obj = "container " + obj
		}
		switch sub {
		case "stop", "kill", "pause":
			return Effect{Class: "stop", Object: obj}
		case "rm", "down":
			return Effect{Class: "delete", Object: obj}
		case "up":
			if containsFlag(rest, "--force-recreate") {
				return Effect{Class: "recreate", Object: obj}
			}
			return Effect{Class: "start", Object: obj}
		case "restart":
			return Effect{Class: "restart", Object: obj}
		case "ps", "logs", "config", "version", "top", "events":
			return Effect{Class: "read", Object: obj}
		case "pull", "build":
			return Effect{Class: "load", Object: obj}
		default:
			return Effect{Class: "unknown", Object: obj}
		}
	}

	if base == "docker" && len(fields) > 1 {
		obj := lastNonFlag(fields[2:])
		switch fields[1] {
		case "load", "pull", "import", "build", "tag":
			return Effect{Class: "load", Object: "docker image store"}
		case "stop", "kill", "pause":
			return Effect{Class: "stop", Object: prefixed("container ", obj)}
		case "rm":
			return Effect{Class: "delete", Object: prefixed("container ", obj)}
		case "rmi", "prune":
			return Effect{Class: "delete", Object: "docker image store"}
		case "run", "create":
			return Effect{Class: "start", Object: prefixed("container ", obj)}
		case "restart":
			return Effect{Class: "restart", Object: prefixed("container ", obj)}
		case "start", "unpause":
			return Effect{Class: "start", Object: prefixed("container ", obj)}
		case "ps", "inspect", "logs", "images", "version", "info", "diff", "port":
			return Effect{Class: "read", Object: prefixed("container ", obj)}
		case "exec":
			return Effect{Class: "exec-opaque", Object: prefixed("container ", obj)}
		}
		return Effect{Class: "unknown"}
	}

	if base == "systemctl" && len(fields) > 1 {
		obj := prefixed("service ", lastNonFlag(fields[2:]))
		switch fields[1] {
		case "restart", "reload", "reload-or-restart", "try-restart":
			return Effect{Class: "restart", Object: obj}
		case "stop":
			return Effect{Class: "stop", Object: obj}
		case "start":
			return Effect{Class: "start", Object: obj}
		case "disable", "mask":
			return Effect{Class: "stop", Object: obj}
		case "enable", "unmask":
			return Effect{Class: "start", Object: obj}
		case "status", "show", "is-active", "is-enabled", "list-units", "cat":
			return Effect{Class: "read", Object: obj}
		}
		return Effect{Class: "unknown", Object: obj}
	}

	switch base {
	case "cd", "export", "set":
		return Effect{Class: "noop"}
	case "rm", "rmdir", "truncate":
		return Effect{Class: "delete", Object: prefixed("path ", lastNonFlag(fields[1:]))}
	case "tee", "dd", "cp", "mv", "install", "rsync", "ln", "patch", "sed":
		return Effect{Class: "overwrite", Object: prefixed("path ", lastNonFlag(fields[1:]))}
	case "tar", "unzip", "cpio", "gunzip", "gzip":
		if containsFlag(fields[1:], "-t") || hasTarListFlag(fields) {
			return Effect{Class: "read"}
		}
		return Effect{Class: "overwrite", Object: "extracted paths"}
	case "mkdir", "touch", "mkfifo":
		return Effect{Class: "create", Object: prefixed("path ", lastNonFlag(fields[1:]))}
	case "chmod", "chown", "chgrp":
		return Effect{Class: "overwrite", Object: prefixed("path ", lastNonFlag(fields[1:]))}
	}

	if strings.HasPrefix(prog, "/") {
		return Effect{Class: "exec-opaque", Object: prog}
	}
	if readOnlyPrograms[base] && !redirectRE.MatchString(seg) {
		return Effect{Class: "read"}
	}
	return Effect{Class: "unknown"}
}

func composeSubcommand(fields []string) (string, []string) {
	start := 1
	if fields[0] != "docker-compose" && len(fields) > 1 && fields[1] == "compose" {
		start = 2
	}
	for i := start; i < len(fields); i++ {
		f := fields[i]
		if strings.HasPrefix(f, "-") {
			// Global flags with a value argument (-f file, --project-directory d).
			if f == "-f" || f == "--file" || f == "--project-directory" || f == "-p" || f == "--project-name" {
				i++
			}
			continue
		}
		return f, fields[i+1:]
	}
	return "", nil
}

// valueFlags take a following argument; the token after one is a flag value,
// not the object. Boolean flags (-d, -f as force, -rf) are NOT listed — the
// token after them IS the object ("up -d web" → web).
var valueFlags = map[string]bool{
	"-t": true, "--timeout": true, "-n": true, "-u": true,
	"--file": true, "-p": true, "--project-name": true,
}

func lastNonFlag(fields []string) string {
	for i := len(fields) - 1; i >= 0; i-- {
		f := fields[i]
		if strings.HasPrefix(f, "-") || strings.HasPrefix(f, "{") && strings.HasSuffix(f, "}") {
			continue
		}
		if i > 0 && valueFlags[fields[i-1]] {
			continue
		}
		return f
	}
	return ""
}

func containsFlag(fields []string, flag string) bool {
	for _, f := range fields {
		if f == flag {
			return true
		}
	}
	return false
}

func hasTarListFlag(fields []string) bool {
	if len(fields) < 2 || fields[0] != "tar" {
		return false
	}
	mode := fields[1]
	return strings.Contains(strings.TrimPrefix(mode, "-"), "t")
}

func prefixed(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

// failureWalk enumerates what a mid-chain failure strands: for each step whose
// failure would leave an earlier-touched object stopped or deleted with no
// completed restore, it names the object and the stranded state. This is the
// generalization of the down-window hazard — the analysis that predicts "if
// the recreate dies here, the container is simply GONE".
func failureWalk(effects []Effect) []string {
	type objState struct{ state string } // "" | "stopped" | "deleted"
	var out []string
	states := map[string]*objState{}
	for i, e := range effects {
		// What would failing AT step i+1 leave behind? The states accumulated
		// from steps 1..i (a failing step's own effect is not guaranteed).
		var stranded []string
		for obj, st := range states {
			if st.state != "" {
				stranded = append(stranded, obj+" left "+strings.ToUpper(st.state))
			}
		}
		if len(stranded) > 0 && i < len(effects) {
			sort.Strings(stranded)
			out = append(out, fmt.Sprintf("if step %d (%s) fails → %s", e.Step, truncate(e.Command, 48), strings.Join(stranded, "; ")))
		}
		// Apply this step's effect.
		if e.Object == "" {
			continue
		}
		st := states[e.Object]
		if st == nil {
			st = &objState{}
			states[e.Object] = st
		}
		switch e.Class {
		case "stop":
			st.state = "stopped"
		case "delete":
			st.state = "deleted"
		case "start", "recreate", "restart":
			st.state = ""
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// frontingProxyRE matches container/service names that typically terminate
// traffic for EVERY domain on the host — restarting one is never a
// single-service change.
var frontingProxyRE = regexp.MustCompile(`\b(traefik|nginx|haproxy|caddy|envoy)\b`)

// VerbEffects is the per-verb consequence summary the plan renders: the derived
// effect chain, the failure walk, the declared impact (if any), and — when the
// constrained targets carry pinned facts — what else those hosts run.
type VerbEffects struct {
	AppAction   string   `json:"app_action"`
	Targets     []string `json:"targets,omitempty"`
	Effects     []Effect `json:"effects"`
	FailureWalk []string `json:"failure_walk,omitempty"`
	Impact      string   `json:"impact,omitempty"`
	CoTenants   []string `json:"co_tenants,omitempty"` // per target: "alias: name, name, …"
	Criticality string   `json:"criticality,omitempty"`
}

// verbEffects builds the consequence summaries for every proposal-added ssh
// verb with a command template.
func verbEffects(p Proposal, allows []policy.Rule, effTargets []admin.SSHTarget) []VerbEffects {
	targetByAlias := map[string]admin.SSHTarget{}
	for _, t := range effTargets {
		targetByAlias[t.Alias] = t
	}
	var out []VerbEffects
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
			if strings.TrimSpace(a.Command) == "" {
				continue
			}
			effects := commandEffects(a.Command)
			ve := VerbEffects{
				AppAction:   d.App.Name + "·" + name,
				Targets:     verbTargets(allows, effTargets, d.App.Name, name),
				Effects:     effects,
				FailureWalk: failureWalk(effects),
				Impact:      impactSummary(a.Impact),
			}
			var crit []string
			for _, alias := range ve.Targets {
				t, ok := targetByAlias[alias]
				if !ok {
					continue
				}
				if t.Criticality != "" {
					crit = append(crit, alias+"="+t.Criticality)
				}
				if t.Facts != nil && len(t.Facts.Containers) > 0 {
					ve.CoTenants = append(ve.CoTenants, alias+": "+strings.Join(t.Facts.Containers, ", "))
				}
			}
			ve.Criticality = strings.Join(crit, ", ")
			out = append(out, ve)
		}
	}
	return out
}

func impactSummary(im *appdef.Impact) string {
	if im == nil {
		return ""
	}
	parts := []string{}
	if len(im.Services) > 0 {
		parts = append(parts, "services="+strings.Join(im.Services, ","))
	}
	if im.Downtime != "" {
		parts = append(parts, "downtime="+im.Downtime)
	}
	if im.Rollback != "" {
		parts = append(parts, "rollback="+im.Rollback)
	}
	return strings.Join(parts, " · ")
}

// effectFindings derives the consequence-scoped findings from the calculus:
//   - SSH-OPS-HAZARD (WARN/MEDIUM) when a mutating effect touches a fronting
//     proxy — with pinned co-tenant facts the domains at stake are named.
//   - SSH-IMPACT-MISMATCH (MEDIUM) when the command touches objects the
//     declared impact omits — humans review claims, the machine catches
//     omissions.
//   - SSH-WRITE-NO-IMPACT (WARN) when a mutating verb declares no impact at
//     all.
func effectFindings(p Proposal, allows []policy.Rule, effTargets []admin.SSHTarget) []Finding {
	targetByAlias := map[string]admin.SSHTarget{}
	for _, t := range effTargets {
		targetByAlias[t.Alias] = t
	}
	var out []Finding
	for _, ve := range verbEffects(p, allows, effTargets) {
		action := findProposedAction(p, ve.AppAction)
		var mutatingObjects []string
		seen := map[string]bool{}
		hasMutation := false
		for _, e := range ve.Effects {
			if !e.mutating() {
				continue
			}
			hasMutation = true
			if e.Object != "" && !seen[e.Object] {
				seen[e.Object] = true
				mutatingObjects = append(mutatingObjects, e.Object)
			}
			if frontingProxyRE.MatchString(e.Object) {
				sev := SevWarn
				summary := fmt.Sprintf("step %d (%s) mutates a fronting proxy (%s) — that touches every domain the host serves, not one service", e.Step, truncate(e.Command, 40), e.Object)
				for _, alias := range ve.Targets {
					if t, ok := targetByAlias[alias]; ok && t.Facts != nil && len(t.Facts.Containers) > 1 {
						sev = SevMedium
						summary = fmt.Sprintf("step %d mutates a fronting proxy (%s) on %s, which also runs: %s — every one of them is in the blast radius", e.Step, e.Object, alias, strings.Join(t.Facts.Containers, ", "))
						break
					}
				}
				out = append(out, Finding{
					RuleID: "SSH-OPS-HAZARD", Severity: sev, Resource: ve.AppAction,
					Summary: summary,
					Fix:     "confirm the proxy restart is intended; declare it in impact.services and add a verify: that checks the OTHER tenants too",
				})
			}
		}
		if !hasMutation {
			continue
		}
		if action == nil {
			continue
		}
		if action.Impact == nil {
			out = append(out, Finding{
				RuleID: "SSH-WRITE-NO-IMPACT", Severity: SevWarn,
				Resource: ve.AppAction,
				Summary:  "mutating verb declares no impact: contract — reviewers approve it without a stated scope, downtime expectation, or rollback",
				Fix:      "add impact: {services: [...], downtime: none|momentary|outage, rollback: \"...\"} to the action",
			})
			continue
		}
		declared := map[string]bool{}
		for _, s := range action.Impact.Services {
			declared[strings.ToLower(s)] = true
		}
		var missing []string
		for _, obj := range mutatingObjects {
			name := objectName(obj)
			if name == "" || strings.Contains(name, "{") {
				continue // parameterized or unnamed — nothing to cross-check
			}
			if obj == "docker image store" || strings.HasPrefix(obj, "path ") || obj == "extracted paths" {
				continue // impact.services declares services, not artifact stores
			}
			if !declared[strings.ToLower(name)] {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			out = append(out, Finding{
				RuleID: "SSH-IMPACT-MISMATCH", Severity: SevMedium,
				Resource: ve.AppAction,
				Summary:  "the command mutates " + strings.Join(missing, ", ") + " but impact.services does not declare it — the reviewed claim understates the blast radius",
				Fix:      "add the missing service(s) to impact.services, or remove the step that touches them",
			})
		}
	}
	return out
}

// objectName strips the class prefix ("container web" → "web").
func objectName(obj string) string {
	for _, p := range []string{"container ", "service "} {
		if strings.HasPrefix(obj, p) {
			return strings.TrimPrefix(obj, p)
		}
	}
	return obj
}

// findProposedAction resolves "app·action" back to the proposal's action.
func findProposedAction(p Proposal, appAction string) *appdef.Action {
	app, name, ok := strings.Cut(appAction, "·")
	if !ok {
		return nil
	}
	for _, d := range p.Apps.Add {
		if d.App.Name != app {
			continue
		}
		if a, ok := d.Actions[name]; ok {
			return &a
		}
	}
	return nil
}
