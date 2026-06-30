// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package capabilities computes, for one agent, the set of actions it is
// currently allowed to run and the exact shape of each — joined live from the
// policy (allow/deny rules), the app definitions (parameter shapes), and the
// ssh targets (valid values). It is the single source of truth for that
// surface, shared by the `openscope capabilities` CLI command and the
// `openscope-mcp` MCP front-end, so the two never drift.
package capabilities

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/policy"
	"github.com/openscope/openscope/resources"
)

// Param describes one parameter of an allowed action. Fixed/Pinned capture a
// policy constraint that pins the value; AllowedValues is the concrete
// enumerable set (target aliases, a target's allowed_services) when one exists;
// Hint is human-readable guidance for free params that cannot be cleanly
// enumerated (e.g. path prefixes).
type Param struct {
	Name          string // appdef parameter name (the ipc Params key)
	Flag          string // "--" + Name (CLI display form)
	PolicyKey     string // policy-context key (policy_key, else Name); what policy.Evaluate and passport.Scope match on
	Type          string // "string" | "integer"
	Required      bool
	Pinned        bool     // policy pinned this param to Fixed
	Fixed         string   // the pinned value (valid only when Pinned)
	Constraint    string   // "" | "path" | "service" | "local_source"
	Hint          string   // human guidance for a free param
	AllowedValues []string // concrete enumerable allow-list, when available
}

// Capability is one thing an agent may do.
type Capability struct {
	App         string
	Action      string
	Description string
	Command     string // ready-to-run CLI form
	Params      []Param
	Note        string // set when the allow rule is inert (no such app/action)
}

// Denied is a deny rule that applies to the agent (deny overrides allow).
type Denied struct {
	App         string
	Action      string
	Constraints map[string]string
}

// Result is the full per-agent surface.
type Result struct {
	Agent        string
	Capabilities []Capability
	Denied       []Denied
}

// BuildFromPaths loads the policy, app definitions, and ssh targets from disk
// and projects the surface for agentID. The inputs are exactly those the CLI
// reads today, so the result tracks config with no separate documentation.
func BuildFromPaths(paths config.Paths, agentID string) (Result, error) {
	pf, err := policy.LoadDefault(paths)
	if err != nil {
		return Result{}, fmt.Errorf("load policy: %w", err)
	}
	defs, err := LoadAllDefinitions(paths)
	if err != nil {
		return Result{}, fmt.Errorf("load app definitions: %w", err)
	}
	targets, _ := admin.LoadSSHTargetsOrDefault(paths) // best-effort value hints
	return Build(agentID, defs, pf, targets), nil
}

// Build projects the surface for agentID from already-loaded inputs. It is
// pure (no I/O), so callers that already hold the inputs can reuse them and
// tests can drive it directly.
func Build(agentID string, defs map[string]appdef.Definition, pf policy.File, targets admin.SSHTargets) Result {
	res := Result{Agent: agentID}
	for _, r := range pf.Rules {
		if r.Agent != agentID {
			continue
		}
		if r.Effect == "deny" {
			res.Denied = append(res.Denied, Denied{App: r.App, Action: r.Action, Constraints: r.Constraints})
			continue
		}
		res.Capabilities = append(res.Capabilities, buildCapability(agentID, r, defs, targets))
	}
	sort.SliceStable(res.Capabilities, func(i, j int) bool {
		a, b := res.Capabilities[i], res.Capabilities[j]
		if a.App != b.App {
			return a.App < b.App
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Command < b.Command
	})
	return res
}

func buildCapability(agentID string, r policy.Rule, defs map[string]appdef.Definition, targets admin.SSHTargets) Capability {
	c := Capability{App: r.App, Action: r.Action}
	base := fmt.Sprintf("openscope %s %s --agent %s", r.App, r.Action, agentID)

	def, ok := defs[r.App]
	if !ok {
		c.Command, c.Note = base, "no such app in the current definitions — this allow rule is inert"
		return c
	}
	action, ok := def.Action(r.Action)
	if !ok {
		c.Command, c.Note = base, "no such action for this app — this allow rule is inert"
		return c
	}
	c.Description = action.Description

	// The ssh target this rule is scoped to (if any), for value hints.
	var tgt admin.SSHTarget
	var haveTgt bool
	if alias := r.Constraints["target"]; alias != "" {
		tgt, haveTgt = admin.FindSSHTarget(targets, alias)
	}

	var sb strings.Builder
	sb.WriteString(base)
	for _, p := range action.Parameters {
		key := p.PolicyKey
		if key == "" {
			key = p.Name
		}
		cp := Param{Name: p.Name, Flag: "--" + p.Name, PolicyKey: key, Type: p.Type, Required: p.Required, Constraint: p.Constraint}
		if fixed, pinned := r.Constraints[key]; pinned {
			cp.Pinned = true
			cp.Fixed = fixed
			fmt.Fprintf(&sb, " --%s %s", p.Name, fixed)
		} else {
			if p.Required {
				fmt.Fprintf(&sb, " --%s <%s>", p.Name, p.Name)
			} else {
				fmt.Fprintf(&sb, " [--%s <%s>]", p.Name, p.Name)
			}
			cp.Hint, cp.AllowedValues = paramHint(r.App, p, haveTgt, tgt, targets)
		}
		c.Params = append(c.Params, cp)
	}
	c.Command = sb.String()
	return c
}

// paramHint suggests valid values for a FREE parameter, sourced from the ssh
// target's allow-lists (or the configured target list). It returns both a
// human hint and, when the values form a clean set, the concrete list (for MCP
// enum generation). Path scopes are returned as a hint only.
func paramHint(app string, p appdef.Parameter, haveTgt bool, tgt admin.SSHTarget, targets admin.SSHTargets) (hint string, values []string) {
	key := p.PolicyKey
	if key == "" {
		key = p.Name
	}
	switch {
	case app == "ssh" && key == "target":
		var aliases []string
		for _, t := range targets.Targets {
			aliases = append(aliases, t.Alias)
		}
		if len(aliases) > 0 {
			return "one of: " + strings.Join(aliases, ", "), aliases
		}
	case app == "ssh" && (p.Constraint == "service" || key == "service"):
		if haveTgt && len(tgt.AllowedServices) > 0 {
			return "allowed services: " + strings.Join(tgt.AllowedServices, ", "), append([]string{}, tgt.AllowedServices...)
		}
		return "must be one of the target's allowed_services", nil
	case app == "ssh" && (p.Constraint == "path" || key == "path"):
		if haveTgt {
			scopes := append([]string{}, tgt.AllowedPaths...)
			for _, pre := range tgt.AllowedPathPrefixes {
				scopes = append(scopes, pre+"/*")
			}
			if len(scopes) > 0 {
				return "under: " + strings.Join(scopes, ", "), nil
			}
		}
		return "must satisfy the target's allowed_paths/allowed_path_prefixes", nil
	}
	return "", nil
}

// LoadAllDefinitions assembles the app definitions the daemon would honor:
// bundled → apps.d → root applied registry, with command-template apps.d verbs
// dropped under SystemMode so the surface matches what the daemon executes.
func LoadAllDefinitions(paths config.Paths) (map[string]appdef.Definition, error) {
	bundled, err := LoadBundledDefinitions()
	if err != nil {
		return nil, err
	}
	return appdef.AssembleDefinitions(bundled, paths.AppsDir, paths.AppDefinitionsFile, config.SystemMode())
}

// LoadBundledDefinitions parses the app definitions embedded in the binary.
func LoadBundledDefinitions() ([]appdef.Definition, error) {
	entries, err := resources.FS.ReadDir("bundled/apps")
	if err != nil {
		return nil, fmt.Errorf("read bundled app definitions: %w", err)
	}
	defs := make([]appdef.Definition, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := "bundled/apps/" + entry.Name()
		data, err := resources.FS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read bundled app definition %s: %w", path, err)
		}
		def, err := appdef.Parse(data, path)
		if err != nil {
			return nil, err
		}
		def.Bundled = true
		def.ManifestPath = path
		defs = append(defs, def)
	}
	return defs, nil
}
