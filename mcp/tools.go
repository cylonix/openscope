// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/openscope/openscope/capabilities"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/ipc"
)

// toolSpec records how an MCP tool maps back to a broker action: the app/action
// to invoke and the params the policy pins (injected server-side so the agent
// cannot override them).
type toolSpec struct {
	app    string
	action string
	fixed  map[string]string
}

// Projection is the generated tool list plus the registry used to service
// calls. It is exported so both the local CapabilityProvider and the cross-org
// reflect-client generate identical tool surfaces from the same code.
type Projection struct {
	Tools []Tool
	specs map[string]toolSpec
}

// Resolve maps an MCP tool call onto a broker action: the (app, action) and the
// params with policy-pinned values injected (they win over agent input). ok is
// false for an unknown tool. Shared by every front end so the mapping never
// drifts.
func (p Projection) Resolve(name string, args map[string]json.RawMessage) (app, action string, params map[string]string, ok bool) {
	spec, found := p.specs[name]
	if !found {
		return "", "", nil, false
	}
	params = make(map[string]string, len(args)+len(spec.fixed))
	for k, raw := range args {
		params[k] = coerce(raw)
	}
	maps.Copy(params, spec.fixed) // policy-pinned params win over agent input
	return spec.app, spec.action, params, true
}

// sanitize maps a name to the MCP tool-name charset ([A-Za-z0-9_-]).
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func toolName(app, action string) string { return sanitize(app) + "_" + sanitize(action) }

func jsonType(t string) string {
	if t == "integer" {
		return "integer"
	}
	return "string"
}

// Project turns an agent's capability surface into MCP tools, aggregating the
// allow rules for each (app, action) into one tool: a param pinned to a single
// value across every rule is injected and omitted from the schema; values that
// vary (or come from target allow-lists) become an enum; free params become
// typed properties with a hint. The broker re-checks policy per call, so a
// loose enum can never grant more than the policy allows. Exported so the local
// CapabilityProvider and the cross-org reflect-client share one code path.
func Project(res capabilities.Result) Projection {
	type group struct {
		app, action string
		desc        string
		order       []string
		meta        map[string]capabilities.Param
		anyFree     map[string]bool
		fixed       map[string]map[string]bool
		allowed     map[string]map[string]bool
	}
	groups := map[string]*group{}
	var keysOrder []string
	for _, c := range res.Capabilities {
		if c.Note != "" {
			continue // inert allow rule (no such app/action) — nothing callable
		}
		key := c.App + "\x00" + c.Action
		g := groups[key]
		if g == nil {
			g = &group{
				app: c.App, action: c.Action, desc: c.Description,
				meta:    map[string]capabilities.Param{},
				anyFree: map[string]bool{},
				fixed:   map[string]map[string]bool{},
				allowed: map[string]map[string]bool{},
			}
			groups[key] = g
			keysOrder = append(keysOrder, key)
		}
		for _, p := range c.Params {
			if _, seen := g.meta[p.Name]; !seen {
				g.meta[p.Name] = p
				g.order = append(g.order, p.Name)
			}
			if p.Pinned {
				if g.fixed[p.Name] == nil {
					g.fixed[p.Name] = map[string]bool{}
				}
				g.fixed[p.Name][p.Fixed] = true
			} else {
				g.anyFree[p.Name] = true
				for _, v := range p.AllowedValues {
					if g.allowed[p.Name] == nil {
						g.allowed[p.Name] = map[string]bool{}
					}
					g.allowed[p.Name][v] = true
				}
			}
		}
	}

	proj := Projection{specs: map[string]toolSpec{}}
	for _, key := range keysOrder {
		g := groups[key]
		spec := toolSpec{app: g.app, action: g.action, fixed: map[string]string{}}
		properties := map[string]any{}
		var required []string
		for _, name := range g.order {
			pm := g.meta[name]
			fixedVals := setKeys(g.fixed[name])
			if !g.anyFree[name] && len(fixedVals) == 1 {
				spec.fixed[name] = fixedVals[0] // pinned everywhere → inject, omit from schema
				continue
			}
			prop := map[string]any{"type": jsonType(pm.Type)}
			enum := union(fixedVals, setKeys(g.allowed[name]))
			if len(enum) > 0 {
				prop["enum"] = enum
			} else if pm.Hint != "" {
				prop["description"] = pm.Hint
			}
			properties[name] = prop
			if pm.Required {
				required = append(required, name)
			}
		}
		schema := map[string]any{"type": "object", "properties": properties}
		if len(required) > 0 {
			schema["required"] = required
		}
		proj.Tools = append(proj.Tools, Tool{
			Name:        toolName(g.app, g.action),
			Description: describe(g.desc),
			InputSchema: schema,
		})
		proj.specs[toolName(g.app, g.action)] = spec
	}
	sort.Slice(proj.Tools, func(i, j int) bool { return proj.Tools[i].Name < proj.Tools[j].Name })
	return proj
}

func describe(desc string) string {
	const note = "The broker re-checks policy per call and may deny a specific argument combination."
	if desc = strings.TrimSpace(desc); desc != "" {
		return desc + " " + note
	}
	return note
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// coerce renders a JSON argument value as the string the broker IPC expects.
func coerce(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return strings.Trim(string(raw), `"`)
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == math.Trunc(t) && !math.IsInf(t, 0) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

// CapabilityProvider serves the agent's policy-filtered capability surface as
// MCP tools and forwards calls to the daemon via ipc.Call. It is an unprivileged
// reflection of the broker's authority; all enforcement stays in the daemon.
type CapabilityProvider struct {
	paths   config.Paths
	agentID string
	call    func(config.Paths, ipc.Request) (ipc.Response, error)

	mu   sync.RWMutex
	proj Projection
}

// NewCapabilityProvider builds a provider for agentID using the given paths.
func NewCapabilityProvider(paths config.Paths, agentID string) *CapabilityProvider {
	return &CapabilityProvider{paths: paths, agentID: agentID, call: ipc.Call}
}

// Refresh recomputes the tool surface from current policy/app definitions.
func (p *CapabilityProvider) Refresh() error {
	res, err := capabilities.BuildFromPaths(p.paths, p.agentID)
	if err != nil {
		return err
	}
	proj := Project(res)
	p.mu.Lock()
	p.proj = proj
	p.mu.Unlock()
	return nil
}

// Tools returns the current tool list (never nil, so tools/list emits []).
func (p *CapabilityProvider) Tools() []Tool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.proj.Tools == nil {
		return []Tool{}
	}
	return p.proj.Tools
}

// Signature is a stable hash of the current tool set, used by the watcher to
// decide whether to emit tools/list_changed.
func (p *CapabilityProvider) Signature() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	b, _ := json.Marshal(p.proj.Tools)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Call maps an MCP tool call onto a broker action and forwards it.
func (p *CapabilityProvider) Call(name string, args map[string]json.RawMessage) ToolResult {
	p.mu.RLock()
	spec, ok := p.proj.specs[name]
	p.mu.RUnlock()
	if !ok {
		return TextResult("unknown tool: "+name, true)
	}

	params := make(map[string]string, len(args)+len(spec.fixed))
	for k, raw := range args {
		params[k] = coerce(raw)
	}
	maps.Copy(params, spec.fixed) // policy-pinned params win over agent input

	resp, err := p.call(p.paths, ipc.Request{
		App: spec.app, Action: spec.action, Agent: p.agentID, Params: params, Mode: "json",
	})
	if err != nil {
		return TextResult("openscope call failed: "+err.Error(), true)
	}
	if resp.OK {
		return TextResult(formatData(resp.Data), false)
	}
	msg := resp.Error
	if msg == "" {
		msg = "request denied"
	}
	return TextResult(fmt.Sprintf("%s (exit %d)", msg, resp.ExitCode), true)
}

func formatData(data any) string {
	if data == nil {
		return "ok"
	}
	if s, ok := data.(string); ok {
		return s
	}
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("%v", data)
	}
	return string(b)
}
