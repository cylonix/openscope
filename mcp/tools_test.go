// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openscope/openscope/capabilities"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/ipc"
)

func findTool(tools []Tool, name string) (Tool, bool) {
	for _, t := range tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

func props(t *testing.T, tool Tool) map[string]any {
	t.Helper()
	p, ok := tool.InputSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("tool %q has no properties object", tool.Name)
	}
	return p
}

func TestProjectInjectsSingleFixedAndKeepsFreeParam(t *testing.T) {
	res := capabilities.Result{Agent: "ag", Capabilities: []capabilities.Capability{{
		App: "ssh", Action: "read_file", Description: "Read a file",
		Params: []capabilities.Param{
			{Name: "target", Type: "string", Required: true, Pinned: true, Fixed: "prod"},
			{Name: "path", Type: "string", Required: true, Constraint: "path", Hint: "under: /var/log/*"},
		},
	}}}

	proj := Project(res)
	tool, ok := findTool(proj.Tools, "ssh_read_file")
	if !ok {
		t.Fatalf("ssh_read_file not projected: %+v", proj.Tools)
	}
	p := props(t, tool)
	if _, present := p["target"]; present {
		t.Fatalf("pinned single-value target should be injected, not in schema: %v", p)
	}
	if spec := proj.specs["ssh_read_file"]; spec.fixed["target"] != "prod" {
		t.Fatalf("target should be injected as fixed=prod, got %+v", spec.fixed)
	}
	pathProp, _ := p["path"].(map[string]any)
	if pathProp["description"] != "under: /var/log/*" {
		t.Fatalf("path hint not carried into description: %v", pathProp)
	}
	req, _ := tool.InputSchema["required"].([]string)
	if len(req) != 1 || req[0] != "path" {
		t.Fatalf("required should be [path], got %v", tool.InputSchema["required"])
	}
}

func TestProjectAggregatesEnumAcrossRules(t *testing.T) {
	res := capabilities.Result{Agent: "ag", Capabilities: []capabilities.Capability{
		{App: "ssh", Action: "tail_logs", Description: "Tail logs", Params: []capabilities.Param{
			{Name: "target", Type: "string", Required: true, Pinned: true, Fixed: "prod"},
			{Name: "service", Type: "string", Required: true, AllowedValues: []string{"nginx"}},
			{Name: "lines", Type: "integer"},
		}},
		{App: "ssh", Action: "tail_logs", Description: "Tail logs", Params: []capabilities.Param{
			{Name: "target", Type: "string", Required: true, Pinned: true, Fixed: "web"},
			{Name: "service", Type: "string", Required: true, AllowedValues: []string{"api"}},
			{Name: "lines", Type: "integer"},
		}},
	}}

	proj := Project(res)
	tool, ok := findTool(proj.Tools, "ssh_tail_logs")
	if !ok {
		t.Fatalf("ssh_tail_logs not projected")
	}
	p := props(t, tool)
	targetEnum, _ := p["target"].(map[string]any)["enum"].([]string)
	if strings.Join(targetEnum, ",") != "prod,web" {
		t.Fatalf("target enum = %v, want [prod web]", targetEnum)
	}
	serviceEnum, _ := p["service"].(map[string]any)["enum"].([]string)
	if strings.Join(serviceEnum, ",") != "api,nginx" {
		t.Fatalf("service enum union = %v, want [api nginx]", serviceEnum)
	}
	if p["lines"].(map[string]any)["type"] != "integer" {
		t.Fatalf("lines should be integer typed: %v", p["lines"])
	}
}

func TestCallInjectsFixedAndMapsResults(t *testing.T) {
	res := capabilities.Result{Agent: "ag", Capabilities: []capabilities.Capability{{
		App: "ssh", Action: "tail_logs", Description: "Tail logs",
		Params: []capabilities.Param{
			{Name: "target", Type: "string", Required: true, Pinned: true, Fixed: "prod"},
			{Name: "service", Type: "string", Required: true, AllowedValues: []string{"api"}},
			{Name: "lines", Type: "integer"},
		},
	}}}

	var captured ipc.Request
	p := &CapabilityProvider{paths: config.Paths{}, agentID: "ag"}
	p.proj = Project(res)
	p.call = func(_ config.Paths, req ipc.Request) (ipc.Response, error) {
		captured = req
		return ipc.Response{OK: true, Data: map[string]any{"lines": []string{"a", "b"}}}, nil
	}

	args := map[string]json.RawMessage{
		"target":  json.RawMessage(`"hacker"`), // attempt to override a pinned param
		"service": json.RawMessage(`"api"`),
		"lines":   json.RawMessage(`50`),
	}
	out := p.Call("ssh_tail_logs", args)
	if out.IsError {
		t.Fatalf("expected success, got error: %+v", out)
	}
	if captured.App != "ssh" || captured.Action != "tail_logs" || captured.Agent != "ag" {
		t.Fatalf("bad request routing: %+v", captured)
	}
	if captured.Params["target"] != "prod" {
		t.Fatalf("pinned target must win over agent input, got %q", captured.Params["target"])
	}
	if captured.Params["lines"] != "50" {
		t.Fatalf("integer arg should coerce to \"50\", got %q", captured.Params["lines"])
	}
	if captured.Mode != "json" {
		t.Fatalf("mode should be json, got %q", captured.Mode)
	}

	// Deny maps to an isError tool result carrying the reason and exit code.
	p.call = func(_ config.Paths, _ ipc.Request) (ipc.Response, error) {
		return ipc.Response{OK: false, Error: "path outside allowed_path_prefixes", ExitCode: 3}, nil
	}
	deny := p.Call("ssh_tail_logs", args)
	if !deny.IsError || !strings.Contains(deny.Content[0].Text, "exit 3") {
		t.Fatalf("deny should be isError with exit 3, got %+v", deny)
	}

	// Unknown tool is a tool error, not a panic.
	if u := p.Call("nope", nil); !u.IsError {
		t.Fatalf("unknown tool should be isError")
	}
}
