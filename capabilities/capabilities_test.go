// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package capabilities

import (
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/policy"
)

func testDefs() map[string]appdef.Definition {
	return map[string]appdef.Definition{
		"ssh": {
			Version: 1,
			App:     appdef.App{Name: "ssh", Executor: "ssh", SecurityMode: "protected"},
			Actions: map[string]appdef.Action{
				"read_file": {
					Description: "Read an approved file from a target",
					Parameters: []appdef.Parameter{
						{Name: "target", Type: "string", Required: true, PolicyKey: "target"},
						{Name: "path", Type: "string", Required: true, PolicyKey: "path", Constraint: "path"},
					},
					Script: "read_file",
				},
				"tail_logs": {
					Description: "Tail logs",
					Parameters: []appdef.Parameter{
						{Name: "target", Type: "string", Required: true, PolicyKey: "target"},
						{Name: "service", Type: "string", Required: true, PolicyKey: "service", Constraint: "service"},
						{Name: "lines", Type: "integer", Required: false},
					},
					Script: "tail_logs",
				},
			},
		},
	}
}

func testTargets() admin.SSHTargets {
	return admin.SSHTargets{Targets: []admin.SSHTarget{{
		Alias: "prod", Host: "h", User: "root",
		AllowedServices:     []string{"nginx"},
		AllowedPaths:        []string{"/etc/nginx/nginx.conf"},
		AllowedPathPrefixes: []string{"/var/log/nginx"},
	}}}
}

func TestBuildCapabilityRendersCommandAndHints(t *testing.T) {
	defs := testDefs()
	targets := testTargets()

	// read_file: target is pinned by the rule; path is free with a prefix hint.
	rf := buildCapability("ag", policy.Rule{Effect: "allow", Agent: "ag", App: "ssh", Action: "read_file",
		Constraints: map[string]string{"target": "prod"}}, defs, targets)
	if want := "openscope ssh read_file --agent ag --target prod --path <path>"; rf.Command != want {
		t.Fatalf("read_file command = %q, want %q", rf.Command, want)
	}
	var pathHint, targetFixed string
	for _, p := range rf.Params {
		switch p.Flag {
		case "--path":
			pathHint = p.Hint
		case "--target":
			targetFixed = p.Fixed
		}
	}
	if targetFixed != "prod" {
		t.Fatalf("--target should be pinned to prod, got %q", targetFixed)
	}
	if !strings.Contains(pathHint, "/etc/nginx/nginx.conf") || !strings.Contains(pathHint, "/var/log/nginx/*") {
		t.Fatalf("path hint missing allowed paths: %q", pathHint)
	}

	// tail_logs: service free (hint = allowed services), optional lines in brackets.
	tl := buildCapability("ag", policy.Rule{Effect: "allow", Agent: "ag", App: "ssh", Action: "tail_logs",
		Constraints: map[string]string{"target": "prod"}}, defs, targets)
	if want := "openscope ssh tail_logs --agent ag --target prod --service <service> [--lines <lines>]"; tl.Command != want {
		t.Fatalf("tail_logs command = %q, want %q", tl.Command, want)
	}

	// An allow rule for an action that no longer exists is rendered inert, not dropped.
	bad := buildCapability("ag", policy.Rule{Effect: "allow", Agent: "ag", App: "ssh", Action: "nope"}, defs, targets)
	if bad.Note == "" {
		t.Fatalf("expected an inert note for an unknown action, got none")
	}
}

// TestBuildFiltersByAgentAndExposesEnumValues checks the per-agent filtering,
// the allow/deny split, and the concrete enum values used by the MCP projection.
func TestBuildFiltersByAgentAndExposesEnumValues(t *testing.T) {
	defs := testDefs()
	targets := testTargets()
	pf := policy.File{Rules: []policy.Rule{
		{Effect: "allow", Agent: "ag", App: "ssh", Action: "tail_logs", Constraints: map[string]string{"target": "prod"}},
		{Effect: "deny", Agent: "ag", App: "ssh", Action: "read_file"},
		{Effect: "allow", Agent: "other", App: "ssh", Action: "tail_logs"}, // different agent, must be excluded
	}}

	res := Build("ag", defs, pf, targets)
	if len(res.Capabilities) != 1 {
		t.Fatalf("want 1 capability for ag, got %d", len(res.Capabilities))
	}
	if len(res.Denied) != 1 || res.Denied[0].Action != "read_file" {
		t.Fatalf("want 1 deny (read_file), got %+v", res.Denied)
	}

	var service Param
	for _, p := range res.Capabilities[0].Params {
		if p.Name == "service" {
			service = p
		}
	}
	if len(service.AllowedValues) != 1 || service.AllowedValues[0] != "nginx" {
		t.Fatalf("service AllowedValues = %v, want [nginx]", service.AllowedValues)
	}
}
