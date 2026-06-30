// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"testing"

	"github.com/openscope/openscope/capabilities"
)

func TestParseVerbSpec(t *testing.T) {
	app, action, pins, err := parseVerbSpec("ssh.tail_logs:target=prod-api-1,service=web")
	if err != nil {
		t.Fatal(err)
	}
	if app != "ssh" || action != "tail_logs" {
		t.Fatalf("app/action = %q/%q", app, action)
	}
	if pins["target"] != "prod-api-1" || pins["service"] != "web" {
		t.Fatalf("pins = %+v", pins)
	}

	if _, _, _, err := parseVerbSpec("nodothere"); err == nil {
		t.Fatal("expected error for missing app.action dot")
	}
	if _, _, _, err := parseVerbSpec("ssh.tail:badpin"); err == nil {
		t.Fatal("expected error for malformed pin")
	}
}

func TestDeriveCapability(t *testing.T) {
	surface := []capabilities.Capability{{
		App: "ssh", Action: "tail_logs",
		Params: []capabilities.Param{
			{Name: "target", PolicyKey: "target"},
			{Name: "service", PolicyKey: "service"},
		},
	}}

	c, err := deriveCapability(surface, "ssh", "tail_logs", map[string]string{"service": "web"})
	if err != nil {
		t.Fatal(err)
	}
	var svc, tgt capabilities.Param
	for _, p := range c.Params {
		switch p.Name {
		case "service":
			svc = p
		case "target":
			tgt = p
		}
	}
	if !svc.Pinned || svc.Fixed != "web" {
		t.Fatalf("service should be pinned to web, got %+v", svc)
	}
	if tgt.Pinned {
		t.Fatalf("unmentioned target should stay free, got %+v", tgt)
	}

	if _, err := deriveCapability(surface, "system", "manage_packages", nil); err == nil {
		t.Fatal("expected error for a verb not in the surface")
	}
	if _, err := deriveCapability(surface, "ssh", "tail_logs", map[string]string{"nope": "x"}); err == nil {
		t.Fatal("expected error for an unknown parameter")
	}
}
