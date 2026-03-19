// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package agent

import (
	"path/filepath"
	"testing"

	"github.com/agentscope/ascope/config"
)

func TestRegister(t *testing.T) {
	tmp := t.TempDir()
	paths := config.Paths{
		AgentsFile: filepath.Join(tmp, "agents.yaml"),
	}

	registry, created, err := Register(paths, "demo")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if !created {
		t.Fatalf("expected first registration to create agent")
	}
	if len(registry.Agents) != 1 || registry.Agents[0] != "demo" {
		t.Fatalf("unexpected registry: %#v", registry)
	}

	_, created, err = Register(paths, "demo")
	if err != nil {
		t.Fatalf("Register second time returned error: %v", err)
	}
	if created {
		t.Fatalf("expected duplicate registration to be idempotent")
	}
}
