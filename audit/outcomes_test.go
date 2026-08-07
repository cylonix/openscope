// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecentOutcomes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	base := time.Date(2026, 8, 1, 6, 0, 0, 0, time.UTC)
	events := []Event{
		{Timestamp: base, Agent: "cc", App: "ssh", Action: "deploy_web", Decision: "allow", Result: "success"},
		{Timestamp: base.Add(time.Minute), Agent: "cc", App: "ssh", Action: "deploy_web", Decision: "deny", Result: "denied"},
		{Timestamp: base.Add(2 * time.Minute), Agent: "cc", App: "ssh", Action: "deploy_web", Decision: "allow", Result: "executor_error", Reason: "KeyError ContainerConfig"},
		{Timestamp: base.Add(3 * time.Minute), Agent: "cc", App: "ssh", Action: "check_host", Decision: "allow", Result: "success"},
	}
	for _, ev := range events {
		if err := Append(path, ev); err != nil {
			t.Fatal(err)
		}
	}
	// A malformed line must be skipped, not fatal.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("{not json\n")
	f.Close()

	out, err := RecentOutcomes(path, 5)
	if err != nil {
		t.Fatal(err)
	}
	deploys := out["ssh·deploy_web"]
	if len(deploys) != 2 {
		t.Fatalf("deploy_web outcomes = %d (denied must be excluded), got %#v", len(deploys), deploys)
	}
	if deploys[0].Result != "executor_error" || !deploys[0].Failed() {
		t.Errorf("newest first: got %+v", deploys[0])
	}
	if deploys[1].Result != "success" || deploys[1].Failed() {
		t.Errorf("oldest: got %+v", deploys[1])
	}
	if len(out["ssh·check_host"]) != 1 {
		t.Errorf("check_host outcomes = %#v", out["ssh·check_host"])
	}

	if capped, _ := RecentOutcomes(path, 1); len(capped["ssh·deploy_web"]) != 1 {
		t.Error("max must cap per-key history")
	}

	if _, err := RecentOutcomes(filepath.Join(t.TempDir(), "missing.jsonl"), 5); err == nil {
		t.Error("a missing file is an error for the caller to swallow")
	}
}
