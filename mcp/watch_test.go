// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileWatcherDetectsEditsAndResets(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(f, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := newFileWatcher([]string{f})
	if w.changed() {
		t.Fatal("no change expected immediately after construction")
	}
	if err := os.WriteFile(f, []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !w.changed() {
		t.Fatal("expected change after rewrite")
	}
	if w.changed() {
		t.Fatal("change should reset after being observed")
	}
}

func TestCapabilityWatcherNotifiesOnlyOnRealChange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(f, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	sig := "A"
	notified := 0
	w := NewCapabilityWatcher([]string{f},
		func() error { return nil },
		func() string { return sig },
		func() error { notified++; return nil },
	)

	// No file change → no work.
	if w.poll() {
		t.Fatal("poll should be a no-op with no file change")
	}

	// File changed but the tool signature is unchanged → no notify.
	if err := os.WriteFile(f, []byte("v2-longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if w.poll() {
		t.Fatal("unchanged signature must not notify")
	}
	if notified != 0 {
		t.Fatalf("notified=%d, want 0", notified)
	}

	// File changed AND signature changed → exactly one notify.
	sig = "B"
	if err := os.WriteFile(f, []byte("v3-even-longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !w.poll() {
		t.Fatal("changed signature should notify")
	}
	if notified != 1 {
		t.Fatalf("notified=%d, want 1", notified)
	}
}
