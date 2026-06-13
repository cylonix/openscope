// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package daemon

import (
	"testing"

	appleexec "github.com/openscope/openscope/executor/applescript"
)

func TestChooseAppleExecutor(t *testing.T) {
	// Root daemon with a session socket configured → forward to the session agent.
	root := chooseAppleExecutor(0, "/var/run/openscope/session.sock")
	if e, ok := root.(appleexec.Executor); !ok || e.Helper == nil {
		t.Fatalf("root + session socket should forward, got %#v", root)
	}

	// Non-root daemon (legacy per-user LaunchAgent) → run asapple locally.
	user := chooseAppleExecutor(501, "/var/run/openscope/session.sock")
	if e, ok := user.(appleexec.Executor); !ok || e.Helper != nil {
		t.Fatalf("non-root should run locally, got %#v", user)
	}

	// Root but no session socket configured → local (misconfig; no TCC, but we
	// don't silently forward to nowhere).
	rootNoSock := chooseAppleExecutor(0, "")
	if e, ok := rootNoSock.(appleexec.Executor); !ok || e.Helper != nil {
		t.Fatalf("root without a session socket should run locally, got %#v", rootNoSock)
	}
}
