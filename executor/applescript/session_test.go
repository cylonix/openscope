// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package applescript

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/executor"
)

// sessionSocketPath returns a short socket path. macOS caps AF_UNIX paths at
// ~104 bytes, and t.TempDir() (with the test name baked in) can exceed that.
func sessionSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "osc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for range 200 {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("session socket %s did not come up", path)
}

func waitForSocketFile(t *testing.T, path string) {
	t.Helper()
	for range 200 {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("session socket file %s did not appear", path)
}

// A root-broker caller's request round-trips to the session agent, which runs
// the action in-session and returns the result. {def, action, params} carry the
// request; no script path/content crosses the wire.
func TestSessionForwardRoundTrip(t *testing.T) {
	sock := sessionSocketPath(t)
	oldExec, oldMode := sessionExec, sessionSocketMode
	var gotAction, gotFolder string
	sessionExec = func(_ appdef.Definition, action string, params map[string]string) (executor.Result, error) {
		gotAction, gotFolder = action, params["folder"]
		return executor.Result{Stdout: "note body"}, nil
	}
	sessionSocketMode = 0o600 // let the non-root test process connect
	t.Cleanup(func() { sessionExec, sessionSocketMode = oldExec, oldMode })

	go func() { _ = ServeSession(sock) }()
	waitForSocket(t, sock)

	res, err := NewForwarder(sock).run(
		appdef.Definition{App: appdef.App{Name: "notes"}}, "read_note",
		map[string]string{"folder": "Work"})
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if res.Stdout != "note body" || gotAction != "read_note" || gotFolder != "Work" {
		t.Fatalf("round-trip mismatch: out=%q action=%q folder=%q", res.Stdout, gotAction, gotFolder)
	}
}

// The 0000 session socket is connectable only by root. This verifies the gate
// empirically: a non-root process (the test) is denied connect by the kernel.
func TestSessionSocketIsRootOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — root bypasses the socket mode, which is the point")
	}
	sock := sessionSocketPath(t)
	old := sessionSocketMode
	sessionSocketMode = 0o000
	t.Cleanup(func() { sessionSocketMode = old })

	go func() { _ = ServeSession(sock) }()
	waitForSocketFile(t, sock) // can't dial-probe: dialing is exactly what's denied

	_, err := net.Dial("unix", sock)
	if err == nil {
		t.Fatal("expected a non-root process to be denied connect to the 0000 session socket")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied, got %v", err)
	}
}
