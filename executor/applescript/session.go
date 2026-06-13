// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package applescript

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/executor"
)

// The session handoff (phase 4): a root LaunchDaemon cannot hold the per-user
// Notes/Mail Automation (TCC) grant, so it delegates Apple-event execution to a
// user-session agent (`openscoped --session-helper`) that does. The root daemon
// has already evaluated policy + written audit; the agent just executes.
//
// The agent is the same `openscoped` binary, so it re-materializes the embedded
// (bundled) or user-owned (apps.d) script itself — no root-owned temp file has
// to cross the uid boundary. Only {def, action, params} travel on the wire.

type sessionRequest struct {
	Def    appdef.Definition `json:"def"`
	Action string            `json:"action"`
	Params map[string]string `json:"params"`
}

type sessionResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// Forwarder is the root daemon's applescript Helper: it hands the action to the
// user-session agent instead of running asapple itself.
type Forwarder struct {
	SocketPath string
	dial       func() (net.Conn, error) // overridable in tests
}

func NewForwarder(socketPath string) *Forwarder { return &Forwarder{SocketPath: socketPath} }

func (f *Forwarder) run(def appdef.Definition, actionName string, params map[string]string) (executor.Result, error) {
	dial := f.dial
	if dial == nil {
		dial = func() (net.Conn, error) { return net.Dial("unix", f.SocketPath) }
	}
	conn, err := dial()
	if err != nil {
		return executor.Result{}, fmt.Errorf("reach session agent at %s: %w", f.SocketPath, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(sessionRequest{Def: def, Action: actionName, Params: params}); err != nil {
		return executor.Result{}, fmt.Errorf("send to session agent: %w", err)
	}
	var resp sessionResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return executor.Result{}, fmt.Errorf("read from session agent: %w", err)
	}
	res := executor.Result{Stdout: resp.Stdout, Stderr: resp.Stderr, ExitCode: resp.ExitCode}
	if resp.Error != "" {
		return res, fmt.Errorf("%s", resp.Error)
	}
	return res, nil
}

// Seams, overridable in tests.
var (
	sessionExec = localRun
	// sessionSocketMode is the session socket's permission. 0000 = root-only:
	// root bypasses DAC checks (it's the root broker), and the kernel denies
	// connect(2) to every other uid — including the same-uid agent, which a
	// uid/peer-cred check cannot exclude. Tests lower it so a non-root test
	// process can exercise the round-trip.
	sessionSocketMode os.FileMode = 0o000
)

// ServeSession runs the user-session agent: it listens on socketPath and runs
// each forwarded Apple-event action in this GUI session (asapple, holding TCC).
// It performs NO policy — the root daemon authorized the request — so it MUST
// accept only the root broker (uid 0). A same-uid agent connecting here would
// otherwise be an unauthenticated TCC oracle that bypasses Notes/Mail policy.
// Blocks until the listener errors.
func ServeSession(socketPath string) error {
	// The session run dir lives in the console user's home (0700, so other users
	// can't reach it; root traverses regardless). The agent runs as that user.
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("create session socket dir: %w", err)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale session socket: %w", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on session socket: %w", err)
	}
	defer ln.Close()
	// Root-only by file permission: mode 0000 lets no uid connect except root,
	// which bypasses DAC checks — exactly the root broker. This blocks a same-uid
	// agent (which a peer-uid check would need a syscall + dependency to exclude)
	// with no peer-credential code at all. Listening is unaffected — the agent
	// already holds the bound fd.
	if err := os.Chmod(socketPath, sessionSocketMode); err != nil {
		return fmt.Errorf("restrict session socket: %w", err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept session connection: %w", err)
		}
		go serveSessionConn(conn)
	}
}

func serveSessionConn(conn net.Conn) {
	defer conn.Close()

	// The socket's mode (root-only) is the access gate — only the root broker
	// can have connected — so no per-request caller check is needed here.
	var req sessionRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(sessionResponse{Error: fmt.Sprintf("decode session request: %v", err)})
		return
	}

	res, err := sessionExec(req.Def, req.Action, req.Params)
	resp := sessionResponse{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode}
	if err != nil {
		resp.Error = err.Error()
	}
	_ = json.NewEncoder(conn).Encode(resp)
}
