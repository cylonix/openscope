// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/ipc"
)

func ListenAndServe(paths config.Paths, service Service) error {
	// Ensure the socket's directory exists — for a root daemon this is a system
	// path (e.g. /var/run/openscope) that may not exist yet on a fresh boot.
	if err := os.MkdirAll(filepath.Dir(paths.SocketPath), 0o755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	if err := os.Remove(paths.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", paths.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on socket: %w", err)
	}
	defer listener.Close()

	if err := os.Chmod(paths.SocketPath, socketMode(os.Geteuid())); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept connection: %w", err)
		}
		go handleConn(conn, service)
	}
}

// socketMode returns the permission bits for the CLI socket. A root daemon (the
// privileged-helper model) must let the non-root agent connect, so the socket
// is world-connectable; confinement is policy enforced per request, not socket
// ownership, and the daemon never returns a credential. A non-root daemon
// already shares the agent's uid, so 0600 suffices. (A multi-user host that
// wants to restrict which local users can reach a root daemon would narrow this
// to a group — a deployment-specific hardening.)
func socketMode(euid int) os.FileMode {
	if euid == 0 {
		return 0o666
	}
	return 0o600
}

func handleConn(conn net.Conn, service Service) {
	defer conn.Close()

	var request ipc.Request
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(ipc.Response{
			OK:       false,
			Error:    fmt.Sprintf("decode request: %v", err),
			ExitCode: ExitInvalid,
		})
		return
	}

	_ = json.NewEncoder(conn).Encode(service.Handle(request))
}
