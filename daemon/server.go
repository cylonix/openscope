// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/ipc"
)

func ListenAndServe(paths config.Paths, service Service) error {
	if err := os.Remove(paths.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", paths.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on socket: %w", err)
	}
	defer listener.Close()

	if err := os.Chmod(paths.SocketPath, 0o600); err != nil {
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
