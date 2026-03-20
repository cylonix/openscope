// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package status

import (
	"net"
	"os"
	"time"

	"github.com/openscope/openscope/config"
)

type Report struct {
	Daemon    DaemonStatus `json:"daemon"`
	ConfigDir string       `json:"config_dir"`
	Socket    string       `json:"socket"`
}

type DaemonStatus struct {
	Running     bool   `json:"running"`
	SocketExists bool  `json:"socket_exists"`
	Error       string `json:"error,omitempty"`
}

func Snapshot(paths config.Paths) Report {
	return Report{
		Daemon:    checkDaemon(paths.SocketPath),
		ConfigDir: paths.ConfigDir,
		Socket:    paths.SocketPath,
	}
}

func checkDaemon(socketPath string) DaemonStatus {
	if _, err := os.Stat(socketPath); err != nil {
		return DaemonStatus{Running: false, SocketExists: false}
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return DaemonStatus{
			SocketExists: true,
			Running:      false,
			Error:        "socket exists but daemon is not responding",
		}
	}
	conn.Close()

	return DaemonStatus{Running: true, SocketExists: true}
}
