// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package status

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openscope/openscope/config"
)

type Report struct {
	Daemon    DaemonStatus `json:"daemon"`
	ConfigDir string       `json:"config_dir"`
	Socket    string       `json:"socket"`
	HTTPURL   string       `json:"http_url,omitempty"`
}

type DaemonStatus struct {
	Running      bool   `json:"running"`
	SocketExists bool   `json:"socket_exists"`
	Error        string `json:"error,omitempty"`
}

func Snapshot(paths config.Paths) Report {
	return Report{
		Daemon:    checkDaemon(paths),
		ConfigDir: paths.ConfigDir,
		Socket:    paths.SocketPath,
		HTTPURL:   paths.HTTPURL,
	}
}

func checkDaemon(paths config.Paths) DaemonStatus {
	if strings.TrimSpace(paths.HTTPURL) != "" {
		return checkHTTP(paths.HTTPURL)
	}
	return checkSocket(paths.SocketPath)
}

func checkSocket(socketPath string) DaemonStatus {
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

func checkHTTP(baseURL string) DaemonStatus {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + "/healthz")
	if err != nil {
		return DaemonStatus{Running: false, Error: err.Error()}
	}
	defer resp.Body.Close()

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return DaemonStatus{Running: false, Error: "invalid health response"}
	}
	if ok, _ := payload["ok"].(bool); ok {
		return DaemonStatus{Running: true}
	}
	return DaemonStatus{Running: false, Error: "broker reported unhealthy"}
}
