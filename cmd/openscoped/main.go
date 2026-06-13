// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"

	"path/filepath"

	"github.com/openscope/openscope/buildinfo"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/cpclient"
	"github.com/openscope/openscope/daemon"
	appleexec "github.com/openscope/openscope/executor/applescript"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("openscoped " + buildinfo.String())
		return
	}

	// Log the build identity to the daemon log on startup — this is the line
	// that tells you which build launchd is actually running (vs. what's on
	// disk), without resorting to md5'ing the binary.
	fmt.Fprintf(os.Stderr, "openscoped %s starting\n", buildinfo.String())

	// Session-helper mode (phase 4, macOS): the user-session LaunchAgent that
	// holds the Notes/Mail TCC grant and runs asapple for the root daemon. It
	// serves only the applescript handoff on a root-only socket — no policy, no
	// CLI socket, no other executors.
	if len(os.Args) > 1 && os.Args[1] == "--session-helper" {
		sock := os.Getenv("OPENSCOPE_SESSION_SOCKET")
		if sock == "" {
			_, _ = fmt.Fprintln(os.Stderr, "--session-helper requires OPENSCOPE_SESSION_SOCKET")
			os.Exit(daemon.ExitConfigError)
		}
		if err := appleexec.ServeSession(sock); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "session helper error: %v\n", err)
			os.Exit(daemon.ExitExecutorError)
		}
		return
	}

	paths, err := config.DefaultPaths()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(daemon.ExitConfigError)
	}
	if err := config.EnsureLayout(paths); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(daemon.ExitConfigError)
	}

	service := daemon.NewService(paths)

	// Control plane (strictly optional): enabled by OPENSCOPE_CONTROL_PLANE_URL
	// or a prior `openscope enroll`. Metering only — an unreachable control
	// plane never blocks broker traffic.
	cpCfg := cpclient.ResolveConfig(
		filepath.Join(paths.ConfigDir, "controlplane.yaml"),
		filepath.Join(paths.StateDir, "cp_spool.jsonl"),
	)
	if cp := cpclient.New(cpCfg); cp != nil {
		defer cp.Close()
		service.Usage = cp.Record
		fmt.Fprintf(os.Stderr, "control plane enabled: %s\n", cpCfg.BaseURL)
	}

	// Fail fast on unsafe network configuration (plaintext on non-loopback,
	// anonymous mode off-loopback) before binding anything.
	if err := daemon.ValidateHTTPConfig(paths); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(daemon.ExitConfigError)
	}

	errCh := make(chan error, 2)

	go func() {
		errCh <- daemon.ListenAndServe(paths, service)
	}()

	if paths.HTTPListenAddr != "" {
		go func() {
			errCh <- daemon.ListenAndServeHTTP(paths, service)
		}()
	}

	err = <-errCh
	_, _ = fmt.Fprintf(os.Stderr, "daemon error: %v\n", err)
	os.Exit(daemon.ExitExecutorError)
}
