// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"

	"github.com/agentscope/ascope/config"
	"github.com/agentscope/ascope/daemon"
)

func main() {
	paths, err := config.DefaultPaths()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(daemon.ExitConfigError)
	}
	if err := config.EnsureLayout(paths); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(daemon.ExitConfigError)
	}

	if err := daemon.ListenAndServe(paths, daemon.NewService(paths)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "daemon error: %v\n", err)
		os.Exit(daemon.ExitExecutorError)
	}
}
