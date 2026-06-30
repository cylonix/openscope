// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command openscope-mcp is an unprivileged MCP front-end for the OpenScope
// broker. It exposes the agent's policy-filtered capability surface as MCP
// tools over stdio and forwards tool calls to openscoped via the same ipc.Call
// the CLI uses. It holds no keys and no policy authority; all custody, policy
// evaluation, and audit stay in the daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/openscope/openscope/buildinfo"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/mcp"
)

// instructions travel with the server (surfaced by the MCP client) so the
// behavioral contract lives with the registration instead of a per-host doc.
const instructions = "Use these tools for privileged actions: SSH to governed hosts, sudo/system " +
	"changes, and brokered apps. A result whose text ends with \"(exit 3)\" is denied by policy " +
	"and is final — report it to the user and stop. Do not retry under a different identity and do " +
	"not fall back to running the raw command yourself. The tools shown reflect what this agent is " +
	"currently allowed to do and update automatically; new verbs are granted by a human applying a " +
	"YAML proposal with `sudo openscope apply`."

func main() { os.Exit(run()) }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func run() int {
	var agentFlag string
	var showVersion bool
	flag.StringVar(&agentFlag, "agent", "", "agent identity this server acts as")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(buildinfo.Version)
		return 0
	}

	// Resolve the agent identity the same way the guard hook does: an explicit
	// flag wins, then OPENSCOPE_AGENT_ID (the documented override), then the
	// legacy OPENSCOPE_AGENT, defaulting to claude-code.
	agentID := firstNonEmpty(agentFlag, os.Getenv("OPENSCOPE_AGENT_ID"), os.Getenv("OPENSCOPE_AGENT"), "claude-code")

	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "openscope-mcp: resolve paths: %v\n", err)
		return 6
	}

	provider := mcp.NewCapabilityProvider(paths, agentID)
	if err := provider.Refresh(); err != nil {
		// Serve an empty surface rather than refuse to start: the client can
		// still connect, and the watcher will pick the surface up once the
		// config loads cleanly.
		fmt.Fprintf(os.Stderr, "openscope-mcp: initial capability load: %v\n", err)
	}

	server := &mcp.Server{
		Conn:         mcp.NewConn(os.Stdin, os.Stdout),
		Provider:     provider,
		Name:         "openscope",
		Version:      buildinfo.Version,
		Instructions: instructions,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher := mcp.NewCapabilityWatcher(
		mcp.CapabilityFiles(paths),
		provider.Refresh,
		provider.Signature,
		server.NotifyToolsChanged,
	)
	go watcher.Run(ctx, 2*time.Second)

	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "openscope-mcp: %v\n", err)
		return 5
	}
	return 0
}
