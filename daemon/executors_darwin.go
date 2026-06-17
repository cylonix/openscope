// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package daemon

import (
	"os"

	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
	appleexec "github.com/openscope/openscope/executor/applescript"
	"github.com/openscope/openscope/executor/httpexec"
	"github.com/openscope/openscope/executor/sshexec"
	"github.com/openscope/openscope/executor/ssmexec"
	"github.com/openscope/openscope/executor/systemexec"
)

// defaultExecutors on macOS includes applescript — the local daemon brokers
// Apple-app automation through the signed asapple helper.
func defaultExecutors(paths config.Paths) map[string]executor.Runner {
	return map[string]executor.Runner{
		"applescript": chooseAppleExecutor(os.Geteuid(), os.Getenv("OPENSCOPE_SESSION_SOCKET")),
		"http":        httpexec.Executor{Paths: paths},
		"ssh":         sshexec.Executor{Paths: paths},
		"ssm":         ssmexec.Executor{Paths: paths},
		"system":      systemexec.Executor{Paths: paths},
	}
}

// chooseAppleExecutor selects how Apple-event actions run. A root daemon (the
// phase-4 privileged-helper model) is not in the user's GUI session and cannot
// hold the Notes/Mail TCC grant, so it forwards execution to the user-session
// agent (`openscoped --session-helper`) over OPENSCOPE_SESSION_SOCKET. A
// non-root daemon (the legacy per-user LaunchAgent) runs asapple directly.
func chooseAppleExecutor(euid int, sessionSocket string) executor.Runner {
	if euid == 0 && sessionSocket != "" {
		return appleexec.Executor{Helper: appleexec.NewForwarder(sessionSocket)}
	}
	return appleexec.Executor{}
}
