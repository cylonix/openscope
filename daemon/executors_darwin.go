// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package daemon

import (
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
	appleexec "github.com/openscope/openscope/executor/applescript"
	"github.com/openscope/openscope/executor/httpexec"
	"github.com/openscope/openscope/executor/sshexec"
	"github.com/openscope/openscope/executor/systemexec"
)

// defaultExecutors on macOS includes applescript — the local daemon brokers
// Apple-app automation through the signed asapple helper.
func defaultExecutors(paths config.Paths) map[string]executor.Runner {
	return map[string]executor.Runner{
		"applescript": appleexec.Executor{},
		"http":        httpexec.Executor{Paths: paths},
		"ssh":         sshexec.Executor{Paths: paths},
		"system":      systemexec.Executor{Paths: paths},
	}
}
