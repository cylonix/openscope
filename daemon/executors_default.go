// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package daemon

import (
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
	"github.com/openscope/openscope/executor/httpexec"
	"github.com/openscope/openscope/executor/sshexec"
	"github.com/openscope/openscope/executor/ssmexec"
	"github.com/openscope/openscope/executor/systemexec"
)

// defaultExecutors on non-darwin platforms (the VPC broker) excludes
// applescript: there is no Apple automation off macOS. Requests for
// applescript apps fail with a clear "not available on this platform"
// executor error.
func defaultExecutors(paths config.Paths) map[string]executor.Runner {
	return map[string]executor.Runner{
		"http":   httpexec.Executor{Paths: paths},
		"ssh":    sshexec.Executor{Paths: paths},
		"ssm":    ssmexec.Executor{Paths: paths},
		"system": systemexec.Executor{Paths: paths},
	}
}
