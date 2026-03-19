// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package executor

import "github.com/agentscope/ascope/appdef"

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type Runner interface {
	Run(def appdef.Definition, actionName string, params map[string]string) (Result, error)
}
