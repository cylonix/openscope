// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"

	"github.com/agentscope/ascope/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
