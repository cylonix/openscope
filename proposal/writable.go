// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"fmt"
	"os"
	"syscall"
)

// pathAgentWritable reports whether a directory could be modified by the
// (non-root) user the agent runs as — the precondition that turns an app
// "install from this source" grant into arbitrary code execution. syscall.Stat_t
// and its Uid field exist on both darwin and linux, so no build tag is needed.
func pathAgentWritable(path string) (writable bool, reason string, known bool) {
	info, err := os.Stat(path)
	if err != nil {
		return false, "does not exist or is unreadable", false
	}
	perm := info.Mode().Perm()
	if perm&0o002 != 0 {
		return true, "world-writable", true
	}
	if perm&0o020 != 0 {
		return true, "group-writable", true
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 0 {
			return true, fmt.Sprintf("owned by uid %d (not root)", st.Uid), true
		}
	}
	return false, "", true
}
