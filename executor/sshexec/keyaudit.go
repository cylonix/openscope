// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/openscope/openscope/admin"
)

type KeyWarning struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// AuditKeyProtection checks whether the SSH identity file for a target is
// adequately protected from unprivileged processes. It warns when the key
// resides in the user's ~/.ssh/ directory (readable by any process running
// as that user, including unsandboxed AI agents), when file permissions are
// too open, or when the file is not owned by root.
func AuditKeyProtection(target admin.SSHTarget, homeDir string) []KeyWarning {
	var warnings []KeyWarning

	if target.IdentityFile == "" {
		warnings = append(warnings, KeyWarning{
			Level: "warning",
			Message: fmt.Sprintf(
				"target %q has no identity_file configured; "+
					"ssh will default to keys in ~/.ssh/ which are readable by all user processes",
				target.Alias),
		})
		return warnings
	}

	resolved := target.IdentityFile
	if homeDir != "" && strings.HasPrefix(resolved, "~/") {
		resolved = filepath.Join(homeDir, resolved[2:])
	}

	// Follow symlinks so a link from a protected dir into ~/.ssh/ is caught.
	if evaled, err := filepath.EvalSymlinks(resolved); err == nil {
		resolved = evaled
	}

	resolvedHome := homeDir
	if resolvedHome != "" {
		if evaled, err := filepath.EvalSymlinks(resolvedHome); err == nil {
			resolvedHome = evaled
		}
	}

	if resolvedHome != "" {
		dotSSH := filepath.Join(resolvedHome, ".ssh")
		if pathIsUnder(resolved, dotSSH) {
			warnings = append(warnings, KeyWarning{
				Level: "critical",
				Message: fmt.Sprintf(
					"identity file %q is under %s/ which is readable by all user processes "+
						"including unsandboxed AI agents; move it to a root-owned directory such as "+
						"/var/openscope/ssh/",
					resolved, dotSSH),
			})
		}
	}

	info, err := os.Stat(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			warnings = append(warnings, KeyWarning{
				Level:   "warning",
				Message: fmt.Sprintf("identity file %q does not exist", resolved),
			})
		}
		return warnings
	}

	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		warnings = append(warnings, KeyWarning{
			Level: "critical",
			Message: fmt.Sprintf(
				"identity file %q has mode %04o; must be 0600 or stricter to prevent "+
					"access by other processes",
				resolved, mode),
		})
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
		warnings = append(warnings, KeyWarning{
			Level: "warning",
			Message: fmt.Sprintf(
				"identity file %q is owned by uid %d, not root; "+
					"user processes may be able to read it via ownership",
				resolved, stat.Uid),
		})
	}

	dir := filepath.Dir(resolved)
	if dirInfo, err := os.Stat(dir); err == nil {
		dirMode := dirInfo.Mode().Perm()
		if dirMode&0o077 != 0 {
			warnings = append(warnings, KeyWarning{
				Level: "warning",
				Message: fmt.Sprintf(
					"directory %q has mode %04o; should be 0700 or stricter",
					dir, dirMode),
			})
		}
	}

	return warnings
}

func pathIsUnder(path, dir string) bool {
	path = filepath.Clean(path)
	dir = filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, dir+string(os.PathSeparator))
}
