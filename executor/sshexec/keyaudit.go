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
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Machine-readable KeyWarning codes. Callers that must assign their own
// severity (e.g. the proposal lint, which blocks agent-readable keys) switch on
// these instead of parsing Message. Level is kept for callers that only need
// the critical/warning split (doctor).
const (
	KeyNoIdentityFile = "no_identity_file"  // ssh will fall back to ~/.ssh
	KeyUnderDotSSH    = "under_dotssh"       // key resolves under ~/.ssh
	KeyModeTooOpen    = "mode_too_open"      // file mode has bits outside 0600
	KeyNotRootOwned   = "not_root_owned"     // file owned by a non-root uid
	KeyNotRegularFile = "not_regular_file"   // identity_file is a dir/socket, not a key
	KeyLooseDir       = "loose_dir"          // containing dir is group/world-accessible
	KeyMissing        = "missing"            // identity file does not exist
)

// AgentAccessible reports whether a code means the CONFIGURED brokered key is
// readable/usable by the agent's user, or is not a usable root-owned key file.
// These are the conditions the ssh executor — which runs as root and therefore
// has the vantage to see inside a 0700 dir the planner cannot — must REFUSE,
// since they let the agent ssh directly (a broker bypass) or mean there is no
// usable root-owned key. KeyNoIdentityFile/LooseDir/Missing are weaker (handled
// by plan/doctor), not a hard executor refusal.
func AgentAccessible(code string) bool {
	switch code {
	case KeyUnderDotSSH, KeyModeTooOpen, KeyNotRootOwned, KeyNotRegularFile:
		return true
	}
	return false
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
			Code:  KeyNoIdentityFile,
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
				Code:  KeyUnderDotSSH,
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
				Code:    KeyMissing,
				Message: fmt.Sprintf("identity file %q does not exist", resolved),
			})
		}
		return warnings
	}

	// identity_file must be a regular file ssh can use as a key. A directory (or
	// other non-regular file) is invalid AND can't be fully vetted from the
	// planner: a 0700 root dir is unreadable by the user-vantage planner, so it
	// would otherwise pass the file-level checks below while its contents stay
	// unverified. Flag it as an invalid key (not "readable" — the agent may well
	// be unable to read it). The per-file audit that follows only sees inside
	// when the caller CAN read the dir (the root daemon, or a too-loose dir);
	// from the user-vantage planner it is a no-op, which is correct — what the
	// planner can't read, the agent can't either.
	if !info.Mode().IsRegular() {
		warnings = append(warnings, KeyWarning{
			Level: "critical",
			Code:  KeyNotRegularFile,
			Message: fmt.Sprintf(
				"identity_file %q is not a regular key file (e.g. a directory); "+
					"ssh cannot use it, and provide a single root-owned 0600 key file instead",
				resolved),
		})
		if info.IsDir() {
			warnings = append(warnings, auditKeysInDir(resolved)...)
		}
		return warnings
	}

	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		warnings = append(warnings, KeyWarning{
			Level: "critical",
			Code:  KeyModeTooOpen,
			Message: fmt.Sprintf(
				"identity file %q has mode %04o; must be 0600 or stricter to prevent "+
					"access by other processes",
				resolved, mode),
		})
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
		warnings = append(warnings, KeyWarning{
			Level: "warning",
			Code:  KeyNotRootOwned,
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
				Code:  KeyLooseDir,
				Message: fmt.Sprintf(
					"directory %q has mode %04o; should be 0700 or stricter",
					dir, dirMode),
			})
		}
	}

	return warnings
}

// auditKeysInDir flags every private-key file in dir that is not root-owned or
// is mode-too-open — so a root-owned directory holding agent-owned keys can't
// pass custody. .pub files are public and skipped; symlinks are followed so a
// link to an agent-owned key is still caught.
func auditKeysInDir(dir string) []KeyWarning {
	var out []KeyWarning
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			out = append(out, KeyWarning{
				Level:   "critical",
				Code:    KeyModeTooOpen,
				Message: fmt.Sprintf("key %q has mode %04o; must be 0600 or stricter", p, mode),
			})
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
			out = append(out, KeyWarning{
				Level:   "critical",
				Code:    KeyNotRootOwned,
				Message: fmt.Sprintf("key %q is owned by uid %d, not root", p, stat.Uid),
			})
		}
	}
	return out
}

func pathIsUnder(path, dir string) bool {
	path = filepath.Clean(path)
	dir = filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, dir+string(os.PathSeparator))
}
