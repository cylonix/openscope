// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/executor"
)

// Bypass-probe outcomes.
const (
	BypassFound   = "bypass"       // a user key authenticated to the target
	BypassClear   = "clear"        // auth refused — no parallel path via this key
	BypassUnknown = "inconclusive" // host unreachable / other error — undetermined
)

// BypassResult is one (target, identity) probe outcome.
type BypassResult struct {
	Target  string `json:"target"`
	Host    string `json:"host"`
	Key     string `json:"key"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// DiscoverUserKeys returns the private-key files in <homeDir>/.ssh that an
// unprivileged agent could use directly: every file with a ".pub" sibling.
// These are the keys whose reach to a brokered server would bypass the broker;
// the public keys and other ~/.ssh contents (config, known_hosts) are ignored.
func DiscoverUserKeys(homeDir string) []string {
	if homeDir == "" {
		return nil
	}
	sshDir := filepath.Join(homeDir, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}
	var keys []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".pub") {
			continue
		}
		priv := filepath.Join(sshDir, strings.TrimSuffix(name, ".pub"))
		if info, err := os.Stat(priv); err == nil && !info.IsDir() {
			keys = append(keys, priv)
		}
	}
	sort.Strings(keys)
	return keys
}

// ProbeBypass attempts to authenticate to target using ONLY each of userKeys
// (never the broker's key), in batch mode. A key that authenticates proves the
// agent has an independent path to the host — the broker is bypassable. The
// only remote command run is the harmless `true`; nothing on the target is read
// or written.
//
// run executes ssh; pass nil for the default os/exec runner. This opens a real
// network connection to the target, so callers must invoke it only on explicit
// user request, never as a side effect of a routine check.
func ProbeBypass(target admin.SSHTarget, userKeys []string, run CommandRunner) []BypassResult {
	if run == nil {
		run = execRunner{}
	}
	port := target.Port
	if port == 0 {
		port = 22
	}
	dest := target.Host
	if target.User != "" {
		dest = target.User + "@" + target.Host
	}
	out := make([]BypassResult, 0, len(userKeys))
	for _, key := range userKeys {
		args := []string{
			"-o", "BatchMode=yes",
			"-o", "IdentitiesOnly=yes",
			"-o", "PreferredAuthentications=publickey",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=5",
			"-i", key,
			"-p", strconv.Itoa(port),
		}
		if target.ProxyJump != "" {
			args = append(args, "-J", target.ProxyJump)
		}
		args = append(args, dest, "true")

		res, err := run.Run("ssh", args, "")
		out = append(out, classifyBypass(target, key, res, err))
	}
	return out
}

// classifyBypass maps an ssh probe's result to an outcome. ssh exits 0 only
// after authenticating and running `true`; a publickey rejection exits 255 with
// "Permission denied"; anything else (timeout, refused, DNS) is undetermined.
func classifyBypass(target admin.SSHTarget, key string, res executor.Result, err error) BypassResult {
	r := BypassResult{Target: target.Alias, Host: target.Host, Key: key}
	switch {
	case err != nil:
		r.Outcome, r.Detail = BypassUnknown, err.Error()
	case res.ExitCode == 0:
		r.Outcome = BypassFound
	case strings.Contains(res.Stderr, "Permission denied") || strings.Contains(res.Stderr, "publickey"):
		r.Outcome = BypassClear
	default:
		r.Outcome, r.Detail = BypassUnknown, firstLine(res.Stderr)
	}
	return r
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if before, _, found := strings.Cut(s, "\n"); found {
		return strings.TrimSpace(before)
	}
	return s
}
