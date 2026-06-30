// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mcp

import (
	"context"
	"os"
	"time"

	"github.com/openscope/openscope/config"
)

// CapabilityFiles are the on-disk inputs that determine an agent's tool
// surface: the policy (incl. its legacy fallback), the root-applied verb
// registry, the ssh targets (enum/hint values), and the user app dir. A change
// to any of them — e.g. `sudo openscope apply` rewriting the registry — can add
// or remove tools.
func CapabilityFiles(paths config.Paths) []string {
	return []string{
		paths.PoliciesFile,
		paths.LegacyPoliciesFile,
		paths.AppDefinitionsFile,
		paths.SSHTargetsFile,
		paths.AppsDir,
	}
}

// fileWatcher tracks per-path modification stamps using only the stdlib (no
// fsnotify dependency, per the root module's dependency policy).
type fileWatcher struct{ last map[string]int64 }

func newFileWatcher(files []string) *fileWatcher {
	w := &fileWatcher{last: make(map[string]int64, len(files))}
	for _, f := range files {
		w.last[f] = stamp(f)
	}
	return w
}

// changed re-stats every watched path and reports whether any changed since the
// last call, updating the recorded stamps.
func (w *fileWatcher) changed() bool {
	changed := false
	for f := range w.last {
		if s := stamp(f); s != w.last[f] {
			w.last[f] = s
			changed = true
		}
	}
	return changed
}

// stamp combines mtime and size so an in-place edit is detected even if the
// mtime resolution is coarse; a missing path stamps 0, so create/delete flips it.
func stamp(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.ModTime().UnixNano() ^ fi.Size()
}

// CapabilityWatcher polls the capability inputs and, when the resulting tool set
// actually changes, refreshes the provider and fires notify (tools/list_changed).
// It is built from function values so the poll logic can be tested without a
// live broker.
type CapabilityWatcher struct {
	fw        *fileWatcher
	refresh   func() error
	signature func() string
	notify    func() error
	lastSig   string
}

// NewCapabilityWatcher captures the initial file stamps and tool signature.
func NewCapabilityWatcher(files []string, refresh func() error, signature func() string, notify func() error) *CapabilityWatcher {
	return &CapabilityWatcher{
		fw:        newFileWatcher(files),
		refresh:   refresh,
		signature: signature,
		notify:    notify,
		lastSig:   signature(),
	}
}

// poll performs one check. It returns true only when a notify was emitted (a
// watched file changed AND the refreshed tool set differs). A refresh error is
// swallowed so the server keeps serving the last good surface.
func (w *CapabilityWatcher) poll() bool {
	if !w.fw.changed() {
		return false
	}
	if err := w.refresh(); err != nil {
		return false
	}
	sig := w.signature()
	if sig == w.lastSig {
		return false
	}
	w.lastSig = sig
	if w.notify != nil {
		_ = w.notify()
	}
	return true
}

// Run polls every interval until ctx is cancelled.
func (w *CapabilityWatcher) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.poll()
		}
	}
}
