// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appdef

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// AppliedFile is the root-owned applied-verb registry written by
// `openscope apply` to <AdminDir>/app_definitions.yaml. Each entry is a
// (possibly partial) Definition that merges onto the bundled namespace — e.g.
// `app: {name: ssh, executor: ssh}` plus only the new custom `actions:`. Because
// the file is root-owned, a same-uid agent cannot rewrite the command a verb
// runs after a human has approved it, the same custody rule policies.yaml uses.
type AppliedFile struct {
	Version int          `yaml:"version"`
	Apps    []Definition `yaml:"apps"`
}

// LoadAppliedFile reads the applied-verb registry, validating and marking each
// definition RootApplied. A missing file is not an error (returns nil) so a
// fresh install with no custom verbs loads cleanly.
func LoadAppliedFile(path string) ([]Definition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read applied app definitions: %w", err)
	}
	var f AppliedFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse applied app definitions: %w", err)
	}
	defs := make([]Definition, 0, len(f.Apps))
	for i := range f.Apps {
		d := f.Apps[i]
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("applied app definitions: %w", err)
		}
		d.RootApplied = true
		d.Source = path
		d.ManifestPath = path
		defs = append(defs, d)
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].App.Name < defs[j].App.Name })
	return defs, nil
}

// SaveAppliedFile persists the registry root-owned and world-readable (0644), so
// the non-root daemon can read it but only root (via `sudo openscope apply`) can
// write it. Mirrors policy.Save.
func SaveAppliedFile(path string, defs []Definition) error {
	f := AppliedFile{Version: 1, Apps: append([]Definition{}, defs...)}
	for i := range f.Apps {
		if err := f.Apps[i].Validate(); err != nil {
			return fmt.Errorf("applied app definitions: %w", err)
		}
	}
	sort.Slice(f.Apps, func(i, j int) bool { return f.Apps[i].App.Name < f.Apps[j].App.Name })
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal applied app definitions: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create admin config dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write applied app definitions: %w", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("chmod applied app definitions: %w", err)
	}
	return nil
}

// Merge folds overlay onto base (same app name), unioning actions with overlay
// winning on conflict. The overlay may not change a set executor or
// security_mode — an extension adds verbs to a namespace, it cannot redefine
// what the namespace is.
func Merge(base, overlay Definition) (Definition, error) {
	if base.App.Name != overlay.App.Name {
		return Definition{}, fmt.Errorf("cannot merge app %q into %q", overlay.App.Name, base.App.Name)
	}
	out := base
	if overlay.App.Executor != "" && base.App.Executor != "" && overlay.App.Executor != base.App.Executor {
		return Definition{}, fmt.Errorf("app %q: overlay executor %q conflicts with %q", base.App.Name, overlay.App.Executor, base.App.Executor)
	}
	if out.App.Executor == "" {
		out.App.Executor = overlay.App.Executor
	}
	if overlay.App.SecurityMode != "" && base.App.SecurityMode != "" && overlay.App.SecurityMode != base.App.SecurityMode {
		return Definition{}, fmt.Errorf("app %q: overlay security_mode %q conflicts with %q", base.App.Name, overlay.App.SecurityMode, base.App.SecurityMode)
	}
	if out.App.SecurityMode == "" {
		out.App.SecurityMode = overlay.App.SecurityMode
	}
	if out.App.DisplayName == "" {
		out.App.DisplayName = overlay.App.DisplayName
	}
	if out.App.Description == "" {
		out.App.Description = overlay.App.Description
	}
	merged := make(map[string]Action, len(base.Actions)+len(overlay.Actions))
	for k, v := range base.Actions {
		merged[k] = v
	}
	for k, v := range overlay.Actions {
		merged[k] = v
	}
	out.Actions = merged
	out.RootApplied = base.RootApplied || overlay.RootApplied
	return out, nil
}

// MergeInto folds def into dst by app name, replacing the entry with the merged
// result (or inserting when the namespace is new).
func MergeInto(dst map[string]Definition, def Definition) error {
	if existing, ok := dst[def.App.Name]; ok {
		merged, err := Merge(existing, def)
		if err != nil {
			return err
		}
		dst[def.App.Name] = merged
		return nil
	}
	dst[def.App.Name] = def
	return nil
}

// MergeDefinitionList folds def into a registry list by app name (action-level
// union, def's actions win), used by apply to accumulate proposal verbs.
func MergeDefinitionList(list []Definition, def Definition) ([]Definition, error) {
	for i := range list {
		if list[i].App.Name == def.App.Name {
			merged, err := Merge(list[i], def)
			if err != nil {
				return nil, err
			}
			list[i] = merged
			return list, nil
		}
	}
	return append(list, def), nil
}

// RemoveDefinitionAction removes one action — or the whole app when action is
// "" — from a registry list, dropping an app left with no actions.
func RemoveDefinitionAction(list []Definition, app, action string) []Definition {
	out := list[:0]
	for _, d := range list {
		if d.App.Name != app {
			out = append(out, d)
			continue
		}
		if action == "" {
			continue
		}
		if _, ok := d.Actions[action]; ok {
			m := make(map[string]Action, len(d.Actions))
			for k, v := range d.Actions {
				if k != action {
					m[k] = v
				}
			}
			d.Actions = m
		}
		if len(d.Actions) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// AssembleDefinitions builds the effective namespace map from three sources in
// pinned precedence (last wins per action): bundled (embedded, trusted) → user
// apps.d → root applied registry (authoritative). When systemMode is true a
// real privilege boundary exists, so command-template actions from the
// user-writable apps.d are dropped: under a boundary a verb's command must come
// from a trusted source (bundled or the root registry), never a file the agent
// can rewrite. Personal installs (no root daemon) keep apps.d custom verbs.
func AssembleDefinitions(bundled []Definition, appsDir, registryFile string, systemMode bool) (map[string]Definition, error) {
	defs := make(map[string]Definition, len(bundled))
	for _, d := range bundled {
		defs[d.App.Name] = d
	}

	userDefs, err := LoadDir(appsDir)
	if err != nil {
		return nil, err
	}
	for _, d := range userDefs {
		if systemMode {
			d = withoutCommandActions(d)
			if len(d.Actions) == 0 {
				continue
			}
		}
		if err := MergeInto(defs, d); err != nil {
			return nil, err
		}
	}

	applied, err := LoadAppliedFile(registryFile)
	if err != nil {
		return nil, err
	}
	for _, d := range applied {
		if err := MergeInto(defs, d); err != nil {
			return nil, err
		}
	}
	return defs, nil
}

// withoutCommandActions returns a copy of d with command-template actions
// removed, leaving script/passthrough actions untouched.
func withoutCommandActions(d Definition) Definition {
	filtered := make(map[string]Action, len(d.Actions))
	for name, a := range d.Actions {
		if strings.TrimSpace(a.Command) != "" {
			continue
		}
		filtered[name] = a
	}
	out := d
	out.Actions = filtered
	return out
}
