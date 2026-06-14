// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"
	"slices"

	"github.com/openscope/openscope/appdef"
)

type loadedApp struct {
	Definition appdef.Definition
	Enabled    bool
}

func applyEnabledState(defs map[string]appdef.Definition, enabled appdef.EnabledFile) map[string]loadedApp {
	loaded := make(map[string]loadedApp, len(defs))
	for name, def := range defs {
		// RootApplied apps came through `sudo openscope apply` (human-reviewed,
		// root-owned) — a stronger gate than `openscope app enable`, so they are
		// enabled without a separate opt-in, like bundled apps.
		isEnabled := def.Bundled || def.RootApplied || slices.Contains(enabled.Apps, name)
		loaded[name] = loadedApp{
			Definition: def,
			Enabled:    isEnabled,
		}
	}
	return loaded
}

func appNames(defs map[string]loadedApp) []string {
	names := make([]string, 0, len(defs))
	for name := range defs {
		names = append(names, name)
	}
	return names
}

func requireEnabledApp(defs map[string]loadedApp, name string) (loadedApp, error) {
	def, ok := defs[name]
	if !ok {
		return loadedApp{}, fmt.Errorf("unknown app %q", name)
	}
	if !def.Enabled {
		return loadedApp{}, fmt.Errorf("app %q is installed but not enabled", name)
	}
	return def, nil
}
