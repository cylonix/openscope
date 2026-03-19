// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const DirName = ".agentscope"

type Paths struct {
	HomeDir         string
	ConfigDir       string
	AppsDir         string
	RunDir          string
	StateDir        string
	PoliciesFile    string
	AgentsFile      string
	AuditFile       string
	EnabledAppsFile string
	SocketPath      string
}

func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("locate home directory: %w", err)
	}

	configDir := filepath.Join(home, DirName)
	return Paths{
		HomeDir:         home,
		ConfigDir:       configDir,
		AppsDir:         filepath.Join(configDir, "apps.d"),
		RunDir:          filepath.Join(configDir, "run"),
		StateDir:        filepath.Join(configDir, "state"),
		PoliciesFile:    filepath.Join(configDir, "policies.yaml"),
		AgentsFile:      filepath.Join(configDir, "agents.yaml"),
		AuditFile:       filepath.Join(configDir, "audit.jsonl"),
		EnabledAppsFile: filepath.Join(configDir, "state", "enabled_apps.yaml"),
		SocketPath:      filepath.Join(configDir, "run", "ascoped.sock"),
	}, nil
}

func EnsureLayout(paths Paths) error {
	for _, dir := range []string{paths.ConfigDir, paths.AppsDir, paths.RunDir, paths.StateDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	return nil
}
