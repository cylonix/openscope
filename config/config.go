// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

const DirName = ".openscope"
const AdminDir = "/Library/Application Support/OpenScope"

type Paths struct {
	HomeDir              string
	ConfigDir            string
	AppsDir              string
	RunDir               string
	StateDir             string
	PoliciesFile         string
	AgentsFile           string
	AuditFile            string
	EnabledAppsFile      string
	SocketPath           string
	HTTPListenAddr       string
	HTTPURL              string
	AdminDir             string
	ProtectedFoldersFile string
	MailFiltersFile      string
	SSHTargetsFile       string
	HTTPProfilesFile     string
	SystemCommandsFile   string
}

func DefaultPaths() (Paths, error) {
	home, err := resolveConfigHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("locate home directory: %w", err)
	}

	configDir := filepath.Join(home, DirName)
	if override := os.Getenv("OPENSCOPE_CONFIG_DIR"); override != "" {
		configDir = override
	}

	adminDir := AdminDir
	if override := os.Getenv("OPENSCOPE_ADMIN_DIR"); override != "" {
		adminDir = override
	}

	paths := Paths{
		HomeDir:              home,
		ConfigDir:            configDir,
		AppsDir:              filepath.Join(configDir, "apps.d"),
		RunDir:               filepath.Join(configDir, "run"),
		StateDir:             filepath.Join(configDir, "state"),
		PoliciesFile:         filepath.Join(configDir, "policies.yaml"),
		AgentsFile:           filepath.Join(configDir, "agents.yaml"),
		AuditFile:            filepath.Join(configDir, "audit.jsonl"),
		EnabledAppsFile:      filepath.Join(configDir, "state", "enabled_apps.yaml"),
		SocketPath:           filepath.Join(configDir, "run", "openscoped.sock"),
		HTTPListenAddr:       os.Getenv("OPENSCOPE_HTTP_LISTEN"),
		HTTPURL:              os.Getenv("OPENSCOPE_HTTP_URL"),
		AdminDir:             adminDir,
		ProtectedFoldersFile: filepath.Join(adminDir, "protected_folders.yaml"),
		MailFiltersFile:      filepath.Join(adminDir, "mail_filters.yaml"),
		SSHTargetsFile:       filepath.Join(adminDir, "ssh_targets.yaml"),
		HTTPProfilesFile:     filepath.Join(adminDir, "http_profiles.yaml"),
		SystemCommandsFile:   filepath.Join(adminDir, "system_commands.yaml"),
	}

	if override := os.Getenv("OPENSCOPE_SOCKET"); override != "" {
		paths.SocketPath = override
	}

	return paths, nil
}

func resolveConfigHomeDir() (string, error) {
	if os.Geteuid() == 0 {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			account, err := user.Lookup(sudoUser)
			if err != nil {
				return "", fmt.Errorf("lookup sudo user %q: %w", sudoUser, err)
			}
			if account.HomeDir != "" {
				return account.HomeDir, nil
			}
		}
	}
	return os.UserHomeDir()
}

func EnsureLayout(paths Paths) error {
	for _, dir := range []string{paths.ConfigDir, paths.AppsDir, paths.RunDir, paths.StateDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	return nil
}
