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

	// Network-broker hardening (enterprise VPC deployment). The HTTP
	// listener requires Bearer agent tokens (osk_agent_*) unless
	// HTTPAllowAnon is set, and refuses to serve plaintext on non-loopback
	// addresses unless HTTPPlaintextOK is set.
	HTTPTLSCertFile string // OPENSCOPE_HTTP_TLS_CERT
	HTTPTLSKeyFile  string // OPENSCOPE_HTTP_TLS_KEY
	HTTPAllowAnon   bool   // OPENSCOPE_HTTP_ALLOW_ANON — legacy localhost bridge
	HTTPPlaintextOK bool   // OPENSCOPE_HTTP_PLAINTEXT_OK — TLS terminated upstream

	// Agent token store (daemon side). Pepper: env wins, else the pepper
	// file (auto-generated on first mint — losing it invalidates every
	// minted token).
	AgentTokensFile string // <ConfigDir>/agent_tokens.yaml
	TokenPepperFile string // <ConfigDir>/token_pepper
	AuthPepper      string // OPENSCOPE_AUTH_PEPPER

	// Client side: token + private-CA bundle for calls to a remote broker.
	ClientToken  string // OPENSCOPE_TOKEN
	ClientCAFile string // OPENSCOPE_HTTP_CA
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

	paths.HTTPTLSCertFile = os.Getenv("OPENSCOPE_HTTP_TLS_CERT")
	paths.HTTPTLSKeyFile = os.Getenv("OPENSCOPE_HTTP_TLS_KEY")
	paths.HTTPAllowAnon = envBool("OPENSCOPE_HTTP_ALLOW_ANON")
	paths.HTTPPlaintextOK = envBool("OPENSCOPE_HTTP_PLAINTEXT_OK")
	paths.AgentTokensFile = filepath.Join(configDir, "agent_tokens.yaml")
	paths.TokenPepperFile = filepath.Join(configDir, "token_pepper")
	paths.AuthPepper = os.Getenv("OPENSCOPE_AUTH_PEPPER")
	paths.ClientToken = os.Getenv("OPENSCOPE_TOKEN")
	paths.ClientCAFile = os.Getenv("OPENSCOPE_HTTP_CA")

	return paths, nil
}

func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "yes", "YES", "on":
		return true
	}
	return false
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
