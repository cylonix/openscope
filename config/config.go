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

// SystemSocketPath is where a root LaunchDaemon (the macOS privileged-helper
// model) binds its CLI socket — a system location its plist points
// OPENSCOPE_SOCKET at. A non-root, per-user daemon uses <ConfigDir>/run instead.
const SystemSocketPath = "/var/run/openscope/openscoped.sock"

// chooseSocketPath resolves the socket both the CLI and daemon use: an explicit
// env override wins (the root daemon's plist sets it); else a present system
// socket (so a user shell finds a running root daemon without any env); else
// the per-user socket.
func chooseSocketPath(envSocket, userSocket string, systemExists bool) string {
	switch {
	case envSocket != "":
		return envSocket
	case systemExists:
		return SystemSocketPath
	default:
		return userSocket
	}
}

// LaunchDaemonPlistPath is the root LaunchDaemon's plist. Its presence is the
// single deployment-level signal that the root-daemon (privileged-helper) model
// is installed — read identically by the daemon, the CLI, and `apply` so they
// agree on the audit/config layout regardless of which uid each runs as. (A
// per-process euid check can't: `apply` runs root via sudo while the legacy
// daemon runs non-root, which would split-brain the audit log.)
const LaunchDaemonPlistPath = "/Library/LaunchDaemons/com.ezblock.openscope.openscoped.plist"

// SystemMode reports whether the root-daemon deployment is installed.
func SystemMode() bool {
	_, err := os.Stat(LaunchDaemonPlistPath)
	return err == nil
}

// auditFilePath puts the audit log root-owned in the admin dir under the
// root-daemon deployment (the agent can read but not truncate it), and in the
// per-user config dir otherwise (where the non-root daemon must append to it).
func auditFilePath(systemMode bool, adminDir, configDir string) string {
	if systemMode {
		return filepath.Join(adminDir, "audit.jsonl")
	}
	return filepath.Join(configDir, "audit.jsonl")
}

type Paths struct {
	HomeDir              string
	ConfigDir            string
	AppsDir              string
	RunDir               string
	StateDir             string
	PoliciesFile         string
	AgentsFile           string
	AuditFile            string
	// LegacyPoliciesFile is the pre-migration location (<ConfigDir>/policies.yaml).
	// Policy now lives root-owned in AdminDir; this is a read-only fallback so an
	// install upgraded before its next `sudo apply` keeps enforcing its policy.
	LegacyPoliciesFile string
	EnabledAppsFile    string
	SocketPath           string
	HTTPListenAddr       string
	HTTPURL              string
	AdminDir             string
	ProtectedFoldersFile string
	MailFiltersFile      string
	SSHTargetsFile       string
	HTTPProfilesFile     string
	SystemCommandsFile   string
	// AppDefinitionsFile is the root-owned applied-verb registry — custom verb
	// (app/action) definitions a proposal added, pinned so a same-uid agent
	// cannot rewrite an approved command. Read by the daemon, written only by
	// `sudo openscope apply`.
	AppDefinitionsFile string

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
		PoliciesFile:         filepath.Join(adminDir, "policies.yaml"),
		LegacyPoliciesFile:   filepath.Join(configDir, "policies.yaml"),
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
		AppDefinitionsFile:   filepath.Join(adminDir, "app_definitions.yaml"),
	}

	// Socket resolution: an explicit OPENSCOPE_SOCKET wins (the root LaunchDaemon
	// sets it to the system socket). Otherwise the CLI prefers a system socket if
	// one exists — so a user shell finds a root daemon's socket without needing
	// the env — and falls back to the per-user socket.
	_, sysSockErr := os.Stat(SystemSocketPath)
	paths.SocketPath = chooseSocketPath(os.Getenv("OPENSCOPE_SOCKET"), paths.SocketPath, sysSockErr == nil)
	paths.AuditFile = auditFilePath(SystemMode(), adminDir, configDir)

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
	if home, err := os.UserHomeDir(); err == nil {
		return home, nil
	}
	// $HOME is unset — a system LaunchDaemon runs with a minimal environment.
	// Fall back to the running user's passwd home (root → /var/root) so the
	// daemon can start; a root daemon overrides ConfigDir via OPENSCOPE_CONFIG_DIR.
	if account, err := user.Current(); err == nil && account.HomeDir != "" {
		return account.HomeDir, nil
	}
	return "", fmt.Errorf("cannot determine home directory ($HOME unset)")
}

func EnsureLayout(paths Paths) error {
	for _, dir := range []string{paths.ConfigDir, paths.AppsDir, paths.RunDir, paths.StateDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	return nil
}
