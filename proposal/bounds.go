// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Bounds is the root-owned outer envelope a proposal can never exceed — the
// SCP/IAM-Access-Analyzer pattern adapted for a single-user install. Findings
// whose rule ID is in BlockingRules hard-fail apply; the only way past is to
// edit this file as root, which is the one deliberate, visible escape hatch.
type Bounds struct {
	Version       int      `yaml:"version"`
	BlockingRules []string `yaml:"blocking_rules"`

	SSH struct {
		// RootUser: "allow" | "acknowledge" | "deny".
		RootUser            string   `yaml:"root_user"`
		SecretAbsolutePaths []string `yaml:"secret_absolute_paths"`
		BroadReadPrefixes   []string `yaml:"broad_read_prefixes"`
		WebrootPrefixes     []string `yaml:"webroot_prefixes"`
		ConfigSecretFiles   []string `yaml:"config_secret_files"`
		RequireIdentityFile bool     `yaml:"require_identity_file"`
	} `yaml:"ssh"`

	System struct {
		DenyAppInstallFromWritableSource bool `yaml:"deny_app_install_from_writable_source"`
		DenySudoManagers                 bool `yaml:"deny_sudo_managers"`
	} `yaml:"system"`

	MaxTargetsPerAgent int `yaml:"max_targets_per_agent"`
}

// DefaultBoundsYAML is the opinionated starter envelope. It ships real
// defaults so the issues a careless proposal introduces (secret-reachable
// read paths, code-execution-capable app installs, sudo package managers) are
// caught out of the box. Written to <AdminDir>/bounds.yaml on first apply.
const DefaultBoundsYAML = `# OpenScope bounds — the root-owned envelope no proposal may exceed.
# Edit as root to deliberately widen what apply will accept.
version: 1

# Findings with these rule IDs hard-fail apply (override only by editing here).
blocking_rules:
  - SYS-APP-CODEEXEC
  - SYS-PKG-CODEEXEC
  - SSH-SECRET-PATH
  - SSH-KEY-READABLE
  - SSH-KEY-INVALID
  - SSH-BYPASS
  - SYS-SUDO-MANAGER
  - SSH-TARGET-CONFLICT
  - POLICY-MAX-TARGETS

ssh:
  # root | acknowledge | deny  — root logins require typed acknowledgment.
  root_user: acknowledge
  # A granted read path/prefix that is, contains, or sits under any of these
  # is treated as reaching secrets and BLOCKS apply.
  secret_absolute_paths:
    - /etc/shadow
    - /etc/sudoers
    - /etc/ssl/private
    - /etc/letsencrypt
    - /etc/nginx/ssl
    - /root/.ssh
    - /home
  # Broad read prefixes — allowed, but flagged MEDIUM (creds leak into them).
  broad_read_prefixes:
    - /var/log
    - /var
    - /etc
    - /usr
    - /opt
  # Web/app roots whose reads may expose application config such as .env.
  webroot_prefixes:
    - /var/www
    - /srv/www
    - /usr/share/nginx/html
  # Config files that commonly inline secrets/env — read grants flagged MEDIUM.
  config_secret_files:
    - compose.yml
    - compose.yaml
    - docker-compose.yml
    - docker-compose.yaml
    - .env
  # Brokered ssh access MUST use an explicit, root-owned identity_file — no
  # ~/.ssh fallback, which is readable by the agent. Set false only on a
  # personal install that knowingly accepts an agent-readable key.
  require_identity_file: true

system:
  deny_app_install_from_writable_source: true
  deny_sudo_managers: false

max_targets_per_agent: 16
`

func DefaultBounds() Bounds {
	var b Bounds
	// DefaultBoundsYAML is a compile-time constant we author — a parse failure
	// is a programming error, so ignore the (impossible) error.
	_ = yaml.Unmarshal([]byte(DefaultBoundsYAML), &b)
	return b
}

// LoadBounds reads bounds from path, falling back to the opinionated defaults
// when the file does not exist (so plan works on a fresh install).
func LoadBounds(path string) (Bounds, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultBounds(), false, nil
		}
		return Bounds{}, false, fmt.Errorf("read bounds: %w", err)
	}
	var b Bounds
	if err := yaml.Unmarshal(data, &b); err != nil {
		return Bounds{}, false, fmt.Errorf("parse bounds: %w", err)
	}
	if b.Version == 0 {
		return Bounds{}, false, fmt.Errorf("bounds version is required")
	}
	return b, true, nil
}

func (b Bounds) blocks(ruleID string) bool {
	return contains(b.BlockingRules, ruleID)
}
