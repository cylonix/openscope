// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package doctor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/config"
)

func TestCheckSSHTargetsConfigMissingIsOptional(t *testing.T) {
	paths := config.Paths{
		SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"),
	}

	check := checkSSHTargetsConfig(paths)
	if !check.Checked || !check.OK || check.Present {
		t.Fatalf("unexpected check result: %#v", check)
	}
}

func TestCheckSSHTargetsConfigInvalidFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_targets.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ntargets:\n  - alias: bad\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	check := checkSSHTargetsConfig(config.Paths{SSHTargetsFile: path})
	if check.OK || !check.Present {
		t.Fatalf("expected invalid file to fail, got %#v", check)
	}
}

func TestCheckSSHKeyProtectionNoTargetsIsOK(t *testing.T) {
	paths := config.Paths{
		SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"),
	}
	check := checkSSHKeyProtection(paths)
	if !check.Checked || !check.OK {
		t.Fatalf("expected OK with no targets: %#v", check)
	}
	if len(check.Warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", check.Warnings)
	}
}

func TestCheckSSHKeyProtectionWarnsKeyInDotSSH(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "prod_key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	targetsPath := filepath.Join(t.TempDir(), "ssh_targets.yaml")
	if err := admin.SaveSSHTargets(targetsPath, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias:        "prod",
			Host:         "prod.internal",
			User:         "deploy",
			IdentityFile: keyPath,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	check := checkSSHKeyProtection(config.Paths{
		SSHTargetsFile: targetsPath,
		HomeDir:        home,
	})
	if check.OK {
		t.Fatalf("expected not OK for key in ~/.ssh/, got %#v", check)
	}
	hasProd := false
	for _, w := range check.Warnings {
		if w.Target == "prod" && w.Level == "critical" {
			hasProd = true
		}
	}
	if !hasProd {
		t.Fatalf("expected critical warning for target prod, got %v", check.Warnings)
	}
}

func TestCheckSSHKeyProtectionWeakPermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "prod_key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}

	targetsPath := filepath.Join(t.TempDir(), "ssh_targets.yaml")
	if err := admin.SaveSSHTargets(targetsPath, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias:        "staging",
			Host:         "staging.internal",
			User:         "deploy",
			IdentityFile: keyPath,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	check := checkSSHKeyProtection(config.Paths{
		SSHTargetsFile: targetsPath,
		HomeDir:        "/nonexistent-home",
	})
	if check.OK {
		t.Fatalf("expected not OK for mode 0644, got %#v", check)
	}
}

func TestCheckSSHKeyProtectionUserOwnedKeyIsError(t *testing.T) {
	// A 0600 key the agent's own user owns is still agent-readable: the broker
	// can be bypassed by sshing directly with it. The key MUST be root-owned, so
	// even a tidy user-owned key is an error, not an OK "protected" key.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "prod_key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	targetsPath := filepath.Join(t.TempDir(), "ssh_targets.yaml")
	if err := admin.SaveSSHTargets(targetsPath, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias:        "prod",
			Host:         "prod.internal",
			User:         "deploy",
			IdentityFile: keyPath,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	check := checkSSHKeyProtection(config.Paths{
		SSHTargetsFile: targetsPath,
		HomeDir:        "/nonexistent-home",
	})
	if check.OK {
		t.Fatalf("expected not OK for a user-owned (non-root) key, got %#v", check)
	}
}

func TestCheckHTTPProfilesConfigCountsProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "http_profiles.yaml")
	if err := admin.SaveHTTPProfiles(path, admin.HTTPProfiles{
		Version: 1,
		Profiles: []admin.HTTPProfile{{
			Name:    "jira-work",
			BaseURL: "https://example.atlassian.net",
		}},
	}); err != nil {
		t.Fatalf("SaveHTTPProfiles returned error: %v", err)
	}

	check := checkHTTPProfilesConfig(config.Paths{HTTPProfilesFile: path})
	if !check.OK || !check.Present || check.Count != 1 {
		t.Fatalf("unexpected check result: %#v", check)
	}
}

func TestCheckPrivilegeSeparationFlagsLocalPrivilegedBrokering(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — the broker would be privilege-separated")
	}
	// Local install (no HTTP URL) with ssh targets, non-root broker, no root
	// daemon installed → bypassable.
	c := checkPrivilegeSeparation(config.Paths{}, false, ConfigCheck{Present: true, Count: 1}, ConfigCheck{})
	if c.OK {
		t.Fatalf("expected not OK for local privileged brokering on a non-root broker, got %+v", c)
	}
	if c.Separated || c.Root {
		t.Errorf("non-root broker should be neither separated nor root, got %+v", c)
	}
}

func TestCheckPrivilegeSeparationOKWhenRootDaemonInstalled(t *testing.T) {
	// Same bypassable-looking config, but the root LaunchDaemon is installed:
	// the broker runs as root regardless of doctor's own (user) euid.
	c := checkPrivilegeSeparation(config.Paths{}, true, ConfigCheck{Present: true, Count: 1}, ConfigCheck{})
	if !c.OK || !c.Separated || !c.Root {
		t.Fatalf("expected separated+OK when the root daemon is installed, got %+v", c)
	}
}

func TestCheckPrivilegeSeparationOKWhenNothingPrivileged(t *testing.T) {
	// No ssh targets, no system commands → nothing privileged is brokered locally.
	c := checkPrivilegeSeparation(config.Paths{}, false, ConfigCheck{}, ConfigCheck{})
	if !c.OK {
		t.Fatalf("expected OK when no privileged brokering is configured, got %+v", c)
	}
}

func TestCheckPrivilegeSeparationOKForRemoteBroker(t *testing.T) {
	// HTTP/VPC topology: the agent is remote, so there is no local same-uid agent.
	c := checkPrivilegeSeparation(
		config.Paths{HTTPURL: "https://broker.example:8443"}, false,
		ConfigCheck{Present: true, Count: 3}, ConfigCheck{})
	if !c.OK {
		t.Fatalf("remote broker should be OK regardless of uid, got %+v", c)
	}
}
