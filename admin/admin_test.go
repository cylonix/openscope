// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openscope/openscope/config"
)

func TestLoadProtectedFoldersOrDefaultUsesDefaultsWhenMissing(t *testing.T) {
	paths := config.Paths{
		ProtectedFoldersFile: filepath.Join(t.TempDir(), "protected_folders.yaml"),
	}

	protected, err := LoadProtectedFoldersOrDefault(paths)
	if err != nil {
		t.Fatalf("LoadProtectedFoldersOrDefault returned error: %v", err)
	}
	if len(protected.Keywords) != 2 || protected.Keywords[0] != "hidden" || protected.Keywords[1] != "private" {
		t.Fatalf("unexpected default keywords: %#v", protected.Keywords)
	}
}

func TestMatchProtectedFolderIsCaseInsensitiveSubstring(t *testing.T) {
	protected := ProtectedFolders{Version: 1, Keywords: []string{"hidden", "private"}}

	keyword, matched := MatchProtectedFolder(protected, "Work Private Notes")
	if !matched {
		t.Fatalf("expected folder match")
	}
	if keyword != "private" {
		t.Fatalf("expected private keyword, got %q", keyword)
	}
}

func TestSenderAllowedUsesNormalizedDomainAllowlist(t *testing.T) {
	filters := MailFilters{
		Version:              1,
		AllowedSenderDomains: []string{"mycompany.com"},
	}

	if !SenderAllowed(filters, "Alice <alice@mycompany.com>") {
		t.Fatalf("expected sender to be allowed")
	}
	if SenderAllowed(filters, "bob@gmail.com") {
		t.Fatalf("expected sender to be blocked")
	}
}

func TestAddAndRemoveSSHTarget(t *testing.T) {
	paths := config.Paths{
		SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"),
	}

	targets, added, err := AddSSHTarget(paths, SSHTarget{
		Alias:               "prod-api-1",
		Host:                "prod-api-1.internal",
		User:                "deploy",
		Port:                2222,
		AllowedServices:     []string{"api", "worker"},
		AllowedPaths:        []string{"/etc/app/config.yaml"},
		AllowedPathPrefixes: []string{"/var/log/app"},
	})
	if err != nil {
		t.Fatalf("AddSSHTarget returned error: %v", err)
	}
	if !added {
		t.Fatalf("expected target to be added")
	}
	if len(targets.Targets) != 1 {
		t.Fatalf("expected one target, got %#v", targets.Targets)
	}

	loaded, err := LoadSSHTargets(paths.SSHTargetsFile)
	if err != nil {
		t.Fatalf("LoadSSHTargets returned error: %v", err)
	}
	target, ok := FindSSHTarget(loaded, "prod-api-1")
	if !ok {
		t.Fatalf("expected target to be found")
	}
	if !SSHTargetAllowsService(target, "api") {
		t.Fatalf("expected api service to be allowed")
	}
	if !SSHTargetAllowsPath(target, "/var/log/app/current.log") {
		t.Fatalf("expected path prefix to be allowed")
	}

	_, removed, err := RemoveSSHTarget(paths, "prod-api-1")
	if err != nil {
		t.Fatalf("RemoveSSHTarget returned error: %v", err)
	}
	if !removed {
		t.Fatalf("expected target to be removed")
	}
}

func TestAddSSHTargetRejectsInvalidValues(t *testing.T) {
	paths := config.Paths{
		SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"),
	}

	if _, _, err := AddSSHTarget(paths, SSHTarget{Alias: "bad", Host: "", User: "deploy"}); err == nil {
		t.Fatalf("expected missing host to fail")
	}
	if _, _, err := AddSSHTarget(paths, SSHTarget{Alias: "bad", Host: "host", User: "", AllowedPaths: []string{"/etc"}}); err == nil {
		t.Fatalf("expected missing user to fail")
	}
	if _, _, err := AddSSHTarget(paths, SSHTarget{Alias: "bad", Host: "host", User: "deploy", AllowedPathPrefixes: []string{"relative/path"}}); err == nil {
		t.Fatalf("expected relative path prefix to fail")
	}
}

func TestLoadSSHTargetsOrDefaultReturnsEmptyWhenMissing(t *testing.T) {
	paths := config.Paths{
		SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml"),
	}

	targets, err := LoadSSHTargetsOrDefault(paths)
	if err != nil {
		t.Fatalf("LoadSSHTargetsOrDefault returned error: %v", err)
	}
	if targets.Version != 1 || len(targets.Targets) != 0 {
		t.Fatalf("unexpected default ssh targets: %#v", targets)
	}
}

func TestSaveSSHTargetsWritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_targets.yaml")
	err := SaveSSHTargets(path, SSHTargets{
		Version: 1,
		Targets: []SSHTarget{{Alias: "prod-api-1", Host: "host", User: "deploy"}},
	})
	if err != nil {
		t.Fatalf("SaveSSHTargets returned error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected ssh targets file to exist: %v", err)
	}
}

func TestAddAndRemoveHTTPProfile(t *testing.T) {
	paths := config.Paths{
		HTTPProfilesFile: filepath.Join(t.TempDir(), "http_profiles.yaml"),
	}

	profiles, added, err := AddHTTPProfile(paths, HTTPProfile{
		Name:    "jira-work",
		BaseURL: "https://example.atlassian.net",
		Headers: map[string]string{"Authorization": "Bearer secret"},
	})
	if err != nil {
		t.Fatalf("AddHTTPProfile returned error: %v", err)
	}
	if !added {
		t.Fatalf("expected profile to be added")
	}
	if len(profiles.Profiles) != 1 {
		t.Fatalf("expected one profile, got %#v", profiles.Profiles)
	}

	loaded, err := LoadHTTPProfiles(paths.HTTPProfilesFile)
	if err != nil {
		t.Fatalf("LoadHTTPProfiles returned error: %v", err)
	}
	if _, ok := FindHTTPProfile(loaded, "jira-work"); !ok {
		t.Fatalf("expected jira-work profile to be present")
	}

	_, removed, err := RemoveHTTPProfile(paths, "jira-work")
	if err != nil {
		t.Fatalf("RemoveHTTPProfile returned error: %v", err)
	}
	if !removed {
		t.Fatalf("expected profile to be removed")
	}
}

func TestAddHTTPProfileRejectsInvalidBaseURL(t *testing.T) {
	paths := config.Paths{
		HTTPProfilesFile: filepath.Join(t.TempDir(), "http_profiles.yaml"),
	}

	if _, _, err := AddHTTPProfile(paths, HTTPProfile{Name: "bad", BaseURL: "not-a-url"}); err == nil {
		t.Fatalf("expected invalid base url to fail")
	}
}

func TestLoadSystemCommandsOrDefaultReturnsEmptyWhenMissing(t *testing.T) {
	paths := config.Paths{
		SystemCommandsFile: filepath.Join(t.TempDir(), "system_commands.yaml"),
	}

	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		t.Fatalf("LoadSystemCommandsOrDefault returned error: %v", err)
	}
	if cmds.Version != 1 {
		t.Fatalf("expected version 1, got %d", cmds.Version)
	}
}

func TestAddAndRemoveManager(t *testing.T) {
	paths := config.Paths{
		SystemCommandsFile: filepath.Join(t.TempDir(), "system_commands.yaml"),
	}

	cmds, added, err := AddManager(paths, ManagerConfig{
		Name:   "brew",
		Binary: "/opt/homebrew/bin/brew",
	})
	if err != nil {
		t.Fatalf("AddManager returned error: %v", err)
	}
	if !added {
		t.Fatalf("expected manager to be added")
	}
	if len(cmds.Packages.Managers) != 1 {
		t.Fatalf("expected one manager, got %d", len(cmds.Packages.Managers))
	}

	// Duplicate should be idempotent.
	_, added, err = AddManager(paths, ManagerConfig{
		Name:   "brew",
		Binary: "/opt/homebrew/bin/brew",
	})
	if err != nil {
		t.Fatalf("duplicate AddManager returned error: %v", err)
	}
	if added {
		t.Fatalf("expected duplicate to be idempotent")
	}

	_, removed, err := RemoveManager(paths, "brew")
	if err != nil {
		t.Fatalf("RemoveManager returned error: %v", err)
	}
	if !removed {
		t.Fatalf("expected manager to be removed")
	}
}

func TestAddManagerRejectsInvalidValues(t *testing.T) {
	paths := config.Paths{
		SystemCommandsFile: filepath.Join(t.TempDir(), "system_commands.yaml"),
	}

	if _, _, err := AddManager(paths, ManagerConfig{Name: "", Binary: "/bin/test"}); err == nil {
		t.Fatalf("expected missing name to fail")
	}
	if _, _, err := AddManager(paths, ManagerConfig{Name: "test", Binary: ""}); err == nil {
		t.Fatalf("expected missing binary to fail")
	}
	if _, _, err := AddManager(paths, ManagerConfig{Name: "test", Binary: "relative/path"}); err == nil {
		t.Fatalf("expected relative binary to fail")
	}
}

func TestAddManagerRejectsSudoUserWritableBinary(t *testing.T) {
	dir := t.TempDir()
	paths := config.Paths{
		SystemCommandsFile: filepath.Join(dir, "system_commands.yaml"),
	}

	// Create a user-owned script.
	script := filepath.Join(dir, "my_script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	_, _, err := AddManager(paths, ManagerConfig{
		Name:   "bad",
		Binary: script,
		Sudo:   true,
	})
	if err == nil {
		t.Fatalf("expected sudo + user-owned binary to be rejected")
	}

	// Same binary without sudo should be fine.
	_, added, err := AddManager(paths, ManagerConfig{
		Name:   "ok",
		Binary: script,
		Sudo:   false,
	})
	if err != nil {
		t.Fatalf("non-sudo manager should succeed: %v", err)
	}
	if !added {
		t.Fatalf("expected manager to be added")
	}
}

func TestRequireSudoSafeRejectsGroupWritable(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "group_writable.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o775); err != nil {
		t.Fatalf("write script: %v", err)
	}

	if err := RequireSudoSafe(script); err == nil {
		t.Fatalf("expected group-writable binary to be rejected")
	}
}

func TestRequireSudoSafeAcceptsRootOwnedBinary(t *testing.T) {
	// /usr/bin/true is root-owned and not user-writable on all macOS/Linux.
	err := RequireSudoSafe("/usr/bin/true")
	if err != nil {
		t.Fatalf("expected root-owned system binary to pass: %v", err)
	}
}

func TestAddAndRemoveAllowedPackage(t *testing.T) {
	paths := config.Paths{
		SystemCommandsFile: filepath.Join(t.TempDir(), "system_commands.yaml"),
	}

	cmds, added, err := AddAllowedPackage(paths, "jq")
	if err != nil {
		t.Fatalf("AddAllowedPackage returned error: %v", err)
	}
	if !added {
		t.Fatalf("expected package to be added")
	}
	if !AllowsPackage(cmds, "jq") {
		t.Fatalf("expected jq to be allowed")
	}
	if AllowsPackage(cmds, "curl") {
		t.Fatalf("expected curl to not be allowed")
	}

	_, removed, err := RemoveAllowedPackage(paths, "jq")
	if err != nil {
		t.Fatalf("RemoveAllowedPackage returned error: %v", err)
	}
	if !removed {
		t.Fatalf("expected package to be removed")
	}
}

func TestBlockedOverridesAllowed(t *testing.T) {
	cmds := SystemCommands{
		Version: 1,
		Packages: PackageConfig{
			Allowed: []string{"jq", "malware"},
			Blocked: []string{"malware"},
		},
	}

	if !AllowsPackage(cmds, "jq") {
		t.Fatalf("expected jq to be allowed")
	}
	if AllowsPackage(cmds, "malware") {
		t.Fatalf("expected blocked package to be denied")
	}
}

func TestAllowsServiceAndSignalAndProcess(t *testing.T) {
	cmds := SystemCommands{
		Version: 1,
		Services: ServiceConfig{
			Allowed: []string{"postgresql", "redis"},
		},
		Processes: ProcessConfig{
			AllowedSignals: []string{"TERM", "HUP"},
			AllowedNames:   []string{"node", "python3"},
			AllowKillByPID: true,
		},
	}

	if !AllowsService(cmds, "postgresql") {
		t.Fatalf("expected postgresql to be allowed")
	}
	if AllowsService(cmds, "mysql") {
		t.Fatalf("expected mysql to not be allowed")
	}
	if !AllowsSignal(cmds, "term") {
		t.Fatalf("expected TERM to be allowed (case-insensitive)")
	}
	if AllowsSignal(cmds, "USR1") {
		t.Fatalf("expected USR1 to not be allowed")
	}
	if !AllowsProcess(cmds, "node") {
		t.Fatalf("expected node to be allowed")
	}
	if AllowsProcess(cmds, "ruby") {
		t.Fatalf("expected ruby to not be allowed")
	}
}

func TestAllowsPort(t *testing.T) {
	cmds := SystemCommands{
		Version: 1,
		Ports:   PortConfig{Allowed: []int{3000, 8080}},
	}

	if !AllowsPort(cmds, 3000) {
		t.Fatalf("expected port 3000 to be allowed")
	}
	if AllowsPort(cmds, 9999) {
		t.Fatalf("expected port 9999 to not be allowed")
	}
}

func TestAllowsFilePath(t *testing.T) {
	prefixes := []string{"/Users/randy/src"}

	if !AllowsFilePath(prefixes, "/Users/randy/src/project/file.go") {
		t.Fatalf("expected path under prefix to be allowed")
	}
	if AllowsFilePath(prefixes, "/etc/passwd") {
		t.Fatalf("expected path outside prefix to be denied")
	}
	if AllowsFilePath(prefixes, "") {
		t.Fatalf("expected empty path to be denied")
	}
	if AllowsFilePath(nil, "/Users/randy/src/file.go") {
		t.Fatalf("expected empty prefix list to deny all")
	}
}
