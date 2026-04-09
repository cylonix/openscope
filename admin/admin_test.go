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
