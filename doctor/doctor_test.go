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
