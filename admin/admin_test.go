// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package admin

import (
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
