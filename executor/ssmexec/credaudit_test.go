// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ssmexec

import (
	"os"
	"path/filepath"
	"testing"
)

func hasCode(ws []CredWarning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}

func TestAuditCredCustody(t *testing.T) {
	dir := t.TempDir()

	// No file → instance role / env creds → custodied, no warnings.
	if ws := AuditCredCustody(filepath.Join(dir, "absent")); len(ws) != 0 {
		t.Errorf("absent cred file should pass, got %v", ws)
	}

	// User-owned (uid != 0 under test) 0600 file → not root-owned → agent-readable.
	f := filepath.Join(dir, "credentials")
	if err := os.WriteFile(f, []byte("[default]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := AuditCredCustody(f)
	if !hasCode(ws, CredNotRootOwned) {
		t.Errorf("user-owned cred file should flag CredNotRootOwned, got %v", ws)
	}
	if !AgentAccessible(CredNotRootOwned) {
		t.Error("CredNotRootOwned must be agent-accessible (executor refuses)")
	}

	// Mode 0644 → readable beyond owner.
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	if ws := AuditCredCustody(f); !hasCode(ws, CredModeTooOpen) {
		t.Errorf("0644 cred file should flag CredModeTooOpen, got %v", ws)
	}
}
