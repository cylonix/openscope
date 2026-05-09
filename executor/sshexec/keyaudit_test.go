// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
)

func TestAuditWarnsNoIdentityFile(t *testing.T) {
	warnings := AuditKeyProtection(admin.SSHTarget{Alias: "prod"}, "/home/user")
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if warnings[0].Level != "warning" {
		t.Fatalf("expected warning level, got %q", warnings[0].Level)
	}
	if !strings.Contains(warnings[0].Message, "no identity_file") {
		t.Fatalf("unexpected message: %s", warnings[0].Message)
	}
}

func TestAuditCriticalKeyInDotSSH(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	warnings := AuditKeyProtection(admin.SSHTarget{
		Alias:        "prod",
		IdentityFile: keyPath,
	}, home)

	if !hasCritical(warnings) {
		t.Fatalf("expected critical warning for key in ~/.ssh/, got %v", warnings)
	}
}

func TestAuditCriticalKeyInDotSSHViaTilde(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	warnings := AuditKeyProtection(admin.SSHTarget{
		Alias:        "prod",
		IdentityFile: "~/.ssh/id_ed25519",
	}, home)

	if !hasCritical(warnings) {
		t.Fatalf("expected critical warning for ~/. ssh/ key, got %v", warnings)
	}
}

func TestAuditCriticalWeakFileMode(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "prod_key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}

	warnings := AuditKeyProtection(admin.SSHTarget{
		Alias:        "prod",
		IdentityFile: keyPath,
	}, "/nonexistent-home")

	if !hasCritical(warnings) {
		t.Fatalf("expected critical warning for mode 0644, got %v", warnings)
	}
}

func TestAuditWarnsWeakDirMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "prod_key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	warnings := AuditKeyProtection(admin.SSHTarget{
		Alias:        "prod",
		IdentityFile: keyPath,
	}, "/nonexistent-home")

	hasDirWarning := false
	for _, w := range warnings {
		if strings.Contains(w.Message, "directory") && strings.Contains(w.Message, "0755") {
			hasDirWarning = true
		}
	}
	if !hasDirWarning {
		t.Fatalf("expected directory permission warning, got %v", warnings)
	}
}

func TestAuditNoCriticalForProtectedKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "prod_key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	warnings := AuditKeyProtection(admin.SSHTarget{
		Alias:        "prod",
		IdentityFile: keyPath,
	}, "/nonexistent-home")

	for _, w := range warnings {
		if w.Level == "critical" {
			t.Fatalf("unexpected critical warning: %s", w.Message)
		}
	}
}

func TestAuditWarnsKeyNotExist(t *testing.T) {
	warnings := AuditKeyProtection(admin.SSHTarget{
		Alias:        "prod",
		IdentityFile: "/var/openscope/ssh/missing_key",
	}, "/nonexistent-home")

	if len(warnings) == 0 {
		t.Fatal("expected warning for missing key file")
	}
	if !strings.Contains(warnings[0].Message, "does not exist") {
		t.Fatalf("unexpected message: %s", warnings[0].Message)
	}
}

func TestAuditCriticalSymlinkIntoDotSSH(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realKey := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(realKey, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	protectedDir := t.TempDir()
	linkPath := filepath.Join(protectedDir, "prod_key")
	if err := os.Symlink(realKey, linkPath); err != nil {
		t.Fatal(err)
	}

	warnings := AuditKeyProtection(admin.SSHTarget{
		Alias:        "prod",
		IdentityFile: linkPath,
	}, home)

	if !hasCritical(warnings) {
		t.Fatalf("expected critical warning for symlink into ~/.ssh/, got %v", warnings)
	}
}

func hasCritical(warnings []KeyWarning) bool {
	for _, w := range warnings {
		if w.Level == "critical" {
			return true
		}
	}
	return false
}
