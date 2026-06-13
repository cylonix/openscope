// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPathsUsesConfigDirOverride(t *testing.T) {
	t.Setenv("OPENSCOPE_CONFIG_DIR", "/tmp/openscope-config-test")
	t.Setenv("OPENSCOPE_SOCKET", "")
	t.Setenv("OPENSCOPE_HTTP_URL", "")
	t.Setenv("OPENSCOPE_HTTP_LISTEN", "")
	t.Setenv("OPENSCOPE_ADMIN_DIR", "")

	paths, err := DefaultPaths()
	if err != nil {
		t.Fatalf("DefaultPaths() error = %v", err)
	}

	if got, want := paths.ConfigDir, "/tmp/openscope-config-test"; got != want {
		t.Fatalf("ConfigDir = %q, want %q", got, want)
	}
	if got, want := paths.SocketPath, filepath.Join("/tmp/openscope-config-test", "run", "openscoped.sock"); got != want {
		t.Fatalf("SocketPath = %q, want %q", got, want)
	}
}

func TestDefaultPathsUsesSocketOverride(t *testing.T) {
	t.Setenv("OPENSCOPE_CONFIG_DIR", "")
	t.Setenv("OPENSCOPE_SOCKET", "/tmp/openscope/run/openscoped.sock")
	t.Setenv("OPENSCOPE_HTTP_URL", "")
	t.Setenv("OPENSCOPE_HTTP_LISTEN", "")
	t.Setenv("OPENSCOPE_ADMIN_DIR", "")

	paths, err := DefaultPaths()
	if err != nil {
		t.Fatalf("DefaultPaths() error = %v", err)
	}

	if got, want := paths.SocketPath, "/tmp/openscope/run/openscoped.sock"; got != want {
		t.Fatalf("SocketPath = %q, want %q", got, want)
	}
}

func TestDefaultPathsUsesHTTPOverrides(t *testing.T) {
	t.Setenv("OPENSCOPE_CONFIG_DIR", "")
	t.Setenv("OPENSCOPE_SOCKET", "")
	t.Setenv("OPENSCOPE_HTTP_URL", "http://127.0.0.1:42357")
	t.Setenv("OPENSCOPE_HTTP_LISTEN", "127.0.0.1:42357")
	t.Setenv("OPENSCOPE_ADMIN_DIR", "")

	paths, err := DefaultPaths()
	if err != nil {
		t.Fatalf("DefaultPaths() error = %v", err)
	}

	if got, want := paths.HTTPURL, "http://127.0.0.1:42357"; got != want {
		t.Fatalf("HTTPURL = %q, want %q", got, want)
	}
	if got, want := paths.HTTPListenAddr, "127.0.0.1:42357"; got != want {
		t.Fatalf("HTTPListenAddr = %q, want %q", got, want)
	}
}

func TestDefaultPathsUsesAdminDirOverride(t *testing.T) {
	t.Setenv("OPENSCOPE_CONFIG_DIR", "")
	t.Setenv("OPENSCOPE_SOCKET", "")
	t.Setenv("OPENSCOPE_HTTP_URL", "")
	t.Setenv("OPENSCOPE_HTTP_LISTEN", "")
	t.Setenv("OPENSCOPE_ADMIN_DIR", "/tmp/openscope-admin")

	paths, err := DefaultPaths()
	if err != nil {
		t.Fatalf("DefaultPaths() error = %v", err)
	}

	if got, want := paths.AdminDir, "/tmp/openscope-admin"; got != want {
		t.Fatalf("AdminDir = %q, want %q", got, want)
	}
	if got, want := paths.ProtectedFoldersFile, filepath.Join("/tmp/openscope-admin", "protected_folders.yaml"); got != want {
		t.Fatalf("ProtectedFoldersFile = %q, want %q", got, want)
	}
	if got, want := paths.MailFiltersFile, filepath.Join("/tmp/openscope-admin", "mail_filters.yaml"); got != want {
		t.Fatalf("MailFiltersFile = %q, want %q", got, want)
	}
	if got, want := paths.HTTPProfilesFile, filepath.Join("/tmp/openscope-admin", "http_profiles.yaml"); got != want {
		t.Fatalf("HTTPProfilesFile = %q, want %q", got, want)
	}
	if got, want := paths.SSHTargetsFile, filepath.Join("/tmp/openscope-admin", "ssh_targets.yaml"); got != want {
		t.Fatalf("SSHTargetsFile = %q, want %q", got, want)
	}
}

func TestEnsureLayoutCreatesOverrideDirs(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, "mounted-config")
	t.Setenv("OPENSCOPE_CONFIG_DIR", configDir)
	t.Setenv("OPENSCOPE_SOCKET", "")

	paths, err := DefaultPaths()
	if err != nil {
		t.Fatalf("DefaultPaths() error = %v", err)
	}
	if err := EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}

	for _, dir := range []string{paths.ConfigDir, paths.AppsDir, paths.RunDir, paths.StateDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat(%q) error = %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("%q is not a directory", dir)
		}
	}
}

func TestChooseSocketPath(t *testing.T) {
	const sys = SystemSocketPath
	user := "/home/u/.openscope/run/openscoped.sock"

	// Explicit env override always wins.
	if got := chooseSocketPath("/tmp/x.sock", user, true); got != "/tmp/x.sock" {
		t.Errorf("env override: got %q", got)
	}
	// No env, a system socket present → use it (CLI finds a running root daemon).
	if got := chooseSocketPath("", user, true); got != sys {
		t.Errorf("system present: got %q, want %q", got, sys)
	}
	// No env, no system socket → per-user socket.
	if got := chooseSocketPath("", user, false); got != user {
		t.Errorf("fallback: got %q, want %q", got, user)
	}
}

func TestAuditFilePath(t *testing.T) {
	const admin = "/Library/Application Support/OpenScope"
	cfg := "/home/u/.openscope"
	// Root-daemon deployment → root-owned audit in the admin dir.
	if got := auditFilePath(true, admin, cfg); got != admin+"/audit.jsonl" {
		t.Errorf("system mode: got %q", got)
	}
	// Per-user deployment → audit in the user config dir (the non-root daemon appends).
	if got := auditFilePath(false, admin, cfg); got != cfg+"/audit.jsonl" {
		t.Errorf("per-user: got %q", got)
	}
}
