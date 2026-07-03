// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package serverconfig

import "testing"

// The router and console must refuse to boot on the publicly-known dev auth
// pepper unless OPENSCOPE_DEV is explicitly set — a known pepper lets anyone
// forge at-rest token hashes.
func TestLoadRejectsDevPepperOutsideDevMode(t *testing.T) {
	// Unset the pepper so Load falls back to DevPepperPlaceholder; ensure dev
	// mode is off. t.Setenv restores both after the test.
	t.Setenv("OPENSCOPE_AUTH_PEPPER", "")
	t.Setenv("OPENSCOPE_DEV", "")

	if _, err := Load(); err == nil {
		t.Fatal("expected Load to reject the dev placeholder pepper without OPENSCOPE_DEV")
	}
}

func TestLoadAllowsDevPepperInDevMode(t *testing.T) {
	t.Setenv("OPENSCOPE_AUTH_PEPPER", "")
	t.Setenv("OPENSCOPE_DEV", "1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("dev mode should permit the placeholder pepper: %v", err)
	}
	if !cfg.IsDevPepper() {
		t.Fatalf("expected the dev placeholder pepper, got %q", cfg.AuthPepper)
	}
}

func TestLoadAcceptsRealPepper(t *testing.T) {
	t.Setenv("OPENSCOPE_AUTH_PEPPER", "a-real-32-plus-byte-production-pepper-value")
	t.Setenv("OPENSCOPE_DEV", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("a real pepper should be accepted without dev mode: %v", err)
	}
	if cfg.IsDevPepper() {
		t.Fatal("real pepper should not report as the dev placeholder")
	}
}
