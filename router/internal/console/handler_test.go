// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoleSwitchRouteGatedByFlag(t *testing.T) {
	// Self-service role switch is a self-elevation path (into the vendor
	// "engineer" persona that sees cross-tenant data). It must not be mounted
	// unless explicitly enabled for the throwaway-tenant demo.
	req := httptest.NewRequest("POST", "/api/v1/session/switch", nil)

	off := http.NewServeMux()
	(&Server{AllowRoleSwitch: false}).Routes(off)
	if _, pat := off.Handler(req); pat != "" {
		t.Errorf("role-switch route must not be mounted when disabled, matched %q", pat)
	}

	on := http.NewServeMux()
	(&Server{AllowRoleSwitch: true}).Routes(on)
	if _, pat := on.Handler(req); pat == "" {
		t.Error("role-switch route should be mounted when enabled")
	}
}

func TestHandleSwitchRoleRefusesWhenDisabled(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/session/switch", strings.NewReader(`{"role":"engineer"}`))
	(&Server{AllowRoleSwitch: false}).handleSwitchRole(rec, req, Session{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (self-elevation must be refused when disabled)", rec.Code)
	}
}
