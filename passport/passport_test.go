// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package passport

import (
	"testing"
	"time"

	"github.com/openscope/openscope/capabilities"
)

// cap is a tiny fixture builder.
func cap(app, action string, params ...capabilities.Param) capabilities.Capability {
	return capabilities.Capability{App: app, Action: action, Params: params}
}

func free(name string) capabilities.Param {
	return capabilities.Param{Name: name, PolicyKey: name}
}

func pinned(name, fixed string) capabilities.Param {
	return capabilities.Param{Name: name, PolicyKey: name, Pinned: true, Fixed: fixed}
}

func allowed(name string, vals ...string) capabilities.Param {
	return capabilities.Param{Name: name, PolicyKey: name, AllowedValues: vals}
}

func TestScopePermits(t *testing.T) {
	tests := []struct {
		name   string
		caps   []capabilities.Capability
		app    string
		action string
		ctx    map[string]string
		wantOK bool
	}{
		{
			name: "verb not sanctioned",
			caps: []capabilities.Capability{cap("ssh", "tail_logs", free("target"))},
			app:  "ssh", action: "restart_service",
			ctx:    map[string]string{"target": "staging"},
			wantOK: false,
		},
		{
			name: "free param permits any value",
			caps: []capabilities.Capability{cap("ssh", "tail_logs", free("target"))},
			app:  "ssh", action: "tail_logs",
			ctx:    map[string]string{"target": "anything"},
			wantOK: true,
		},
		{
			name: "pinned param matches",
			caps: []capabilities.Capability{cap("ssh", "restart_service", pinned("service", "billing"))},
			app:  "ssh", action: "restart_service",
			ctx:    map[string]string{"service": "billing"},
			wantOK: true,
		},
		{
			name: "pinned param mismatch denied",
			caps: []capabilities.Capability{cap("ssh", "restart_service", pinned("service", "billing"))},
			app:  "ssh", action: "restart_service",
			ctx:    map[string]string{"service": "auth"},
			wantOK: false,
		},
		{
			name: "allowed-values member permitted",
			caps: []capabilities.Capability{cap("ssh", "restart_service", allowed("service", "billing", "auth"))},
			app:  "ssh", action: "restart_service",
			ctx:    map[string]string{"service": "auth"},
			wantOK: true,
		},
		{
			name: "allowed-values non-member denied",
			caps: []capabilities.Capability{cap("ssh", "restart_service", allowed("service", "billing", "auth"))},
			app:  "ssh", action: "restart_service",
			ctx:    map[string]string{"service": "payments"},
			wantOK: false,
		},
		{
			name: "allowed-values absent value permitted (left to required/policy)",
			caps: []capabilities.Capability{cap("ssh", "restart_service", allowed("service", "billing"))},
			app:  "ssh", action: "restart_service",
			ctx:    map[string]string{},
			wantOK: true,
		},
		{
			name: "union over multiple rules for one verb",
			caps: []capabilities.Capability{
				cap("ssh", "restart_service", pinned("service", "billing")),
				cap("ssh", "restart_service", pinned("service", "auth")),
			},
			app: "ssh", action: "restart_service",
			ctx:    map[string]string{"service": "auth"},
			wantOK: true,
		},
		{
			name: "union: value in neither rule denied",
			caps: []capabilities.Capability{
				cap("ssh", "restart_service", pinned("service", "billing")),
				cap("ssh", "restart_service", pinned("service", "auth")),
			},
			app: "ssh", action: "restart_service",
			ctx:    map[string]string{"service": "payments"},
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScope(tt.caps)
			ok, reason := s.Permits(tt.app, tt.action, tt.ctx)
			if ok != tt.wantOK {
				t.Fatalf("Permits = %v (%q), want %v", ok, reason, tt.wantOK)
			}
			if !ok && reason == "" {
				t.Fatalf("deny must carry a reason")
			}
		})
	}
}

func TestSubset(t *testing.T) {
	tests := []struct {
		name      string
		requested []capabilities.Capability
		surface   []capabilities.Capability
		wantOK    bool
	}{
		{
			name:      "verb not in surface",
			requested: []capabilities.Capability{cap("system", "manage_packages", free("package"))},
			surface:   []capabilities.Capability{cap("ssh", "tail_logs", free("target"))},
			wantOK:    false,
		},
		{
			name:      "free requested, free issuer",
			requested: []capabilities.Capability{cap("ssh", "tail_logs", free("target"))},
			surface:   []capabilities.Capability{cap("ssh", "tail_logs", free("target"))},
			wantOK:    true,
		},
		{
			name:      "pin requested within issuer allow-set",
			requested: []capabilities.Capability{cap("ssh", "restart_service", pinned("service", "billing"))},
			surface:   []capabilities.Capability{cap("ssh", "restart_service", allowed("service", "billing", "auth"))},
			wantOK:    true,
		},
		{
			name:      "pin requested outside issuer allow-set",
			requested: []capabilities.Capability{cap("ssh", "restart_service", pinned("service", "payments"))},
			surface:   []capabilities.Capability{cap("ssh", "restart_service", allowed("service", "billing", "auth"))},
			wantOK:    false,
		},
		{
			name:      "allow-set requested subset of issuer allow-set",
			requested: []capabilities.Capability{cap("ssh", "restart_service", allowed("service", "billing"))},
			surface:   []capabilities.Capability{cap("ssh", "restart_service", allowed("service", "billing", "auth"))},
			wantOK:    true,
		},
		{
			name:      "allow-set requested not subset",
			requested: []capabilities.Capability{cap("ssh", "restart_service", allowed("service", "billing", "x"))},
			surface:   []capabilities.Capability{cap("ssh", "restart_service", allowed("service", "billing", "auth"))},
			wantOK:    false,
		},
		{
			name:      "free requested but issuer pinned is broader → reject",
			requested: []capabilities.Capability{cap("ssh", "restart_service", free("service"))},
			surface:   []capabilities.Capability{cap("ssh", "restart_service", pinned("service", "billing"))},
			wantOK:    false,
		},
		{
			name:      "issuer free covers any pin",
			requested: []capabilities.Capability{cap("ssh", "restart_service", pinned("service", "anything"))},
			surface:   []capabilities.Capability{cap("ssh", "restart_service", free("service"))},
			wantOK:    true,
		},
		{
			name:      "covered by one of several issuer rules for same verb",
			requested: []capabilities.Capability{cap("ssh", "restart_service", pinned("service", "auth"))},
			surface: []capabilities.Capability{
				cap("ssh", "restart_service", pinned("service", "billing")),
				cap("ssh", "restart_service", pinned("service", "auth")),
			},
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := Subset(tt.requested, tt.surface)
			if ok != tt.wantOK {
				t.Fatalf("Subset = %v (%q), want %v", ok, reason, tt.wantOK)
			}
			if !ok && reason == "" {
				t.Fatalf("deny must carry a reason")
			}
		})
	}
}

func TestHandleRoundTrip(t *testing.T) {
	h := Handle{
		ID:                "osp_abc123",
		RelayURL:          "https://relay.openscopeai.com",
		RendezvousID:      "rdv_xyz",
		ValidUntil:        time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC),
		Sanctioned:        []capabilities.Capability{cap("ssh", "tail_logs", free("target"))},
		DaemonEphPub:      []byte{1, 2, 3, 4},
		DaemonIDPub:       []byte("daemon-id-pub"),
		DaemonEphPubSig:   []byte{9, 8, 7},
		DaemonFingerprint: Fingerprint([]byte("daemon-id-pub")),
	}

	enc, err := EncodeHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeHandle(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != h.ID || got.RendezvousID != "rdv_xyz" || got.RelayURL != h.RelayURL {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if len(got.Sanctioned) != 1 || got.Sanctioned[0].Action != "tail_logs" {
		t.Fatalf("sanctioned caps lost in round-trip: %+v", got.Sanctioned)
	}
	if got.DaemonFingerprint != Fingerprint([]byte("daemon-id-pub")) {
		t.Fatalf("fingerprint mismatch: %q", got.DaemonFingerprint)
	}
	if got.DaemonFingerprint == "" || got.DaemonFingerprint[:7] != "sha256:" {
		t.Fatalf("fingerprint shape: %q", got.DaemonFingerprint)
	}
}

func TestExpired(t *testing.T) {
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	if !(Passport{}).Expired(now) {
		t.Fatal("zero ValidUntil must be expired (fail-closed)")
	}
	if (Passport{ValidUntil: now.Add(time.Minute)}).Expired(now) {
		t.Fatal("future ValidUntil must not be expired")
	}
	if !(Passport{ValidUntil: now.Add(-time.Minute)}).Expired(now) {
		t.Fatal("past ValidUntil must be expired")
	}
}

func TestHandleVerifyPin(t *testing.T) {
	const fp = "sha256:abc123"
	sealed := Handle{DaemonFingerprint: fp, SealedSecret: []byte("x")}
	bearer := Handle{DaemonFingerprint: fp}

	// A sealed handle is authenticated only by the out-of-band fingerprint (the
	// seal uses the recipient's public key), so it must be rejected without a pin.
	if err := sealed.VerifyPin(""); err == nil {
		t.Error("sealed handle must require a pin")
	}
	if err := sealed.VerifyPin(fp); err != nil {
		t.Errorf("sealed handle with matching pin should pass: %v", err)
	}
	if err := sealed.VerifyPin("sha256:wrong"); err == nil {
		t.Error("wrong pin must be rejected")
	}

	// A bearer (unsealed) handle carries an out-of-band connect secret that
	// authenticates the peer, so a pin is optional but still checked when given.
	if err := bearer.VerifyPin(""); err != nil {
		t.Errorf("bearer handle without a pin should pass: %v", err)
	}
	if err := bearer.VerifyPin(fp); err != nil {
		t.Errorf("bearer handle with matching pin should pass: %v", err)
	}
	if err := bearer.VerifyPin("sha256:wrong"); err == nil {
		t.Error("bearer handle with mismatched pin must be rejected")
	}
}
