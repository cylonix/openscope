// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package passport models an ephemeral, attenuated delegation that lets an
// external agent run a SCOPED subset of an issuer's verbs against the local
// host through the outbound reflector tunnel.
//
// The design corrects the ERD's "bearer authority" framing: a passport can
// only NARROW an issuer's existing, root-owned policy grant, never widen it.
// Two consequences run through this package:
//
//   - The authority lives in the daemon's in-memory session (Issuer + Scope),
//     not in the bytes handed to the external agent. The Handle (the wire form)
//     carries only the public surface the external client needs and never the
//     Issuer principal.
//   - Scope.Permits is a deny-only overlay the daemon evaluates INSIDE its
//     request chokepoint, in addition to (never instead of) policy.Evaluate run
//     under the issuer principal. Even a buggy Permits cannot exceed the
//     issuer's standing authority.
//
// The package is pure: no I/O, no randomness, no clock. Session ids, key
// material, and timestamps are supplied by callers (the reflector package and
// the daemon), so it is fully table-testable.
package passport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/openscope/openscope/capabilities"
)

// Principal is the issuer identity every reflected request executes as. It is
// authoritative (policy.Evaluate runs against it) and is never serialized into
// the relay-visible Handle.
type Principal struct {
	Agent  string   `json:"agent"`
	User   string   `json:"user,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Passport is the in-memory delegation record the daemon holds for a session's
// lifetime. Sanctioned reuses capabilities.Capability verbatim: it is a SUBSET
// of capabilities.Build(Issuer, ...).Capabilities, so a passport adds nothing
// the issuer doesn't already have — it only removes.
type Passport struct {
	ID         string // "osp_<random>"; supplied by the caller
	IssuerOrg  string // display only
	Issuer     Principal
	External   string // advisory external-agent id; audit/display only
	RelayURL   string
	ValidUntil time.Time
	Sanctioned []capabilities.Capability

	// Recipient is the registered external identity the session is bound to:
	// the X25519 public key `--to <alias>` resolved to. Empty only in explicit
	// --bearer mode. The connect secret is sealed to this key by the reflector
	// crypto layer; passport itself stays free of crypto.
	Recipient []byte
}

// Handle is the public, relay-visible projection of a session: exactly what the
// external client needs to connect, verify the daemon, and project its tool
// surface — and nothing the issuer would not want a blind relay to see. It
// deliberately omits the Issuer principal. The reflector layer fills the crypto
// fields; this package keeps it as pure data.
type Handle struct {
	ID           string                    `json:"id"`
	RelayURL     string                    `json:"relay"`
	RendezvousID string                    `json:"rendezvous"`
	ValidUntil   time.Time                 `json:"valid_until"`
	Sanctioned   []capabilities.Capability `json:"sanctioned"`

	// Daemon authentication material. DaemonEphPub is the per-session X25519 key
	// the client runs ECDH against; it is signed (DaemonEphPubSig, Ed25519 over
	// DaemonEphPub‖RendezvousID) by the long-term identity DaemonIDPub, whose
	// SHA-256 is the out-of-band-pinned DaemonFingerprint. Signing the ephemeral
	// key is what lets the pinned fingerprint protect it.
	DaemonEphPub      []byte `json:"daemon_eph_pub"`
	DaemonIDPub       []byte `json:"daemon_id_pub"`
	DaemonEphPubSig   []byte `json:"daemon_eph_pub_sig"`
	DaemonFingerprint string `json:"daemon_fingerprint"`

	// SealedSecret is the session connect secret sealed to the recipient's
	// registered key. Empty in --bearer mode (the secret travels out of band).
	SealedSecret []byte `json:"sealed_secret,omitempty"`
}

// VerifyPin enforces the out-of-band daemon fingerprint before a client trusts
// a handle. When a pin is supplied it must equal the handle's fingerprint. When
// none is supplied, a SEALED handle is rejected: its connect secret is sealed to
// the recipient's PUBLIC key, which an attacker who tampers with handle delivery
// can also seal to, so the seal does not authenticate the issuer's daemon — only
// the pinned fingerprint does. An unsealed (bearer) handle carries an
// out-of-band connect secret that authenticates the peer, so a pin is optional
// there (still checked when given). The fingerprint printed in the sealed-error
// is the UNTRUSTED value from the handle; obtain the real one from the issuer.
func (h Handle) VerifyPin(pin string) error {
	if pin != "" {
		if h.DaemonFingerprint != pin {
			return fmt.Errorf("daemon fingerprint mismatch: handle says %s, you pinned %s", h.DaemonFingerprint, pin)
		}
		return nil
	}
	if len(h.SealedSecret) > 0 {
		return fmt.Errorf("sealed passport requires --pin-fingerprint: the seal uses your public key and does not authenticate the issuer's daemon; confirm the fingerprint with the issuer over a separate channel (handle claims %s, do not trust this value)", h.DaemonFingerprint)
	}
	return nil
}

// Fingerprint is the pinned daemon identity: "sha256:" + hex(SHA256(ed25519Pub)).
// It is the ERD's target_identity_fingerprint, conveyed out-of-band and pinned
// by the external client.
func Fingerprint(ed25519Pub []byte) string {
	if len(ed25519Pub) == 0 {
		return ""
	}
	sum := sha256.Sum256(ed25519Pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Expired reports whether the passport is no longer valid at now. A zero
// ValidUntil is treated as already expired (fail-closed).
func (p Passport) Expired(now time.Time) bool {
	return p.ValidUntil.IsZero() || !now.Before(p.ValidUntil)
}
