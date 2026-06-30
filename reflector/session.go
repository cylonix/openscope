// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"context"
	"crypto/ecdh"
	"sync"
	"time"

	"github.com/openscope/openscope/passport"
)

// Session is one live delegation. The authority is held here, in daemon memory:
// Issuer is the principal every reflected request runs as, and scope is the
// attenuation it must also satisfy. Tearing the session down (TTL, revoke,
// disconnect) drops this struct — no policy file is ever mutated, so revocation
// is instant and total.
//
// Issuer/ID/External are immutable after Open and exported for the daemon's
// dispatch + audit. scope is mutable (share extend) and read through Scope().
type Session struct {
	ID         string             // "osp_..." management id (share list / revoke)
	External   string             // advisory delegatee id (audit only)
	Issuer     passport.Principal // authoritative run-as principal
	ValidUntil time.Time

	rendezvousID  string
	dEphPriv      *ecdh.PrivateKey
	connectSecret []byte
	ctx           context.Context
	cancel        context.CancelFunc

	mu    sync.Mutex
	scope passport.Scope
	aead  *aeadSession
}

// Scope returns the session's current attenuation. Safe for concurrent use with
// setScope (share extend).
func (s *Session) Scope() passport.Scope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scope
}

func (s *Session) setScope(sc passport.Scope) {
	s.mu.Lock()
	s.scope = sc
	s.mu.Unlock()
}

func (s *Session) channel() *aeadSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aead
}

func (s *Session) setChannel(a *aeadSession) {
	s.mu.Lock()
	s.aead = a
	s.mu.Unlock()
}

// SessionInfo is the read-only projection returned by Manager.List.
type SessionInfo struct {
	ID         string
	External   string
	Issuer     string
	ValidUntil time.Time
}
