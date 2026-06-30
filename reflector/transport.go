// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"context"
	"errors"
	"time"
)

// Transport is the daemon's leg of the relay: it registers a session, then
// exchanges opaque frames with the paired external leg. The relay is a blind
// byte-pump — it forwards frames it cannot read. Satisfied by httpMailbox (the
// long-poll HTTP client) and by an in-memory fake in tests.
type Transport interface {
	// CreateSession registers the daemon leg and returns the rendezvous id the
	// external client connects with.
	CreateSession(ctx context.Context, req SessionRequest) (rendezvousID string, err error)
	// Fetch blocks (long-poll) for the next inbound frame from the external leg.
	// It returns ErrSessionClosed when the relay session has ended.
	Fetch(ctx context.Context, rendezvousID string) (Frame, error)
	// Send delivers an outbound frame to the external leg.
	Send(ctx context.Context, rendezvousID string, f Frame) error
	// CloseSession tears the relay session down.
	CloseSession(ctx context.Context, rendezvousID string) error
}

// SessionRequest is what the daemon posts to register a relay session.
type SessionRequest struct {
	// DaemonEphemeralPub is published so the relay (and metadata observers) can
	// correlate, but it carries no secret — the channel keys derive from it plus
	// the client ephemeral the relay never sees in usable form.
	DaemonEphemeralPub []byte
	TTL                time.Duration
}

// ErrSessionClosed is returned by Fetch when the relay session has ended (TTL,
// teardown, or peer disconnect) so the daemon serve loop exits cleanly.
var ErrSessionClosed = errors.New("reflector: relay session closed")
