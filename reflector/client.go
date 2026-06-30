// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/passport"
)

// ExternalClient is the vendor-B side of the tunnel: it connects to the relay as
// the external leg, authenticates the daemon, runs the E2E handshake, and
// exposes Call to forward a scoped request and await its response. All crypto
// stays inside this package; the reflect-client binary only orchestrates.
type ExternalClient struct {
	mb   *httpMailbox
	rdv  string
	sess *aeadSession

	mu  sync.Mutex // serializes one request/response at a time
	ctr int
}

// Connect dials the relay described by the handle, verifies the daemon's
// identity (fingerprint pin + ephemeral-key signature), establishes the E2E
// channel, and returns a ready client.
//
// recipientPriv is vendor-B's registered X25519 identity, used to unseal the
// connect secret. For a --bearer handle (no SealedSecret), pass bearerSecret and
// a nil recipientPriv.
func Connect(ctx context.Context, h passport.Handle, recipientPriv *ecdh.PrivateKey, bearerSecret []byte) (*ExternalClient, error) {
	if len(h.DaemonIDPub) != ed25519.PublicKeySize {
		return nil, errors.New("reflector: handle missing daemon identity key")
	}
	if h.DaemonFingerprint != passport.Fingerprint(h.DaemonIDPub) {
		return nil, errors.New("reflector: handle fingerprint does not match its identity key")
	}
	if !ed25519.Verify(ed25519.PublicKey(h.DaemonIDPub), ephSigMessage(h.DaemonEphPub, h.RendezvousID), h.DaemonEphPubSig) {
		return nil, errors.New("reflector: daemon ephemeral-key signature is invalid (untrusted relay or tampered handle)")
	}

	secret, err := resolveConnectSecret(h, recipientPriv, bearerSecret)
	if err != nil {
		return nil, err
	}

	mb := newExternalMailbox(h.RelayURL)
	pending, hs1, err := clientHandshakeStart(h.DaemonEphPub, h.RendezvousID, secret, rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := mb.Send(ctx, h.RendezvousID, hs1); err != nil {
		return nil, fmt.Errorf("reflector: send handshake: %w", err)
	}
	hs2Frame, err := mb.Fetch(ctx, h.RendezvousID)
	if err != nil {
		return nil, fmt.Errorf("reflector: await handshake: %w", err)
	}
	if hs2Frame.Type != FrameHandshake {
		return nil, errors.New("reflector: expected a handshake response")
	}
	hs2, err := decodeHandshake(hs2Frame.Payload)
	if err != nil {
		return nil, err
	}
	sess, err := pending.finish(hs2)
	if err != nil {
		return nil, err
	}
	return &ExternalClient{mb: mb, rdv: h.RendezvousID, sess: sess}, nil
}

func resolveConnectSecret(h passport.Handle, recipientPriv *ecdh.PrivateKey, bearerSecret []byte) ([]byte, error) {
	if len(h.SealedSecret) > 0 {
		if recipientPriv == nil {
			return nil, errors.New("reflector: handle is sealed to a recipient key — run with the recipient identity (`keygen` output registered with the issuer)")
		}
		secret, err := unsealFromRecipient(recipientPriv, h.SealedSecret)
		if err != nil {
			return nil, fmt.Errorf("reflector: cannot unseal handle (wrong recipient key?): %w", err)
		}
		return secret, nil
	}
	if len(bearerSecret) == 0 {
		return nil, errors.New("reflector: bearer handle requires --secret")
	}
	return bearerSecret, nil
}

// Call forwards one reflected request and returns the daemon's response. Calls
// are serialized: one request/response is in flight at a time, which keeps the
// AEAD counters monotonic and the correlation simple.
func (c *ExternalClient) Call(ctx context.Context, req ipc.Request) (ipc.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ctr++
	id := fmt.Sprintf("c-%d", c.ctr)
	msg, err := Message{T: "req", ID: id, Req: &req}.encode()
	if err != nil {
		return ipc.Response{}, err
	}
	rec, err := c.sess.Seal(msg)
	if err != nil {
		return ipc.Response{}, err
	}
	if err := c.mb.Send(ctx, c.rdv, Frame{Type: FrameData, Payload: rec}); err != nil {
		return ipc.Response{}, err
	}
	for {
		f, err := c.mb.Fetch(ctx, c.rdv)
		if err != nil {
			return ipc.Response{}, err
		}
		if f.Type != FrameData {
			continue
		}
		pt, err := c.sess.Open(f.Payload)
		if err != nil {
			continue // not yet our frame / undecryptable; keep waiting
		}
		m, err := decodeMessage(pt)
		if err != nil {
			continue
		}
		if m.T == "resp" && m.ID == id && m.Resp != nil {
			return *m.Resp, nil
		}
	}
}

// Rendezvous returns the relay session id (for diagnostics).
func (c *ExternalClient) Rendezvous() string { return c.rdv }
