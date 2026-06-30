// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/passport"
)

// DispatchFunc executes a reflected request and returns its response. The daemon
// supplies one that overwrites the request identity with sess.Issuer and runs
// the request through Service.HandleWithMeta with the session's attenuation.
type DispatchFunc func(sess *Session, req ipc.Request) ipc.Response

// Options tunes a Manager. Zero values are filled with safe defaults.
type Options struct {
	MaxSessions int       // default 4
	Rand        io.Reader // default crypto/rand.Reader
	Now         func() time.Time
	MaxFrame    int // max accepted inbound frame payload bytes (default 1 MiB)
}

// Manager owns the daemon's live reflector sessions. It holds no accept loop:
// sessions are dialed on demand (Open, driven by the local control IPC), each
// with its own long-poll serve goroutine.
type Manager struct {
	transport Transport
	identity  ed25519.PrivateKey // long-term daemon identity; signs per-session ephemeral keys
	relayURL  string
	dispatch  DispatchFunc
	opts      Options

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewManager constructs a Manager. identity is the daemon's long-term Ed25519
// key (its SHA-256 fingerprint is what external clients pin). transport is the
// relay leg (httpMailbox in production).
func NewManager(transport Transport, identity ed25519.PrivateKey, relayURL string, dispatch DispatchFunc, opts Options) *Manager {
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 4
	}
	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxFrame <= 0 {
		opts.MaxFrame = 1 << 20
	}
	return &Manager{transport: transport, identity: identity, relayURL: relayURL, dispatch: dispatch, opts: opts, sessions: map[string]*Session{}}
}

var errTooManySessions = errors.New("reflector: max concurrent sessions reached")

// Open registers a session with the relay and returns the encoded passport
// handle for the external agent. In --bearer mode (p.Recipient empty) the
// connect secret cannot be sealed, so it is returned as fragmentSecret for the
// caller to convey out of band; otherwise fragmentSecret is nil.
func (m *Manager) Open(p passport.Passport, scope passport.Scope, ttl time.Duration) (handle string, fragmentSecret []byte, err error) {
	m.mu.Lock()
	if len(m.sessions) >= m.opts.MaxSessions {
		m.mu.Unlock()
		return "", nil, errTooManySessions
	}
	m.mu.Unlock()

	dEph, err := generateX25519(m.opts.Rand)
	if err != nil {
		return "", nil, err
	}
	connectSecret := make([]byte, 32)
	if _, err := io.ReadFull(m.opts.Rand, connectSecret); err != nil {
		return "", nil, err
	}

	var sealed []byte
	if len(p.Recipient) > 0 {
		if sealed, err = sealToRecipient(p.Recipient, connectSecret, m.opts.Rand); err != nil {
			return "", nil, err
		}
	} else {
		fragmentSecret = connectSecret // bearer mode
	}

	if p.ID == "" {
		p.ID = randomID("osp_", m.opts.Rand)
	}
	validUntil := m.opts.Now().Add(ttl)

	ctx, cancel := context.WithTimeout(context.Background(), ttl)
	rdv, err := m.transport.CreateSession(ctx, SessionRequest{DaemonEphemeralPub: dEph.PublicKey().Bytes(), TTL: ttl})
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("reflector: create relay session: %w", err)
	}

	idPub := m.identity.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(m.identity, ephSigMessage(dEph.PublicKey().Bytes(), rdv))
	h := passport.Handle{
		ID:                p.ID,
		RelayURL:          m.relayURL,
		RendezvousID:      rdv,
		ValidUntil:        validUntil,
		Sanctioned:        p.Sanctioned,
		DaemonEphPub:      dEph.PublicKey().Bytes(),
		DaemonIDPub:       idPub,
		DaemonEphPubSig:   sig,
		DaemonFingerprint: passport.Fingerprint(idPub),
		SealedSecret:      sealed,
	}
	encoded, err := passport.EncodeHandle(h)
	if err != nil {
		cancel()
		return "", nil, err
	}

	sess := &Session{
		ID:            p.ID,
		External:      p.External,
		Issuer:        p.Issuer,
		ValidUntil:    validUntil,
		rendezvousID:  rdv,
		dEphPriv:      dEph,
		connectSecret: connectSecret,
		ctx:           ctx,
		cancel:        cancel,
		scope:         scope,
	}
	m.mu.Lock()
	m.sessions[p.ID] = sess
	m.mu.Unlock()

	go m.serve(sess)
	return encoded, fragmentSecret, nil
}

// serve is the per-session long-poll loop: complete the handshake on the first
// frame, then decrypt requests, dispatch them, and encrypt responses back, until
// the session ends (TTL, close, or relay disconnect).
func (m *Manager) serve(sess *Session) {
	defer m.teardown(sess)
	for {
		if sess.ctx.Err() != nil {
			return
		}
		f, err := m.transport.Fetch(sess.ctx, sess.rendezvousID)
		if err != nil {
			return // ErrSessionClosed, ctx cancel, or transport error → tear down
		}
		if len(f.Payload) > m.opts.MaxFrame {
			continue // oversized; drop
		}
		switch f.Type {
		case FrameHandshake:
			m.handleHandshake(sess, f)
		case FrameData:
			m.handleData(sess, f)
		case FrameClose:
			return
		}
	}
}

func (m *Manager) handleHandshake(sess *Session, f Frame) {
	if sess.channel() != nil {
		return // already established; ignore duplicate HS1
	}
	hs1, err := decodeHandshake(f.Payload)
	if err != nil {
		return
	}
	aead, hs2, err := daemonHandshake(sess.dEphPriv, sess.rendezvousID, sess.connectSecret, hs1, m.opts.Rand)
	if err != nil {
		return
	}
	if err := m.transport.Send(sess.ctx, sess.rendezvousID, hs2); err != nil {
		return
	}
	sess.setChannel(aead)
}

func (m *Manager) handleData(sess *Session, f Frame) {
	ch := sess.channel()
	if ch == nil {
		return // data before handshake; ignore
	}
	pt, err := ch.Open(f.Payload)
	if err != nil {
		return // bad record; drop (do not tear down on a single bad frame)
	}
	msg, err := decodeMessage(pt)
	if err != nil || msg.T != "req" || msg.Req == nil {
		return
	}
	resp := m.dispatch(sess, *msg.Req)
	out, err := Message{T: "resp", ID: msg.ID, Resp: &resp}.encode()
	if err != nil {
		return
	}
	rec, err := ch.Seal(out)
	if err != nil {
		return
	}
	_ = m.transport.Send(sess.ctx, sess.rendezvousID, Frame{Type: FrameData, Payload: rec})
}

func (m *Manager) teardown(sess *Session) {
	sess.cancel()
	m.mu.Lock()
	delete(m.sessions, sess.ID)
	m.mu.Unlock()
	_ = m.transport.CloseSession(context.Background(), sess.rendezvousID)
}

// Close revokes a session immediately. Returns false if no such session.
func (m *Manager) Close(id string) bool {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return false
	}
	sess.cancel() // serve loop will observe ctx cancel and teardown
	return true
}

// Extend replaces a live session's attenuation (share extend within the
// issuer's scope). Returns false if no such session.
func (m *Manager) Extend(id string, scope passport.Scope) bool {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return false
	}
	sess.setScope(scope)
	return true
}

// List returns the live sessions for `share list`.
func (m *Manager) List() []SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, SessionInfo{ID: s.ID, External: s.External, Issuer: s.Issuer.Agent, ValidUntil: s.ValidUntil})
	}
	return out
}

// ephSigMessage is the message the daemon signs to bind its per-session
// ephemeral key to its long-term identity.
func ephSigMessage(ephPub []byte, rendezvousID string) []byte {
	msg := make([]byte, 0, len(ephPub)+len(rendezvousID))
	msg = append(msg, ephPub...)
	return append(msg, []byte(rendezvousID)...)
}

func randomID(prefix string, r io.Reader) string {
	b := make([]byte, 8)
	_, _ = io.ReadFull(r, b)
	return prefix + hex.EncodeToString(b)
}
