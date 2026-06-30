// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openscope/openscope/capabilities"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/passport"
)

// fakeRelay is an in-memory blind byte-pump: two queues per session, paired by
// rendezvous id. The Manager drives the daemon leg via the Transport interface;
// the test drives the external leg via the ext* helpers.
type fakeRelay struct {
	mu       sync.Mutex
	sessions map[string]*fakeSession
	n        int
}

type fakeSession struct {
	toDaemon   chan Frame
	toExternal chan Frame
	closed     chan struct{}
	once       sync.Once
}

func newFakeRelay() *fakeRelay { return &fakeRelay{sessions: map[string]*fakeSession{}} }

func (r *fakeRelay) CreateSession(_ context.Context, _ SessionRequest) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	id := fmt.Sprintf("rdv_%d", r.n)
	r.sessions[id] = &fakeSession{
		toDaemon:   make(chan Frame, 16),
		toExternal: make(chan Frame, 16),
		closed:     make(chan struct{}),
	}
	return id, nil
}

func (r *fakeRelay) get(id string) *fakeSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id]
}

func (r *fakeRelay) Fetch(ctx context.Context, id string) (Frame, error) {
	s := r.get(id)
	if s == nil {
		return Frame{}, ErrSessionClosed
	}
	select {
	case f := <-s.toDaemon:
		return f, nil
	case <-s.closed:
		return Frame{}, ErrSessionClosed
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	}
}

func (r *fakeRelay) Send(_ context.Context, id string, f Frame) error {
	s := r.get(id)
	if s == nil {
		return ErrSessionClosed
	}
	s.toExternal <- f
	return nil
}

func (r *fakeRelay) CloseSession(_ context.Context, id string) error {
	if s := r.get(id); s != nil {
		s.once.Do(func() { close(s.closed) })
	}
	return nil
}

// external-leg helpers (the test plays the vendor-B side).
func (r *fakeRelay) extSend(id string, f Frame) { r.get(id).toDaemon <- f }
func (r *fakeRelay) extFetch(t *testing.T, id string) Frame {
	t.Helper()
	select {
	case f := <-r.get(id).toExternal:
		return f
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a frame from the daemon")
		return Frame{}
	}
}

func TestManagerReflectsRequestEndToEnd(t *testing.T) {
	relay := newFakeRelay()
	_, identity, _ := ed25519.GenerateKey(rand.Reader)

	dispatched := make(chan ipc.Request, 1)
	dispatch := func(sess *Session, req ipc.Request) ipc.Response {
		dispatched <- req
		return ipc.Response{OK: true, App: req.App, Action: req.Action, Agent: sess.Issuer.Agent,
			Data: "ran as " + sess.Issuer.Agent}
	}
	mgr := NewManager(relay, identity, "relay://test", dispatch, Options{})

	// vendor-B's registered recipient identity.
	recipient, _ := generateX25519(rand.Reader)

	p := passport.Passport{
		Issuer:   passport.Principal{Agent: "dev-a"},
		External: "vendor-b",
		Sanctioned: []capabilities.Capability{{App: "ssh", Action: "tail_logs",
			Params: []capabilities.Param{{Name: "service", PolicyKey: "service", Pinned: true, Fixed: "web"}}}},
		Recipient: recipient.PublicKey().Bytes(),
	}
	scope := passport.NewScope(p.Sanctioned)

	handleStr, fragment, err := mgr.Open(p, scope, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if fragment != nil {
		t.Fatal("recipient-bound session must not return a bearer fragment")
	}

	h, err := passport.DecodeHandle(handleStr)
	if err != nil {
		t.Fatal(err)
	}

	// The external client verifies the daemon: fingerprint pin + ephemeral-key
	// signature chain to the long-term identity.
	if h.DaemonFingerprint != passport.Fingerprint(h.DaemonIDPub) {
		t.Fatal("fingerprint does not match the identity key in the handle")
	}
	if !ed25519.Verify(ed25519.PublicKey(h.DaemonIDPub), ephSigMessage(h.DaemonEphPub, h.RendezvousID), h.DaemonEphPubSig) {
		t.Fatal("daemon ephemeral-key signature failed to verify")
	}

	// Unseal the connect secret with vendor-B's private key, then handshake.
	secret, err := unsealFromRecipient(recipient, h.SealedSecret)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	pending, hs1, err := clientHandshakeStart(h.DaemonEphPub, h.RendezvousID, secret, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relay.extSend(h.RendezvousID, hs1)
	clientSess, err := pending.finish(mustDecodeHS(t, relay.extFetch(t, h.RendezvousID)))
	if err != nil {
		t.Fatalf("client handshake finish: %v", err)
	}

	// Send a request frame and read the reflected response.
	reqMsg, _ := Message{T: "req", ID: "1", Req: &ipc.Request{App: "ssh", Action: "tail_logs",
		Params: map[string]string{"service": "web"}}}.encode()
	rec, _ := clientSess.Seal(reqMsg)
	relay.extSend(h.RendezvousID, Frame{Type: FrameData, Payload: rec})

	respFrame := relay.extFetch(t, h.RendezvousID)
	pt, err := clientSess.Open(respFrame.Payload)
	if err != nil {
		t.Fatalf("open response: %v", err)
	}
	respMsg, err := decodeMessage(pt)
	if err != nil {
		t.Fatal(err)
	}
	if respMsg.T != "resp" || respMsg.ID != "1" || respMsg.Resp == nil || !respMsg.Resp.OK {
		t.Fatalf("unexpected response message: %+v", respMsg)
	}
	if respMsg.Resp.Agent != "dev-a" {
		t.Fatalf("reflected request must run as the issuer dev-a, got agent %q", respMsg.Resp.Agent)
	}

	// The dispatch saw the request.
	select {
	case got := <-dispatched:
		if got.Params["service"] != "web" {
			t.Fatalf("dispatch saw wrong params: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatch was never called")
	}

	// Revoke: the session disappears and its relay leg closes. The id was
	// assigned inside Open, so recover it from List.
	live := mgr.List()
	if len(live) != 1 {
		t.Fatalf("expected 1 live session, got %d", len(live))
	}
	if live[0].Issuer != "dev-a" {
		t.Fatalf("List should report the issuer, got %q", live[0].Issuer)
	}
	if !mgr.Close(live[0].ID) {
		t.Fatal("Close returned false for a live session")
	}
	deadline := time.Now().Add(time.Second)
	for len(mgr.List()) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(mgr.List()); got != 0 {
		t.Fatalf("expected 0 live sessions after close, got %d", got)
	}
}

func TestManagerBearerModeReturnsFragment(t *testing.T) {
	relay := newFakeRelay()
	_, identity, _ := ed25519.GenerateKey(rand.Reader)
	mgr := NewManager(relay, identity, "relay://test", func(*Session, ipc.Request) ipc.Response {
		return ipc.Response{OK: true}
	}, Options{})

	p := passport.Passport{Issuer: passport.Principal{Agent: "dev-a"}} // no Recipient → bearer
	_, fragment, err := mgr.Open(p, passport.NewScope(nil), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragment) != 32 {
		t.Fatalf("bearer mode must return the 32-byte connect secret, got %d bytes", len(fragment))
	}
}

func TestManagerMaxSessions(t *testing.T) {
	relay := newFakeRelay()
	_, identity, _ := ed25519.GenerateKey(rand.Reader)
	mgr := NewManager(relay, identity, "relay://test", func(*Session, ipc.Request) ipc.Response {
		return ipc.Response{}
	}, Options{MaxSessions: 1})

	if _, _, err := mgr.Open(passport.Passport{Issuer: passport.Principal{Agent: "a"}}, passport.NewScope(nil), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mgr.Open(passport.Passport{Issuer: passport.Principal{Agent: "b"}}, passport.NewScope(nil), time.Minute); err == nil {
		t.Fatal("expected max-sessions rejection on the second open")
	}
}

func mustDecodeHS(t *testing.T, f Frame) handshakeMsg {
	t.Helper()
	hs, err := decodeHandshake(f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return hs
}
