// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSealRoundTrip(t *testing.T) {
	recipient, err := generateX25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("32-byte-connect-secret-aaaaaaaaa")
	sealed, err := sealToRecipient(recipient.PublicKey().Bytes(), secret, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unsealFromRecipient(recipient, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("unseal mismatch: %q", got)
	}

	// A different recipient cannot unseal.
	other, _ := generateX25519(rand.Reader)
	if _, err := unsealFromRecipient(other, sealed); err == nil {
		t.Fatal("expected unseal to fail for the wrong recipient")
	}
}

func TestHandshakeAndChannel(t *testing.T) {
	// Daemon per-session ephemeral; its public half ships in the passport handle.
	dEph, err := generateX25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rendezvous := "rdv_test123"
	connectSecret := make([]byte, 32)
	if _, err := rand.Read(connectSecret); err != nil {
		t.Fatal(err)
	}

	// Client starts (HS1), daemon responds (HS2), client finishes.
	pending, hs1Frame, err := clientHandshakeStart(dEph.PublicKey().Bytes(), rendezvous, connectSecret, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hs1, err := decodeHandshake(hs1Frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	daemonSess, hs2Frame, err := daemonHandshake(dEph, rendezvous, connectSecret, hs1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hs2, err := decodeHandshake(hs2Frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	clientSess, err := pending.finish(hs2)
	if err != nil {
		t.Fatal(err)
	}

	// Client → daemon.
	for range 3 {
		msg := []byte("request frame")
		rec, err := clientSess.Seal(msg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := daemonSess.Open(rec)
		if err != nil {
			t.Fatalf("daemon open: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("c2d mismatch: %q", got)
		}
	}

	// Daemon → client.
	resp := []byte("response frame")
	rec, err := daemonSess.Seal(resp)
	if err != nil {
		t.Fatal(err)
	}
	got, err := clientSess.Open(rec)
	if err != nil {
		t.Fatalf("client open: %v", err)
	}
	if !bytes.Equal(got, resp) {
		t.Fatalf("d2c mismatch: %q", got)
	}

	// Replay of a prior client record must be rejected by the daemon.
	replay, _ := clientSess.Seal([]byte("x"))
	if _, err := daemonSess.Open(replay); err != nil {
		t.Fatalf("fresh record should open: %v", err)
	}
	if _, err := daemonSess.Open(replay); err == nil {
		t.Fatal("replayed record must be rejected")
	}

	// A cross-direction record (daemon's own outbound) must not Open on the
	// daemon's receive side — the AAD direction byte differs.
	d2c, _ := daemonSess.Seal([]byte("y"))
	if _, err := daemonSess.Open(d2c); err == nil {
		t.Fatal("daemon must not be able to open its own outbound record")
	}
}

func TestHandshakeWrongDaemonFailsConfirm(t *testing.T) {
	realDaemon, _ := generateX25519(rand.Reader)
	attacker, _ := generateX25519(rand.Reader)
	rendezvous := "rdv_x"
	secret := make([]byte, 32)

	// Client pins realDaemon's key (from the handle) and sends HS1.
	pending, hs1Frame, err := clientHandshakeStart(realDaemon.PublicKey().Bytes(), rendezvous, secret, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hs1, _ := decodeHandshake(hs1Frame.Payload)

	// A relay splices in `attacker`, which answers HS2 with its own key. Its
	// ECDH differs from what the client computes against realDaemon's key, so it
	// cannot forge the confirm MAC the client expects.
	_, hs2Frame, err := daemonHandshake(attacker, rendezvous, secret, hs1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hs2, _ := decodeHandshake(hs2Frame.Payload)
	if _, err := pending.finish(hs2); err == nil {
		t.Fatal("key-confirmation must fail when the daemon key does not match the pinned passport key")
	}
}
