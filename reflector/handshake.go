// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"crypto/ecdh"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
)

// The handshake is a two-message exchange over FrameHandshake frames:
//
//	HS1  client → daemon : { role:"client", eph_pub, nonce }
//	HS2  daemon → client : { role:"daemon", nonce, confirm_mac }
//
// The daemon's ephemeral public key reached the client out-of-band in the signed
// passport handle, and the connect secret reached it sealed to its registered
// key — so two messages suffice for a mutually-authenticated, forward-secret
// channel.

// clientPending holds initiator state between sending HS1 and receiving HS2.
type clientPending struct {
	eEphPriv      *ecdh.PrivateKey
	nC            []byte
	dEphPub       []byte
	rendezvousID  string
	connectSecret []byte
}

// clientHandshakeStart generates the client ephemeral + nonce and returns the
// HS1 frame to send. dEphPub and connectSecret come from the passport handle
// (connectSecret after unsealing with the recipient's private key).
func clientHandshakeStart(dEphPub []byte, rendezvousID string, connectSecret []byte, rand io.Reader) (clientPending, Frame, error) {
	eEph, err := generateX25519(rand)
	if err != nil {
		return clientPending{}, Frame{}, err
	}
	nC := make([]byte, 16)
	if _, err := io.ReadFull(rand, nC); err != nil {
		return clientPending{}, Frame{}, err
	}
	hs1, err := handshakeMsg{Role: "client", EphPub: eEph.PublicKey().Bytes(), Nonce: nC}.frame()
	if err != nil {
		return clientPending{}, Frame{}, err
	}
	return clientPending{eEphPriv: eEph, nC: nC, dEphPub: dEphPub, rendezvousID: rendezvousID, connectSecret: connectSecret}, hs1, nil
}

// finish consumes HS2, verifies the daemon key-confirmation, and returns the
// established session. A failed confirmation means the relay paired the client
// to a daemon that does not hold the pinned key — abort.
func (p clientPending) finish(hs2 handshakeMsg) (*aeadSession, error) {
	if hs2.Role != "daemon" || len(hs2.Nonce) == 0 {
		return nil, errors.New("reflector: malformed HS2")
	}
	dEphPub, err := parseX25519Pub(p.dEphPub)
	if err != nil {
		return nil, fmt.Errorf("reflector: bad daemon key: %w", err)
	}
	z, err := p.eEphPriv.ECDH(dEphPub)
	if err != nil {
		return nil, fmt.Errorf("reflector: client ecdh: %w", err)
	}
	d, err := deriveKeys(z, p.rendezvousID, p.dEphPub, p.eEphPriv.PublicKey().Bytes(), p.nC, hs2.Nonce, p.connectSecret)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(d.confirmMAC, hs2.ConfirmMAC) {
		return nil, errors.New("reflector: daemon key-confirmation failed (wrong daemon or tampered relay)")
	}
	return newSession(d, dirClientToDaemon)
}

// daemonHandshake consumes HS1 (the client's first frame) and returns the
// established session plus the HS2 frame to send back.
func daemonHandshake(dEphPriv *ecdh.PrivateKey, rendezvousID string, connectSecret []byte, hs1 handshakeMsg, rand io.Reader) (*aeadSession, Frame, error) {
	if hs1.Role != "client" || len(hs1.EphPub) == 0 || len(hs1.Nonce) == 0 {
		return nil, Frame{}, errors.New("reflector: malformed HS1")
	}
	eEphPub, err := parseX25519Pub(hs1.EphPub)
	if err != nil {
		return nil, Frame{}, fmt.Errorf("reflector: bad client key: %w", err)
	}
	z, err := dEphPriv.ECDH(eEphPub)
	if err != nil {
		return nil, Frame{}, fmt.Errorf("reflector: daemon ecdh: %w", err)
	}
	nD := make([]byte, 16)
	if _, err := io.ReadFull(rand, nD); err != nil {
		return nil, Frame{}, err
	}
	d, err := deriveKeys(z, rendezvousID, dEphPriv.PublicKey().Bytes(), hs1.EphPub, hs1.Nonce, nD, connectSecret)
	if err != nil {
		return nil, Frame{}, err
	}
	hs2, err := handshakeMsg{Role: "daemon", Nonce: nD, ConfirmMAC: d.confirmMAC}.frame()
	if err != nil {
		return nil, Frame{}, err
	}
	sess, err := newSession(d, dirDaemonToClient)
	if err != nil {
		return nil, Frame{}, err
	}
	return sess, hs2, nil
}
