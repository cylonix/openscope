// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package reflector is the daemon side of the cross-org outbound tunnel: it
// dials OUT to a blind relay, runs an end-to-end encrypted handshake with an
// external agent through that relay, and feeds the agent's scoped requests into
// the daemon's normal request chokepoint under the issuer's attenuated identity.
//
// Everything here is stdlib-only (net/http, crypto/ecdh, crypto/hkdf,
// crypto/aes, crypto/ed25519, crypto/hmac), so the package can be imported by
// openscoped, which lives in the yaml.v3-only root module.
//
// Layers (bottom to top): frame (this file, the relay-visible envelope) →
// crypto (the E2E handshake + AEAD session) → mailbox (the long-poll HTTP
// transport to the relay) → manager/session (daemon-side lifecycle).
package reflector

import (
	"encoding/json"
	"fmt"

	"github.com/openscope/openscope/ipc"
)

// Frame is the outer, relay-visible envelope. The relay forwards DATA and
// HANDSHAKE frames between the two paired legs verbatim and never inspects the
// payload — DATA payloads are AEAD ciphertext it has no key for, and HANDSHAKE
// payloads carry only public ephemeral keys and nonces.
type Frame struct {
	Type    byte
	Payload []byte
}

const (
	// FrameHandshake carries a cleartext handshakeMsg (public values only),
	// exchanged before the AEAD channel exists.
	FrameHandshake byte = 1
	// FrameData carries one AEAD record whose plaintext is a Message.
	FrameData byte = 2
	// FrameClose signals teardown; Payload[0] is an advisory reason code.
	FrameClose byte = 3
)

// Encode serializes a frame to the relay wire form: a single type byte followed
// by the opaque payload. The relay (and the mailbox transport) treat the result
// as one indivisible message, so no length prefix is needed.
func (f Frame) Encode() []byte {
	out := make([]byte, 0, len(f.Payload)+1)
	out = append(out, f.Type)
	return append(out, f.Payload...)
}

// DecodeFrame parses a frame produced by Encode.
func DecodeFrame(b []byte) (Frame, error) {
	if len(b) == 0 {
		return Frame{}, fmt.Errorf("reflector: empty frame")
	}
	return Frame{Type: b[0], Payload: b[1:]}, nil
}

// Message is the inner, end-to-end-encrypted application payload (the plaintext
// of a FrameData record). It reuses ipc.Request/ipc.Response verbatim so the
// reflected call is identical to a local one.
type Message struct {
	T    string        `json:"t"`            // "req" | "resp" | "bye"
	ID   string        `json:"id,omitempty"` // correlation id (request ↔ response)
	Req  *ipc.Request  `json:"req,omitempty"`
	Resp *ipc.Response `json:"resp,omitempty"`
}

func (m Message) encode() ([]byte, error) { return json.Marshal(m) }

func decodeMessage(b []byte) (Message, error) {
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return Message{}, fmt.Errorf("reflector: decode message: %w", err)
	}
	return m, nil
}

// handshakeMsg is the cleartext handshake payload (FrameHandshake). It carries
// only public material; binding to the recipient identity and key confirmation
// happen through the derived keys, not these bytes.
type handshakeMsg struct {
	Role       string `json:"role"` // "client" | "daemon"
	EphPub     []byte `json:"eph_pub,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	ConfirmMAC []byte `json:"confirm_mac,omitempty"`
}

func (h handshakeMsg) frame() (Frame, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return Frame{}, fmt.Errorf("reflector: encode handshake: %w", err)
	}
	return Frame{Type: FrameHandshake, Payload: b}, nil
}

func decodeHandshake(b []byte) (handshakeMsg, error) {
	var h handshakeMsg
	if err := json.Unmarshal(b, &h); err != nil {
		return handshakeMsg{}, fmt.Errorf("reflector: decode handshake: %w", err)
	}
	return h, nil
}
