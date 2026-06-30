// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
)

// The end-to-end channel between the daemon and the external agent rides DATA
// frames through the blind relay. Construction (all stdlib):
//
//   - X25519 ephemeral-ephemeral ECDH for forward secrecy.
//   - The session connect secret is sealed to the recipient's REGISTERED static
//     X25519 key (sealToRecipient), so only that recipient can derive the
//     channel: the handle is identity-bound, not bearer. The secret is folded
//     into the transcript, so a matching key-confirmation also authenticates the
//     recipient to the daemon.
//   - HKDF-SHA256 derives per-direction AES-256-GCM keys and 4-byte nonce
//     prefixes; an 8-byte monotonic counter completes each nonce. The transcript
//     hash is bound into every record's AAD (channel binding + replay defense).
//
// A daemon key-confirmation MAC proves the daemon holds the per-session private
// key whose public half is pinned (via the passport fingerprint), defeating a
// relay that tries to splice the client onto a different daemon.

const (
	dirClientToDaemon byte = 'C'
	dirDaemonToClient byte = 'D'

	sealInfo = "openscope-reflect/seal/v1"
)

func x25519() ecdh.Curve { return ecdh.X25519() }

// generateX25519 returns a fresh ephemeral key pair.
func generateX25519(rand io.Reader) (*ecdh.PrivateKey, error) {
	return x25519().GenerateKey(rand)
}

func parseX25519Pub(b []byte) (*ecdh.PublicKey, error) {
	return x25519().NewPublicKey(b)
}

// sealToRecipient seals secret to recipientPub (a 32-byte X25519 key) using an
// ephemeral-static ECDH + AES-256-GCM (ECIES). The output is ephPub(32) ‖
// ciphertext. A zero nonce is safe: the wrap key is unique per call because the
// ephemeral key is.
func sealToRecipient(recipientPub, secret []byte, rand io.Reader) ([]byte, error) {
	pub, err := parseX25519Pub(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("reflector: bad recipient key: %w", err)
	}
	eph, err := generateX25519(rand)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("reflector: seal ecdh: %w", err)
	}
	ephPub := eph.PublicKey().Bytes()
	wrapKey, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephPub...), recipientPub...), sealInfo, 32)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, make([]byte, gcm.NonceSize()), secret, recipientPub)
	return append(ephPub, ct...), nil
}

// unsealFromRecipient reverses sealToRecipient using the recipient's static
// private key.
func unsealFromRecipient(recipientPriv *ecdh.PrivateKey, sealed []byte) ([]byte, error) {
	if len(sealed) < 32 {
		return nil, errors.New("reflector: sealed secret too short")
	}
	ephPub, ct := sealed[:32], sealed[32:]
	eph, err := parseX25519Pub(ephPub)
	if err != nil {
		return nil, fmt.Errorf("reflector: bad seal ephemeral: %w", err)
	}
	shared, err := recipientPriv.ECDH(eph)
	if err != nil {
		return nil, fmt.Errorf("reflector: unseal ecdh: %w", err)
	}
	recipientPub := recipientPriv.PublicKey().Bytes()
	wrapKey, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephPub...), recipientPub...), sealInfo, 32)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, make([]byte, gcm.NonceSize()), ct, recipientPub)
}

// derived holds everything both sides compute identically from the handshake.
type derived struct {
	kC2D, kD2C  []byte
	prefixC2D   []byte
	prefixD2C   []byte
	confirmMAC  []byte // HMAC(kConf, "daemon")
	transcriptH []byte
}

func deriveKeys(z []byte, rendezvousID string, dEphPub, eEphPub, nC, nD, connectSecret []byte) (derived, error) {
	salt := append(append([]byte{}, nC...), nD...)
	prk, err := hkdf.Extract(sha256.New, z, salt)
	if err != nil {
		return derived{}, err
	}

	var t []byte
	t = append(t, []byte("openscope-reflect/v1\x00")...)
	t = append(t, []byte(rendezvousID)...)
	t = append(t, dEphPub...)
	t = append(t, eEphPub...)
	t = append(t, nC...)
	t = append(t, nD...)
	t = append(t, connectSecret...)
	thArr := sha256.Sum256(t)
	th := thArr[:]
	tag := "|" + hex.EncodeToString(th)

	expand := func(label string, n int) ([]byte, error) {
		return hkdf.Expand(sha256.New, prk, label+tag, n)
	}
	kC2D, err := expand("c2d", 32)
	if err != nil {
		return derived{}, err
	}
	kD2C, err := expand("d2c", 32)
	if err != nil {
		return derived{}, err
	}
	kConf, err := expand("confirm", 32)
	if err != nil {
		return derived{}, err
	}
	pC2D, err := expand("nonce-c2d", 4)
	if err != nil {
		return derived{}, err
	}
	pD2C, err := expand("nonce-d2c", 4)
	if err != nil {
		return derived{}, err
	}
	mac := hmac.New(sha256.New, kConf)
	mac.Write([]byte("daemon"))
	return derived{kC2D: kC2D, kD2C: kD2C, prefixC2D: pC2D, prefixD2C: pD2C, confirmMAC: mac.Sum(nil), transcriptH: th}, nil
}

// aeadSession is one end of the established channel. Seal/Open are safe for
// concurrent use; counters are per-direction and strictly increasing.
type aeadSession struct {
	transcriptH []byte

	mu       sync.Mutex
	send     cipher.AEAD
	recv     cipher.AEAD
	sendPref [4]byte
	recvPref [4]byte
	sendDir  byte
	recvDir  byte
	sendCtr  uint64
	recvCtr  uint64
}

func newSession(d derived, role byte) (*aeadSession, error) {
	var sendKey, recvKey []byte
	var sendPref, recvPref []byte
	var sendDir, recvDir byte
	switch role {
	case dirDaemonToClient: // daemon: sends D2C, receives C2D
		sendKey, recvKey = d.kD2C, d.kC2D
		sendPref, recvPref = d.prefixD2C, d.prefixC2D
		sendDir, recvDir = dirDaemonToClient, dirClientToDaemon
	case dirClientToDaemon: // client: sends C2D, receives D2C
		sendKey, recvKey = d.kC2D, d.kD2C
		sendPref, recvPref = d.prefixC2D, d.prefixD2C
		sendDir, recvDir = dirClientToDaemon, dirDaemonToClient
	default:
		return nil, fmt.Errorf("reflector: bad role %q", role)
	}
	sendGCM, err := newGCM(sendKey)
	if err != nil {
		return nil, err
	}
	recvGCM, err := newGCM(recvKey)
	if err != nil {
		return nil, err
	}
	s := &aeadSession{transcriptH: d.transcriptH, send: sendGCM, recv: recvGCM, sendDir: sendDir, recvDir: recvDir}
	copy(s.sendPref[:], sendPref)
	copy(s.recvPref[:], recvPref)
	return s, nil
}

// Seal encrypts plaintext into a record: counter(8 BE) ‖ AES-GCM ciphertext.
func (s *aeadSession) Seal(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctr := s.sendCtr
	s.sendCtr++
	nonce := make([]byte, 12)
	copy(nonce[:4], s.sendPref[:])
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	out := make([]byte, 8, 8+len(plaintext)+s.send.Overhead())
	binary.BigEndian.PutUint64(out, ctr)
	out = s.send.Seal(out, nonce, plaintext, s.aad(s.sendDir, ctr))
	return out, nil
}

// Open decrypts a record, enforcing a strictly increasing receive counter.
func (s *aeadSession) Open(record []byte) ([]byte, error) {
	if len(record) < 8 {
		return nil, errors.New("reflector: short record")
	}
	ctr := binary.BigEndian.Uint64(record[:8])
	nonce := make([]byte, 12)
	copy(nonce[:4], s.recvPref[:])
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	pt, err := s.recv.Open(nil, nonce, record[8:], s.aad(s.recvDir, ctr))
	if err != nil {
		return nil, fmt.Errorf("reflector: open record: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctr < s.recvCtr || (ctr == 0 && s.recvCtr != 0) {
		return nil, errors.New("reflector: replayed or reordered record")
	}
	s.recvCtr = ctr + 1
	return pt, nil
}

func (s *aeadSession) aad(dir byte, ctr uint64) []byte {
	aad := make([]byte, 0, 1+8+len(s.transcriptH))
	aad = append(aad, dir)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], ctr)
	aad = append(aad, c[:]...)
	return append(aad, s.transcriptH...)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("reflector: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("reflector: gcm: %w", err)
	}
	return gcm, nil
}
