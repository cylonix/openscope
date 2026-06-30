// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openscope/openscope/passport"
)

// LoadOrCreateIdentity returns the daemon's long-term Ed25519 identity, creating
// and persisting it (mode 0600) at path on first use. The SHA-256 of the public
// half is the fingerprint external clients pin out of band, so the key must be
// stable across restarts and protected from the agent (root-owned AdminDir).
func LoadOrCreateIdentity(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		seed, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("reflector: malformed identity file %s", path)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	case os.IsNotExist(err):
		// create below
	default:
		return nil, fmt.Errorf("reflector: read identity: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("reflector: create identity dir: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(priv.Seed())
	if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("reflector: write identity: %w", err)
	}
	return priv, nil
}

// IdentityFingerprint returns the pinned fingerprint of an identity key.
func IdentityFingerprint(priv ed25519.PrivateKey) string {
	return passport.Fingerprint(priv.Public().(ed25519.PublicKey))
}

// LoadOrCreateRecipientIdentity returns the external agent's (vendor-B's)
// long-term X25519 identity, creating and persisting it (mode 0600) at path on
// first use. Its public half is what the issuer registers as a contact and seals
// the per-session connect secret to.
func LoadOrCreateRecipientIdentity(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		seed, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil {
			return nil, fmt.Errorf("reflector: malformed recipient identity %s", path)
		}
		return ecdh.X25519().NewPrivateKey(seed)
	case os.IsNotExist(err):
		// create below
	default:
		return nil, fmt.Errorf("reflector: read recipient identity: %w", err)
	}

	priv, err := generateX25519(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("reflector: create recipient identity dir: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(priv.Bytes())
	if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("reflector: write recipient identity: %w", err)
	}
	return priv, nil
}
