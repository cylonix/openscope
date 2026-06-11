// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package authtoken implements the shared osk_* API token scheme used across
// OpenScope: router API keys, broker agent tokens, and control-plane
// deployment tokens.
//
// Token shape:  osk_<kind>_<22-char-url-safe-base64-of-16-bytes>
// Storage:      HMAC-SHA256(pepper, token) — never the token itself
// Lookup:       prefix-indexed (first 12 chars), constant-time hmac.Equal
//
// Why HMAC-SHA256 not argon2: tokens carry 128 bits of entropy in the
// suffix — brute force is infeasible regardless of hash function. The hash
// protects against rainbow tables and exact-match dumps of the store. HMAC
// + pepper is fast (microseconds), simple, and equally secure for this
// threat model.
package authtoken

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// PrefixLen is the indexable prefix size — first 12 chars of an osk_* token.
// Stored verbatim alongside the hash for fast candidate lookup.
const PrefixLen = 12

var ErrBadPepper = errors.New("auth pepper must be non-empty")

// Mint generates a new token of the given kind ("agent", "deploy", or a
// router role such as "developer"), computing its prefix and HMAC hash with
// the given pepper. Returns the full token (show once to the recipient),
// the prefix (stored for indexed lookup), and the hash.
//
// The suffix is 22 url-safe-base64 chars carrying 128 bits of entropy from
// 16 random bytes.
func Mint(kind string, pepper []byte) (token, prefix string, hash []byte, err error) {
	if err := validateKind(kind); err != nil {
		return "", "", nil, err
	}
	if len(pepper) == 0 {
		return "", "", nil, ErrBadPepper
	}
	var b [16]byte
	if _, err = rand.Read(b[:]); err != nil {
		return "", "", nil, fmt.Errorf("rand: %w", err)
	}
	suffix := base64.RawURLEncoding.EncodeToString(b[:])
	token = "osk_" + kind + "_" + suffix
	return token, token[:PrefixLen], HashToken(token, pepper), nil
}

// validateKind rejects kinds that would break the osk_<kind>_<suffix> shape
// or produce a token shorter than PrefixLen.
func validateKind(kind string) error {
	if kind == "" {
		return errors.New("token kind must be non-empty")
	}
	for _, r := range kind {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return fmt.Errorf("invalid token kind %q (want lowercase letters, digits, hyphens)", kind)
		}
	}
	return nil
}

// HashToken computes HMAC-SHA256(pepper, token).
func HashToken(token string, pepper []byte) []byte {
	h := hmac.New(sha256.New, pepper)
	h.Write([]byte(token))
	return h.Sum(nil)
}

// Verify reports whether token hashes to expected under pepper, in constant
// time with respect to the hash comparison.
func Verify(token string, pepper, expected []byte) bool {
	return hmac.Equal(HashToken(token, pepper), expected)
}

// ParseBearer extracts an osk_* token from an Authorization header value.
func ParseBearer(authHeader string) (string, bool) {
	const bearer = "Bearer "
	if !strings.HasPrefix(authHeader, bearer) {
		return "", false
	}
	token := strings.TrimPrefix(authHeader, bearer)
	if !strings.HasPrefix(token, "osk_") || len(token) < PrefixLen {
		return "", false
	}
	return token, true
}
