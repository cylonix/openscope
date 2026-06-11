// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package authtoken

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FileStore is a YAML-backed token store for daemons that run without a
// database. Each row maps a hashed agent token to an agent ID; the file
// never contains the token itself.
type FileStore struct {
	Path   string
	Pepper []byte
}

type fileStoreDoc struct {
	Version int        `yaml:"version"`
	Tokens  []TokenRow `yaml:"tokens"`
}

type TokenRow struct {
	Agent     string     `yaml:"agent"`
	Prefix    string     `yaml:"prefix"`
	Hash      string     `yaml:"hash"` // base64(HMAC-SHA256(pepper, token))
	CreatedAt time.Time  `yaml:"created_at"`
	RevokedAt *time.Time `yaml:"revoked_at,omitempty"`
}

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExists  = errors.New("agent already has an active token (revoke it or rotate)")
)

func (s *FileStore) load() (fileStoreDoc, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileStoreDoc{Version: 1}, nil
		}
		return fileStoreDoc{}, fmt.Errorf("read token store: %w", err)
	}
	var doc fileStoreDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fileStoreDoc{}, fmt.Errorf("parse token store: %w", err)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return doc, nil
}

func (s *FileStore) save(doc fileStoreDoc) error {
	if doc.Version == 0 {
		doc.Version = 1
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal token store: %w", err)
	}
	if err := os.WriteFile(s.Path, data, 0o600); err != nil {
		return fmt.Errorf("write token store: %w", err)
	}
	return nil
}

// Mint creates a new agent token, stores its hash, and returns the full
// token — the only time it is ever available. If the agent already has an
// active token, Mint fails unless rotate is true, in which case the old
// token is revoked first.
func (s *FileStore) Mint(agentID string, rotate bool) (string, error) {
	if strings.TrimSpace(agentID) == "" {
		return "", errors.New("agent id must be non-empty")
	}
	doc, err := s.load()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	for i := range doc.Tokens {
		row := &doc.Tokens[i]
		if row.Agent == agentID && row.RevokedAt == nil {
			if !rotate {
				return "", ErrTokenExists
			}
			row.RevokedAt = &now
		}
	}
	token, prefix, hash, err := Mint("agent", s.Pepper)
	if err != nil {
		return "", err
	}
	doc.Tokens = append(doc.Tokens, TokenRow{
		Agent:     agentID,
		Prefix:    prefix,
		Hash:      base64.StdEncoding.EncodeToString(hash),
		CreatedAt: now,
	})
	if err := s.save(doc); err != nil {
		return "", err
	}
	return token, nil
}

// Resolve maps a presented token to its agent ID. It compares every
// prefix-matching candidate to keep timing oblivious across the
// {match-on-1st, match-on-Nth, no-match} cases. Revoked rows never match.
func (s *FileStore) Resolve(token string) (string, error) {
	if len(token) < PrefixLen || !strings.HasPrefix(token, "osk_") {
		return "", ErrInvalidToken
	}
	doc, err := s.load()
	if err != nil {
		return "", err
	}
	expected := HashToken(token, s.Pepper)
	prefix := token[:PrefixLen]
	matched := ""
	for _, row := range doc.Tokens {
		if row.Prefix != prefix || row.RevokedAt != nil {
			continue
		}
		hash, err := base64.StdEncoding.DecodeString(row.Hash)
		if err != nil {
			continue
		}
		if hmac.Equal(expected, hash) && matched == "" {
			matched = row.Agent
		}
	}
	if matched == "" {
		return "", ErrInvalidToken
	}
	return matched, nil
}

// Revoke marks all active tokens matching the agent ID or token prefix as
// revoked and reports how many rows changed.
func (s *FileStore) Revoke(agentOrPrefix string) (int, error) {
	doc, err := s.load()
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	revoked := 0
	for i := range doc.Tokens {
		row := &doc.Tokens[i]
		if row.RevokedAt != nil {
			continue
		}
		if row.Agent == agentOrPrefix || row.Prefix == agentOrPrefix {
			row.RevokedAt = &now
			revoked++
		}
	}
	if revoked == 0 {
		return 0, nil
	}
	return revoked, s.save(doc)
}

// List returns all rows (hashes included — callers must not print them).
func (s *FileStore) List() ([]TokenRow, error) {
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	return doc.Tokens, nil
}

// LoadPepper resolves the HMAC pepper: the env value wins if non-empty;
// otherwise the pepper file is read, and created with 32 random bytes
// (base64, mode 0600) on first use. Losing the pepper invalidates every
// token minted with it.
func LoadPepper(envValue, pepperFile string) ([]byte, error) {
	if envValue != "" {
		return []byte(envValue), nil
	}
	data, err := os.ReadFile(pepperFile)
	if err == nil {
		pepper := strings.TrimSpace(string(data))
		if pepper == "" {
			return nil, fmt.Errorf("pepper file %s is empty", pepperFile)
		}
		return []byte(pepper), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read pepper file: %w", err)
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	pepper := base64.StdEncoding.EncodeToString(b[:])
	if err := os.WriteFile(pepperFile, []byte(pepper+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write pepper file: %w", err)
	}
	return []byte(pepper), nil
}
