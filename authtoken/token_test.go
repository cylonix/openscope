// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package authtoken

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden vectors computed independently (openssl dgst -sha256 -hmac).
// They pin the hash scheme: changing HashToken breaks every minted token.
func TestHashTokenGoldenVectors(t *testing.T) {
	cases := []struct {
		token  string
		pepper string
		want   string
	}{
		{
			token:  "osk_agent_AAAAAAAAAAAAAAAAAAAAAA",
			pepper: "test-pepper",
			want:   "ed06da666cfbcce6e838fe8d71ace86832ee7438cdad0eb9d9d056ca9b1826d1",
		},
		{
			token:  "osk_developer_h2DTbnVxIc1z9PIa64qC3A",
			pepper: "pepper-2",
			want:   "23fe2c333aa4eb3bc5c3360af09bb84cf41f267aa503ace0e79782c0942a7f80",
		},
	}
	for _, tc := range cases {
		got := hex.EncodeToString(HashToken(tc.token, []byte(tc.pepper)))
		if got != tc.want {
			t.Errorf("HashToken(%q, %q) = %s, want %s", tc.token, tc.pepper, got, tc.want)
		}
	}
}

func TestMintShape(t *testing.T) {
	token, prefix, hash, err := Mint("agent", []byte("pepper"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(token, "osk_agent_") {
		t.Errorf("token = %q, want osk_agent_ prefix", token)
	}
	if len(token) != len("osk_agent_")+22 {
		t.Errorf("token length = %d, want %d", len(token), len("osk_agent_")+22)
	}
	if prefix != token[:PrefixLen] {
		t.Errorf("prefix = %q, want %q", prefix, token[:PrefixLen])
	}
	if !Verify(token, []byte("pepper"), hash) {
		t.Error("minted token does not verify against its own hash")
	}
	if Verify(token, []byte("wrong"), hash) {
		t.Error("token verifies under wrong pepper")
	}
}

func TestMintRejectsBadInput(t *testing.T) {
	if _, _, _, err := Mint("agent", nil); err == nil {
		t.Error("Mint with empty pepper succeeded")
	}
	for _, kind := range []string{"", "Agent", "has_underscore", "spaced kind"} {
		if _, _, _, err := Mint(kind, []byte("p")); err == nil {
			t.Errorf("Mint(%q) succeeded, want error", kind)
		}
	}
}

func TestParseBearer(t *testing.T) {
	token, ok := ParseBearer("Bearer osk_agent_AAAAAAAAAAAAAAAAAAAAAA")
	if !ok || token != "osk_agent_AAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("ParseBearer = (%q, %v)", token, ok)
	}
	for _, header := range []string{
		"",
		"osk_agent_AAAAAAAAAAAAAAAAAAAAAA", // no Bearer
		"Bearer ",
		"Bearer not-an-osk-token",
		"Bearer osk_a", // shorter than PrefixLen
		"Basic osk_agent_AAAAAAAAAAAAAAAAAAAAAA",
	} {
		if _, ok := ParseBearer(header); ok {
			t.Errorf("ParseBearer(%q) accepted, want reject", header)
		}
	}
}

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	return &FileStore{
		Path:   filepath.Join(t.TempDir(), "agent_tokens.yaml"),
		Pepper: []byte("test-pepper"),
	}
}

func TestFileStoreMintResolveRoundtrip(t *testing.T) {
	s := newTestStore(t)
	token, err := s.Mint("ci-runner-1", false)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	agent, err := s.Resolve(token)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if agent != "ci-runner-1" {
		t.Errorf("Resolve = %q, want ci-runner-1", agent)
	}

	info, err := os.Stat(s.Path)
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("store file mode = %o, want 600", perm)
	}
	if data, _ := os.ReadFile(s.Path); strings.Contains(string(data), token) {
		t.Error("store file contains the raw token")
	}
}

func TestFileStoreWrongPepperFails(t *testing.T) {
	s := newTestStore(t)
	token, err := s.Mint("agent-a", false)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	bad := &FileStore{Path: s.Path, Pepper: []byte("other-pepper")}
	if _, err := bad.Resolve(token); err == nil {
		t.Error("Resolve with wrong pepper succeeded")
	}
}

func TestFileStoreDuplicateAndRotate(t *testing.T) {
	s := newTestStore(t)
	first, err := s.Mint("agent-a", false)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := s.Mint("agent-a", false); err == nil {
		t.Error("second active mint for same agent succeeded, want ErrTokenExists")
	}
	second, err := s.Mint("agent-a", true)
	if err != nil {
		t.Fatalf("rotate mint: %v", err)
	}
	if _, err := s.Resolve(first); err == nil {
		t.Error("rotated-away token still resolves")
	}
	if agent, err := s.Resolve(second); err != nil || agent != "agent-a" {
		t.Errorf("Resolve(second) = (%q, %v)", agent, err)
	}
}

func TestFileStoreRevoke(t *testing.T) {
	s := newTestStore(t)
	token, err := s.Mint("agent-a", false)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	n, err := s.Revoke("agent-a")
	if err != nil || n != 1 {
		t.Fatalf("Revoke = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := s.Resolve(token); err == nil {
		t.Error("revoked token still resolves")
	}
	// Revoking by prefix on an already-revoked row is a no-op.
	if n, err := s.Revoke(token[:PrefixLen]); err != nil || n != 0 {
		t.Errorf("second Revoke = (%d, %v), want (0, nil)", n, err)
	}
}

// All agent tokens share the literal prefix "osk_agent_" plus two suffix
// chars, so distinct agents can collide on the 12-char prefix. Resolve must
// compare hashes across all candidates.
func TestFileStorePrefixCollision(t *testing.T) {
	s := newTestStore(t)
	tokens := map[string]string{}
	// Mint until two tokens share a prefix (12 chars = "osk_agent_" + 2
	// base64url chars, 4096 combos; 80 mints ≈ 54% collision odds, retry
	// loop makes it deterministic enough in practice).
	for i := range 500 {
		agent := "agent-" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
		tok, err := s.Mint(agent, false)
		if err != nil {
			t.Fatalf("Mint #%d: %v", i, err)
		}
		tokens[agent] = tok
		// Stop early once a collision exists.
		seen := map[string]int{}
		collided := false
		for _, tk := range tokens {
			seen[tk[:PrefixLen]]++
			if seen[tk[:PrefixLen]] > 1 {
				collided = true
			}
		}
		if collided {
			break
		}
	}
	for agent, tok := range tokens {
		got, err := s.Resolve(tok)
		if err != nil || got != agent {
			t.Fatalf("Resolve(%s token) = (%q, %v)", agent, got, err)
		}
	}
}

func TestLoadPepper(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token_pepper")

	// Env wins.
	p, err := LoadPepper("from-env", file)
	if err != nil || string(p) != "from-env" {
		t.Fatalf("LoadPepper(env) = (%q, %v)", p, err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Error("pepper file created despite env value")
	}

	// First call generates, second call reads the same value.
	p1, err := LoadPepper("", file)
	if err != nil {
		t.Fatalf("LoadPepper generate: %v", err)
	}
	p2, err := LoadPepper("", file)
	if err != nil || string(p1) != string(p2) {
		t.Fatalf("LoadPepper reread = (%q, %v), want %q", p2, err, p1)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat pepper: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("pepper file mode = %o, want 600", perm)
	}
}

func TestFileStoreMintWithUserAndProxy(t *testing.T) {
	s := newTestStore(t)

	// Per-user token: a bound subject travels with the token.
	userTok, err := s.MintWith(MintOptions{Agent: "ci", User: "ci@corp"})
	if err != nil {
		t.Fatalf("MintWith user: %v", err)
	}
	res, err := s.ResolveFull(userTok)
	if err != nil {
		t.Fatalf("ResolveFull user: %v", err)
	}
	if res.Agent != "ci" || res.User != "ci@corp" || res.TrustedProxy {
		t.Fatalf("ResolveFull = %+v, want agent=ci user=ci@corp proxy=false", res)
	}

	// Trusted-proxy token: capability flag is set, no bound user.
	proxyTok, err := s.MintWith(MintOptions{Agent: "sso-proxy", TrustedProxy: true})
	if err != nil {
		t.Fatalf("MintWith proxy: %v", err)
	}
	res, err = s.ResolveFull(proxyTok)
	if err != nil {
		t.Fatalf("ResolveFull proxy: %v", err)
	}
	if res.Agent != "sso-proxy" || !res.TrustedProxy || res.User != "" {
		t.Fatalf("ResolveFull = %+v, want agent=sso-proxy proxy=true user empty", res)
	}

	// Plain Mint stays a plain agent token (no user, no proxy capability).
	plain, err := s.Mint("agent-x", false)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	res, err = s.ResolveFull(plain)
	if err != nil {
		t.Fatalf("ResolveFull plain: %v", err)
	}
	if res.User != "" || res.TrustedProxy {
		t.Fatalf("plain token carried identity it should not: %+v", res)
	}
}
