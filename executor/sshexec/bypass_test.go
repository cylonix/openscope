// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/executor"
)

func TestDiscoverUserKeys(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A private key with a .pub sibling (discovered), plus noise that must not be.
	for _, f := range []string{"id_ed25519", "id_ed25519.pub", "known_hosts", "config"} {
		if err := os.WriteFile(filepath.Join(sshDir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keys := DiscoverUserKeys(home)
	if len(keys) != 1 || filepath.Base(keys[0]) != "id_ed25519" {
		t.Fatalf("expected only id_ed25519, got %v", keys)
	}
	// A .pub with no private sibling yields nothing.
	if err := os.WriteFile(filepath.Join(sshDir, "orphan.pub"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DiscoverUserKeys(home); len(got) != 1 {
		t.Errorf("orphan .pub should be ignored, got %v", got)
	}
	if got := DiscoverUserKeys(""); got != nil {
		t.Errorf("empty home should yield no keys, got %v", got)
	}
}

// fakeRunner returns a fixed result for every ssh invocation and records the
// last args it saw.
type fakeRunner struct {
	res      executor.Result
	err      error
	lastArgs []string
}

func (f *fakeRunner) Run(name string, args []string, stdin io.Reader) (executor.Result, error) {
	f.lastArgs = args
	return f.res, f.err
}

func TestProbeBypassClassifies(t *testing.T) {
	target := admin.SSHTarget{Alias: "prod", Host: "p.example.com", User: "deploy", Port: 2222}
	keys := []string{"/home/u/.ssh/id_ed25519"}

	cases := []struct {
		name string
		res  executor.Result
		want string
	}{
		{"auth ok is bypass", executor.Result{ExitCode: 0}, BypassFound},
		{"permission denied is clear", executor.Result{ExitCode: 255, Stderr: "Permission denied (publickey)."}, BypassClear},
		{"timeout is inconclusive", executor.Result{ExitCode: 255, Stderr: "ssh: connect to host p.example.com port 2222: Operation timed out"}, BypassUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fr := &fakeRunner{res: c.res}
			out := ProbeBypass(target, keys, fr)
			if len(out) != 1 {
				t.Fatalf("expected 1 result, got %d", len(out))
			}
			if out[0].Outcome != c.want {
				t.Fatalf("outcome = %q, want %q (detail %q)", out[0].Outcome, c.want, out[0].Detail)
			}
			// The probe must scope to this key only, in batch mode, on the port.
			joined := strings.Join(fr.lastArgs, " ")
			for _, want := range []string{"BatchMode=yes", "IdentitiesOnly=yes", "-i /home/u/.ssh/id_ed25519", "-p 2222", "deploy@p.example.com"} {
				if !strings.Contains(joined, want) {
					t.Errorf("ssh args missing %q: %s", want, joined)
				}
			}
		})
	}
}

// ed25519Line builds a self-consistent authorized_keys/.pub line for a synthetic
// ed25519 key (32 bytes of `seed`) plus the OpenSSH SHA256 fingerprint that
// sshKeyFingerprint must recompute from it. No external tools, deterministic.
func ed25519Line(seed byte, comment string) (line, fingerprint string) {
	var blob bytes.Buffer
	writeSSHString(&blob, []byte("ssh-ed25519"))
	writeSSHString(&blob, bytes.Repeat([]byte{seed}, 32))
	b64 := base64.StdEncoding.EncodeToString(blob.Bytes())
	sum := sha256.Sum256(blob.Bytes())
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	return "ssh-ed25519 " + b64 + " " + comment, fp
}

func writeSSHString(w *bytes.Buffer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	w.Write(l[:])
	w.Write(b)
}

func TestSSHKeyFingerprint(t *testing.T) {
	line, want := ed25519Line(0x01, "user@host")

	got, ok := sshKeyFingerprint(line)
	if !ok || got != want {
		t.Fatalf("sshKeyFingerprint(line) = %q,%v; want %q,true", got, ok, want)
	}

	// Options before the key type must be tolerated and yield the same fingerprint.
	withOpts := `no-pty,from="10.0.0.0/8" ` + line
	if got, ok := sshKeyFingerprint(withOpts); !ok || got != want {
		t.Fatalf("with options = %q,%v; want %q,true", got, ok, want)
	}

	// Non-key lines (comments, blanks) yield nothing.
	for _, bad := range []string{"", "   ", "# a comment", "ssh-ed25519"} {
		if got, ok := sshKeyFingerprint(bad); ok {
			t.Errorf("sshKeyFingerprint(%q) = %q,true; want false", bad, got)
		}
	}
}

func TestInspectAuthorizedKeys(t *testing.T) {
	// A personal key on disk (only the .pub is read).
	dir := t.TempDir()
	priv := filepath.Join(dir, "id_test")
	mineLine, _ := ed25519Line(0x02, "me@laptop")
	if err := os.WriteFile(priv+".pub", []byte(mineLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherLine, _ := ed25519Line(0x03, "ci@server")

	// IdentityFile is the (root-owned) broker key; the caller gates on its
	// readability before calling, so the inspection itself just connects with it.
	// The runner is stubbed here, so the path is only echoed into the ssh args.
	target := admin.SSHTarget{Alias: "prod", Host: "p.example.com", User: "root", IdentityFile: "/var/openscope/ssh/prod/id_rsa"}

	// remoteDump builds the command output: authorized_keys lines, the sentinel,
	// then any sshd_config alt-auth directives.
	remoteDump := func(authKeys, sshdCfg string) string {
		return authKeys + "\n" + authKeysSentinel + "\n" + sshdCfg
	}

	cases := []struct {
		name    string
		res     executor.Result
		err     error
		want    string
		wantSub string // optional substring the Detail must contain
	}{
		{
			name: "personal key authorized is bypass",
			res:  executor.Result{ExitCode: 0, Stdout: remoteDump(mineLine, "")},
			want: BypassFound,
		},
		{
			name: "personal key absent is clear",
			res:  executor.Result{ExitCode: 0, Stdout: remoteDump(otherLine, "")},
			want: BypassClear,
		},
		{
			name:    "absent but CA trust configured is inconclusive",
			res:     executor.Result{ExitCode: 0, Stdout: remoteDump(otherLine, "TrustedUserCAKeys /etc/ssh/ca.pub")},
			want:    BypassUnknown,
			wantSub: "CA/command-based auth",
		},
		{
			name:    "absent but AuthorizedKeysCommand configured is inconclusive",
			res:     executor.Result{ExitCode: 0, Stdout: remoteDump(otherLine, "AuthorizedKeysCommand /usr/bin/keys")},
			want:    BypassUnknown,
			wantSub: "CA/command-based auth",
		},
		{
			name:    "broker key cannot connect is inconclusive",
			res:     executor.Result{ExitCode: 255, Stderr: "Permission denied (publickey)."},
			want:    BypassUnknown,
			wantSub: "could not read authorized_keys",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fr := &fakeRunner{res: c.res, err: c.err}
			out := InspectAuthorizedKeys(target, []string{priv}, fr)
			if len(out) != 1 {
				t.Fatalf("expected 1 result, got %d", len(out))
			}
			if out[0].Outcome != c.want {
				t.Fatalf("outcome = %q, want %q (detail %q)", out[0].Outcome, c.want, out[0].Detail)
			}
			if c.wantSub != "" && !strings.Contains(out[0].Detail, c.wantSub) {
				t.Errorf("detail %q missing %q", out[0].Detail, c.wantSub)
			}
		})
	}

	// The connection must use the broker's identity, accept-new host keys, and run
	// the read-only authorized_keys command — never a personal key, never an auth
	// attempt with one.
	fr := &fakeRunner{res: executor.Result{ExitCode: 0, Stdout: remoteDump(mineLine, "")}}
	InspectAuthorizedKeys(target, []string{priv}, fr)
	joined := strings.Join(fr.lastArgs, " ")
	for _, want := range []string{"BatchMode=yes", "StrictHostKeyChecking=accept-new", "-i /var/openscope/ssh/prod/id_rsa", "root@p.example.com", authKeysSentinel} {
		if !strings.Contains(joined, want) {
			t.Errorf("ssh args missing %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, priv+" ") || strings.Contains(joined, "-i "+priv) {
		t.Errorf("personal key must never be offered to ssh: %s", joined)
	}
}
