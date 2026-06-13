// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
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

func (f *fakeRunner) Run(name string, args []string, stdin string) (executor.Result, error) {
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
