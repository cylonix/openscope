// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import "testing"

func TestSocketMode(t *testing.T) {
	// A root daemon must let the non-root agent connect (world-connectable;
	// confined by policy). A non-root daemon shares the agent's uid, so 0600.
	if got := socketMode(0); got != 0o666 {
		t.Errorf("root socket mode = %04o, want 0666", got)
	}
	if got := socketMode(501); got != 0o600 {
		t.Errorf("non-root socket mode = %04o, want 0600", got)
	}
}
