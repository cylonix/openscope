// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package privsep

import (
	"os"
	"strings"
	"testing"
)

func TestClassifyRootIsSeparated(t *testing.T) {
	m := classify(0)
	if !m.Separated || !m.Root {
		t.Fatalf("root should be separated+root, got %+v", m)
	}
	if m.EUID != 0 {
		t.Errorf("euid = %d, want 0", m.EUID)
	}
}

func TestClassifyNonRootIsNotSeparated(t *testing.T) {
	m := classify(501)
	if m.Separated || m.Root {
		t.Fatalf("non-root should be neither separated nor root, got %+v", m)
	}
	if m.EUID != 501 {
		t.Errorf("euid = %d, want 501", m.EUID)
	}
	if !strings.Contains(m.Reason, "501") || !strings.Contains(m.Reason, "root helper") {
		t.Errorf("reason should name the uid and the fix, got %q", m.Reason)
	}
}

func TestDetectMatchesProcess(t *testing.T) {
	if got, want := Detect().EUID, os.Geteuid(); got != want {
		t.Fatalf("Detect euid = %d, want %d", got, want)
	}
}
