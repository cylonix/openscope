// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotateIfLarge_UnderCap(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "d.log")
	if err := os.WriteFile(log, []byte("small\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rotated, err := rotateIfLarge(log, 1<<20)
	if err != nil {
		t.Fatalf("rotateIfLarge: %v", err)
	}
	if rotated {
		t.Fatal("rotated an under-cap file")
	}
	if _, err := os.Stat(log + ".1"); !os.IsNotExist(err) {
		t.Fatalf(".1 backup created for under-cap file: %v", err)
	}
	if b, _ := os.ReadFile(log); string(b) != "small\n" {
		t.Fatalf("live log altered: %q", b)
	}
}

func TestRotateIfLarge_OverCap(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "d.log")
	content := make([]byte, 2048)
	for i := range content {
		content[i] = 'x'
	}
	if err := os.WriteFile(log, content, 0o600); err != nil {
		t.Fatal(err)
	}

	rotated, err := rotateIfLarge(log, 1024)
	if err != nil {
		t.Fatalf("rotateIfLarge: %v", err)
	}
	if !rotated {
		t.Fatal("did not rotate an over-cap file")
	}

	// Live file truncated to zero in place.
	fi, err := os.Stat(log)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Fatalf("live log not truncated: size=%d", fi.Size())
	}

	// History preserved in .1 with the original contents and perms.
	backup, err := os.ReadFile(log + ".1")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if len(backup) != len(content) {
		t.Fatalf("backup size=%d want %d", len(backup), len(content))
	}
	bfi, err := os.Stat(log + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if bfi.Mode().Perm() != 0o600 {
		t.Fatalf("backup perms=%o want 600", bfi.Mode().Perm())
	}
}

// TestRotateIfLarge_AppendResumesFromZero documents the load-bearing assumption:
// launchd holds the log open with O_APPEND, so after an in-place truncate its
// next write resumes at offset 0 and the file stays capped (rather than
// re-growing a sparse file back to the old offset).
func TestRotateIfLarge_AppendResumesFromZero(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "d.log")

	// A writer holding the file open across the rotation, the way launchd does.
	w, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}

	if _, err := rotateIfLarge(log, 1024); err != nil {
		t.Fatalf("rotateIfLarge: %v", err)
	}

	// The held-open writer keeps writing; with O_APPEND it lands at offset 0.
	if _, err := w.Write([]byte("after\n")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(log)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != int64(len("after\n")) {
		t.Fatalf("post-rotate size=%d want %d — append did not resume from 0", fi.Size(), len("after\n"))
	}
}

func TestRotateIfLarge_Missing(t *testing.T) {
	rotated, err := rotateIfLarge(filepath.Join(t.TempDir(), "nope.log"), 1024)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if rotated {
		t.Fatal("reported rotation of a missing file")
	}
}

func TestStartLogRotator(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "d.log")
	if err := os.WriteFile(log, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}

	stop := StartLogRotator([]string{log}, 1024, 5*time.Millisecond)
	defer stop()

	// The immediate pass should truncate the over-cap file promptly.
	deadline := time.Now().Add(2 * time.Second)
	for {
		fi, err := os.Stat(log)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("log not rotated within deadline: size=%d", fi.Size())
		}
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := os.Stat(log + ".1"); err != nil {
		t.Fatalf("backup missing after rotation: %v", err)
	}
}

func TestStartLogRotator_NoFilesIsNoop(t *testing.T) {
	// Must not panic or spawn anything; stop() is safe to call repeatedly.
	stop := StartLogRotator(nil, 1024, time.Millisecond)
	stop()
	stop()
}
