// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// DefaultLogMaxBytes caps each launchd stdout/stderr log at 1 MiB. Past that the
// log is rotated (one generation kept) and truncated in place.
const DefaultLogMaxBytes int64 = 1 << 20

// LogRotateInterval is how often the rotator re-checks the managed log files.
const LogRotateInterval = time.Minute

// StartLogRotator caps the named operational logs (the daemon's launchd
// StandardOut/StandardErrorPath files) so they cannot grow without bound. It
// runs one pass immediately — so an already-oversized log from a long-running
// or prior build is capped at startup — then re-checks every interval.
//
// Returns a stop function; the daemon never needs it (process exit reaps the
// goroutine) but tests do. A no-op when there is nothing to manage, so non-
// launchd runs (dev, tests, Linux/systemd) cost nothing.
//
// This is strictly for operational logs. The audit log is an append-only
// record and is never rotated here.
func StartLogRotator(files []string, maxBytes int64, interval time.Duration) func() {
	if len(files) == 0 || maxBytes <= 0 || interval <= 0 {
		return func() {}
	}
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		pass := func() {
			for _, f := range files {
				if _, err := rotateIfLarge(f, maxBytes); err != nil {
					fmt.Fprintf(os.Stderr, "log rotate %s: %v\n", f, err)
				}
			}
		}
		pass()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				pass()
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }) }
}

// rotateIfLarge rotates path when it exceeds maxBytes: the current contents are
// copied to "<path>.1" (overwriting any prior generation), then the live file
// is truncated to zero in place.
//
// In-place truncation — rather than rename-and-recreate — is deliberate.
// launchd holds the log open with O_APPEND, so after the truncate its next
// write resumes at offset 0 and the file stays capped. A rename would leave
// launchd writing to the now-unlinked inode (its ".1") until the daemon next
// restarts, so the live log would appear to stop growing. Truncation keeps the
// one fd launchd actually owns pointed at a file that shrinks.
func rotateIfLarge(path string, maxBytes int64) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if fi.Size() <= maxBytes {
		return false, nil
	}

	perm := fi.Mode().Perm()
	if perm == 0 {
		perm = 0o644
	}

	// Stream rather than ReadFile so a pathologically large pre-existing log
	// (e.g. a runaway from before rotation shipped) doesn't load whole into RAM.
	if err := copyFile(path, path+".1", perm); err != nil {
		return false, err
	}
	if err := os.Truncate(path, 0); err != nil {
		return false, err
	}
	return true, nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
