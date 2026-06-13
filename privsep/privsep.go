// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package privsep reports whether the running broker is privilege-separated
// from the agent — i.e. whether a local process sharing the daemon's uid could
// reach the broker's credentials or privileged commands directly, bypassing
// policy. It is the keystone for the macOS privileged-helper design (see
// docs/macos-privileged-helper.md): privileged brokering (ssh keys, sudo system
// commands) is only contained when the privileged work is isolated from the
// agent's uid.
package privsep

import (
	"fmt"
	"os"
)

// Model describes the privilege relationship between the broker and a local
// same-uid agent.
type Model struct {
	// Separated is true when privileged work is out of an unprivileged,
	// same-uid agent's reach (today: the process runs as root).
	Separated bool `json:"separated"`
	// Root is true when the process itself runs as root.
	Root bool `json:"root"`
	// EUID is the effective uid the process runs as.
	EUID int `json:"euid"`
	// Reason explains the verdict in operator-facing terms.
	Reason string `json:"reason"`
}

// Detect inspects the current process.
func Detect() Model {
	return classify(os.Geteuid())
}

// classify is the pure core, split out so tests do not depend on the real uid.
//
// A root process can own keys and run privileged commands that a non-root,
// same-uid agent cannot read or invoke, so it is separated. A non-root process
// shares its privileges with any same-uid agent: the agent can read whatever
// key the daemon reads and run whatever sudo grant the daemon's user has, so it
// is NOT separated. (A non-root *dedicated service user* distinct from the
// agent — the enterprise/VPC broker — is also safe, but that topology is keyed
// off the remote-access path by the caller, not off the uid alone.)
func classify(euid int) Model {
	if euid == 0 {
		return Model{
			Separated: true,
			Root:      true,
			EUID:      euid,
			Reason:    "daemon runs as root; brokered keys and privileged commands are out of an unprivileged agent's reach",
		}
	}
	return Model{
		Separated: false,
		Root:      false,
		EUID:      euid,
		Reason: fmt.Sprintf(
			"daemon runs as uid %d (not root); a local agent sharing this uid can read brokered ssh keys and run its sudo commands directly — privileged brokering must go through a root helper",
			euid),
	}
}
