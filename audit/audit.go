// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Event struct {
	Timestamp time.Time         `json:"ts"`
	Agent     string            `json:"agent"`
	App       string            `json:"app"`
	Action    string            `json:"action"`
	Params    map[string]string `json:"params,omitempty"`
	Decision  string            `json:"decision"`
	Result    string            `json:"result"`
	Reason    string            `json:"reason,omitempty"`

	// Human attribution: the authenticated user (and their groups) on whose
	// behalf the agent acted, and how that identity was established. Empty for
	// plain agent tokens / unauthenticated local calls. AuthMethod is one of
	// "proxy" (SSO reverse proxy), "token" (per-user bearer token), or "unix"
	// (local socket).
	User       string   `json:"user,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	AuthMethod string   `json:"auth_method,omitempty"`

	// Network-transport context, set when the request arrived over the
	// daemon's HTTP listener (empty for the local Unix socket — the JSONL
	// shape is unchanged for existing local deployments).
	RequestID   string `json:"request_id,omitempty"`
	Transport   string `json:"transport,omitempty"` // "unix" | "http" | "reflector"
	RemoteAddr  string `json:"remote_addr,omitempty"`
	TokenPrefix string `json:"token_prefix,omitempty"` // never the token itself

	// Reflector delegation context, set when the request arrived over a
	// cross-org reflector session. Agent stays the issuer (who delegated);
	// ExternalAgent records the advisory delegatee; SessionID ties the events
	// of one share session together.
	SessionID     string `json:"session_id,omitempty"`
	ExternalAgent string `json:"external_agent,omitempty"`

	// Proposal apply context, set by `openscope apply` (empty otherwise).
	ProposalSHA256 string `json:"proposal_sha256,omitempty"`
	ProposalName   string `json:"proposal_name,omitempty"`
	AuthoredBy     string `json:"authored_by,omitempty"`
}

// EnsureWritable reports whether the audit log can be opened for appending,
// without writing a record. The daemon calls this before executing an
// authorized action so it fails closed rather than acting unlogged: in the
// per-user deployment the log is the agent's own file, which the agent could
// make unwritable to erase its trail. Uses the same open flags as Append.
func EnsureWritable(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	return file.Close()
}

// Outcome is one recorded execution of an app·action, reduced to what risk
// review needs: did it run, did it work, and why not.
type Outcome struct {
	Timestamp time.Time `json:"ts"`
	Result    string    `json:"result"` // success | executor_error | executor_failure | ...
	Reason    string    `json:"reason,omitempty"`
}

// Failed reports whether the run reached the executor and went wrong — the
// signal that predicts the next run better than any static analysis.
func (o Outcome) Failed() bool {
	return o.Result == "executor_error" || o.Result == "executor_failure"
}

// RecentOutcomes scans the JSONL audit log and returns, per "app·action", the
// most recent EXECUTED outcomes (decision allow), newest first, capped at max
// per key. Denied requests are policy working as intended, not run history, so
// they are excluded. Reads best-effort: a malformed line is skipped, a missing
// file returns an empty map — plan runs as the user and the log may be
// root-owned; callers treat absence as "no history", never as an error to
// surface.
func RecentOutcomes(path string, max int) (map[string][]Outcome, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string][]Outcome{}
	for _, line := range splitJSONL(data) {
		var ev Event
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev.Decision != "allow" || ev.App == "" || ev.Action == "" {
			continue
		}
		switch ev.Result {
		case "success", "executor_error", "executor_failure":
		default:
			continue // bypass inspections, filter errors, etc. are not run history
		}
		key := ev.App + "·" + ev.Action
		out[key] = append(out[key], Outcome{Timestamp: ev.Timestamp, Result: ev.Result, Reason: ev.Reason})
	}
	// Newest first, capped per key (the file is append-ordered oldest first).
	for key, list := range out {
		for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
			list[i], list[j] = list[j], list[i]
		}
		if len(list) > max {
			list = list[:max]
		}
		out[key] = list
	}
	return out, nil
}

func splitJSONL(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

func Append(path string, event Event) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	if _, err := file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}

	return nil
}
