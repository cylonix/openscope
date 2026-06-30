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
