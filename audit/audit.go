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

	// Network-transport context, set when the request arrived over the
	// daemon's HTTP listener (empty for the local Unix socket — the JSONL
	// shape is unchanged for existing local deployments).
	RequestID   string `json:"request_id,omitempty"`
	Transport   string `json:"transport,omitempty"` // "unix" | "http"
	RemoteAddr  string `json:"remote_addr,omitempty"`
	TokenPrefix string `json:"token_prefix,omitempty"` // never the token itself

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
