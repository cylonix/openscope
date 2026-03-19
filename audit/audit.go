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
