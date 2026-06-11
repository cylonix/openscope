// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// EnrollResult is what the control plane returns for a valid enroll code.
// The deployment token is shown once; the caller persists it (0600).
type EnrollResult struct {
	DeploymentID    string `json:"deployment_id"`
	DeploymentToken string `json:"deployment_token"` // osk_deploy_*
}

// Enroll registers this deployment with the vendor control plane using a
// vendor-provisioned enroll code. One-shot; does not need a Client.
func Enroll(baseURL, code, name, kind, version string) (*EnrollResult, error) {
	if baseURL == "" || code == "" {
		return nil, fmt.Errorf("control plane URL and enroll code are required")
	}
	body, err := json.Marshal(map[string]string{
		"enroll_code":     code,
		"deployment_name": name,
		"kind":            kind, // "router" | "broker"
		"version":         version,
	})
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	resp, err := hc.Post(strings.TrimRight(baseURL, "/")+"/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll failed: control plane returned %d", resp.StatusCode)
	}
	var out EnrollResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("parse enroll response: %w", err)
	}
	if out.DeploymentToken == "" {
		return nil, fmt.Errorf("enroll response missing deployment_token")
	}
	return &out, nil
}
