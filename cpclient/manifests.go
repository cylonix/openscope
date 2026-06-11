// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cpclient

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// VendorKeys is the ring of trusted vendor Ed25519 public keys (base64),
// keyed by public_key_id. Policy bundles and release manifests must verify
// against one of these before a payload is trusted. The customer remains
// authoritative: a verified bundle is only STORED; applying it is an
// explicit admin action.
//
// Compiled in so a compromised control plane cannot push itself a new key.
var VendorKeys = map[string]string{
	// "openscope-vendor-2026": "<base64 ed25519 public key>",
}

// Manifest is the signed envelope the control plane serves for both policy
// bundles and release manifests. The signature covers the raw payload
// bytes exactly as served.
type Manifest struct {
	Kind        string          `json:"kind"`    // "policy-bundle" | "release"
	Version     string          `json:"version"` // bundle version or release version
	Payload     json.RawMessage `json:"payload"`
	Signature   string          `json:"signature"`     // base64(ed25519.Sign(payload))
	PublicKeyID string          `json:"public_key_id"` // selects the VendorKeys entry
}

// ReleaseInfo is the payload of a "release" manifest.
type ReleaseInfo struct {
	Product    string `json:"product"` // "router" | "broker"
	Version    string `json:"version"`
	ReleasedAt string `json:"released_at"`
	NotesURL   string `json:"notes_url,omitempty"`
	Artifacts  []struct {
		Platform string `json:"platform"`
		URL      string `json:"url"`
		SHA256   string `json:"sha256"`
	} `json:"artifacts,omitempty"`
}

// Verify checks the manifest signature against the trusted key ring
// (VendorKeys by default; pass a non-nil ring to override, e.g. in tests).
func (m *Manifest) Verify(ring map[string]string) error {
	if ring == nil {
		ring = VendorKeys
	}
	pubB64, ok := ring[m.PublicKeyID]
	if !ok {
		return fmt.Errorf("unknown vendor key id %q", m.PublicKeyID)
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad vendor key %q in ring", m.PublicKeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), m.Payload, sig) {
		return fmt.Errorf("signature does not verify against key %q", m.PublicKeyID)
	}
	return nil
}

// FetchUpdateManifest gets and verifies the latest release manifest for a
// product ("router" | "broker"). Callers compare ReleaseInfo.Version with
// their own build version to surface "update available" — check-only,
// nothing is downloaded or executed.
func (c *Client) FetchUpdateManifest(product string) (*Manifest, *ReleaseInfo, error) {
	m, err := c.fetchManifest("/v1/updates/latest?product=" + product)
	if err != nil {
		return nil, nil, err
	}
	var info ReleaseInfo
	if err := json.Unmarshal(m.Payload, &info); err != nil {
		return nil, nil, fmt.Errorf("parse release payload: %w", err)
	}
	return m, &info, nil
}

// FetchPolicyBundle gets and verifies the latest policy bundle (DLP rule
// packs, model allowlists) for a deployment kind. The verified payload is
// returned for the caller to store; applying it is a separate, explicit
// admin step.
func (c *Client) FetchPolicyBundle(kind string) (*Manifest, error) {
	return c.fetchManifest("/v1/policy-bundles/latest?kind=" + kind)
}

func (c *Client) fetchManifest(path string) (*Manifest, error) {
	if c == nil {
		return nil, fmt.Errorf("control plane not configured")
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(c.cfg.BaseURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.DeploymentToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := m.Verify(nil); err != nil {
		return nil, err
	}
	return &m, nil
}
