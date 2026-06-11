// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cpclient

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Enrollment is the on-disk record written by `openscope enroll`
// (<ConfigDir>/controlplane.yaml, mode 0600).
type Enrollment struct {
	Version         int    `yaml:"version"`
	ControlPlaneURL string `yaml:"control_plane_url"`
	DeploymentID    string `yaml:"deployment_id"`
	DeploymentToken string `yaml:"deployment_token"`
}

func SaveEnrollment(path string, e Enrollment) error {
	if e.Version == 0 {
		e.Version = 1
	}
	data, err := yaml.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal enrollment: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write enrollment: %w", err)
	}
	return nil
}

func LoadEnrollment(path string) (Enrollment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Enrollment{}, err
	}
	var e Enrollment
	if err := yaml.Unmarshal(data, &e); err != nil {
		return Enrollment{}, fmt.Errorf("parse enrollment: %w", err)
	}
	return e, nil
}

// ResolveConfig builds the effective client config: env vars win, else the
// enrollment file, else disabled (zero BaseURL → New returns nil).
func ResolveConfig(enrollmentPath, spoolPath string) Config {
	cfg := FromEnv(spoolPath)
	if cfg.BaseURL != "" {
		return cfg
	}
	e, err := LoadEnrollment(enrollmentPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: unreadable %s: %v\n", enrollmentPath, err)
		}
		return cfg
	}
	cfg.BaseURL = e.ControlPlaneURL
	cfg.DeploymentToken = e.DeploymentToken
	return cfg
}
