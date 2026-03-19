// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package agent

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/agentscope/ascope/config"
	"gopkg.in/yaml.v3"
)

type Registry struct {
	Version int      `yaml:"version"`
	Agents  []string `yaml:"agents"`
}

func Load(path string) (Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Registry{}, fmt.Errorf("read agents file: %w", err)
	}

	var registry Registry
	if err := yaml.Unmarshal(data, &registry); err != nil {
		return Registry{}, fmt.Errorf("parse agents file: %w", err)
	}

	if registry.Version == 0 {
		registry.Version = 1
	}

	return registry, nil
}

func LoadDefault(paths config.Paths) (Registry, error) {
	return Load(paths.AgentsFile)
}

func LoadDefaultOrEmpty(paths config.Paths) (Registry, error) {
	registry, err := LoadDefault(paths)
	if err == nil {
		return registry, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return Registry{Version: 1, Agents: []string{}}, nil
	}
	return Registry{}, err
}

func Save(path string, registry Registry) error {
	if registry.Version == 0 {
		registry.Version = 1
	}

	sort.Strings(registry.Agents)
	data, err := yaml.Marshal(registry)
	if err != nil {
		return fmt.Errorf("marshal agents file: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write agents file: %w", err)
	}

	return nil
}

func Register(paths config.Paths, agentID string) (Registry, bool, error) {
	registry, err := LoadDefaultOrEmpty(paths)
	if err != nil {
		return Registry{}, false, err
	}

	if slices.Contains(registry.Agents, agentID) {
		return registry, false, nil
	}

	registry.Agents = append(registry.Agents, agentID)
	if err := Save(paths.AgentsFile, registry); err != nil {
		return Registry{}, false, err
	}

	return registry, true, nil
}

func IsRegistered(paths config.Paths, agentID string) (bool, error) {
	registry, err := LoadDefaultOrEmpty(paths)
	if err != nil {
		return false, err
	}
	return slices.Contains(registry.Agents, agentID), nil
}
