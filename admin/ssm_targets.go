// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/openscope/openscope/config"
	"gopkg.in/yaml.v3"
)

// SSMTargets are named EC2 instances the broker reaches over AWS Systems Manager
// (Run Command) — no inbound SSH, no SSH key. The broker's AWS identity is the
// credential under custody (see executor/ssmexec credaudit); a target carries no
// secret, only the instance id + region and the same path/service allow-lists the
// SSH targets use to bound a verb's blast radius.
type SSMTargets struct {
	Version int         `yaml:"version"`
	Targets []SSMTarget `yaml:"targets"`
}

type SSMTarget struct {
	Alias               string   `yaml:"alias"`
	InstanceID          string   `yaml:"instance_id"`
	Region              string   `yaml:"region"`
	AllowedServices     []string `yaml:"allowed_services,omitempty"`
	AllowedPaths        []string `yaml:"allowed_paths,omitempty"`
	AllowedPathPrefixes []string `yaml:"allowed_path_prefixes,omitempty"`
}

func LoadSSMTargets(path string) (SSMTargets, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SSMTargets{}, fmt.Errorf("read ssm targets file: %w", err)
	}
	var targets SSMTargets
	if err := yaml.Unmarshal(data, &targets); err != nil {
		return SSMTargets{}, fmt.Errorf("parse ssm targets file: %w", err)
	}
	return normalizeSSMTargets(targets), targets.Validate()
}

func LoadSSMTargetsOrDefault(paths config.Paths) (SSMTargets, error) {
	targets, err := LoadSSMTargets(paths.SSMTargetsFile)
	if err == nil {
		return targets, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return SSMTargets{Version: 1, Targets: []SSMTarget{}}, nil
	}
	return SSMTargets{}, err
}

func SaveSSMTargets(path string, targets SSMTargets) error {
	targets = normalizeSSMTargets(targets)
	if targets.Version == 0 {
		targets.Version = 1
	}
	data, err := yaml.Marshal(targets)
	if err != nil {
		return fmt.Errorf("marshal ssm targets: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create ssm targets dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write ssm targets file: %w", err)
	}
	return os.Chmod(path, 0o644)
}

func FindSSMTarget(targets SSMTargets, alias string) (SSMTarget, bool) {
	for _, target := range targets.Targets {
		if target.Alias == alias {
			return target, true
		}
	}
	return SSMTarget{}, false
}

func NormalizeSSMTarget(target SSMTarget) SSMTarget {
	target.Alias = strings.TrimSpace(target.Alias)
	target.InstanceID = strings.TrimSpace(target.InstanceID)
	target.Region = strings.TrimSpace(target.Region)
	target.AllowedServices = normalizeStringList(target.AllowedServices)
	target.AllowedPaths = normalizePathList(target.AllowedPaths)
	target.AllowedPathPrefixes = normalizePathList(target.AllowedPathPrefixes)
	return target
}

func normalizeSSMTargets(targets SSMTargets) SSMTargets {
	if targets.Version == 0 {
		targets.Version = 1
	}
	normalized := make([]SSMTarget, 0, len(targets.Targets))
	for _, target := range targets.Targets {
		normalized = append(normalized, NormalizeSSMTarget(target))
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Alias < normalized[j].Alias
	})
	targets.Targets = normalized
	return targets
}

func (t SSMTarget) Validate() error {
	if strings.TrimSpace(t.Alias) == "" {
		return fmt.Errorf("ssm target alias is required")
	}
	if strings.TrimSpace(t.InstanceID) == "" {
		return fmt.Errorf("ssm target %q instance_id is required", t.Alias)
	}
	if strings.TrimSpace(t.Region) == "" {
		return fmt.Errorf("ssm target %q region is required", t.Alias)
	}
	for _, p := range append(append([]string{}, t.AllowedPaths...), t.AllowedPathPrefixes...) {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("ssm target %q allowed path %q must be absolute", t.Alias, p)
		}
	}
	return nil
}

// SaveDefaultSSMTargets writes the targets to the root-owned admin location.
func SaveDefaultSSMTargets(paths config.Paths, targets SSMTargets) error {
	return SaveSSMTargets(paths.SSMTargetsFile, targets)
}

// AddSSMTarget appends a target if its alias is new (keeps the existing target on
// alias collision, like AddSSHTarget); the bool reports whether it was added.
func AddSSMTarget(paths config.Paths, target SSMTarget) (SSMTargets, bool, error) {
	targets, err := LoadSSMTargetsOrDefault(paths)
	if err != nil {
		return SSMTargets{}, false, err
	}
	target = NormalizeSSMTarget(target)
	if err := target.Validate(); err != nil {
		return SSMTargets{}, false, err
	}
	for _, existing := range targets.Targets {
		if existing.Alias == target.Alias {
			return targets, false, nil
		}
	}
	targets.Targets = append(targets.Targets, target)
	if err := SaveDefaultSSMTargets(paths, targets); err != nil {
		return SSMTargets{}, false, err
	}
	return normalizeSSMTargets(targets), true, nil
}

func RemoveSSMTarget(paths config.Paths, alias string) (SSMTargets, bool, error) {
	targets, err := LoadSSMTargetsOrDefault(paths)
	if err != nil {
		return SSMTargets{}, false, err
	}
	alias = strings.TrimSpace(alias)
	index := -1
	for i, target := range targets.Targets {
		if target.Alias == alias {
			index = i
			break
		}
	}
	if index < 0 {
		return targets, false, nil
	}
	targets.Targets = append(targets.Targets[:index], targets.Targets[index+1:]...)
	if err := SaveDefaultSSMTargets(paths, targets); err != nil {
		return SSMTargets{}, false, err
	}
	return normalizeSSMTargets(targets), true, nil
}

func (t SSMTargets) Validate() error {
	if t.Version == 0 {
		return fmt.Errorf("ssm targets version is required")
	}
	seen := map[string]struct{}{}
	for i, target := range t.Targets {
		if target.Alias == "" || target.InstanceID == "" || target.Region == "" {
			return fmt.Errorf("ssm target %d must set alias, instance_id, and region", i)
		}
		if _, dup := seen[target.Alias]; dup {
			return fmt.Errorf("duplicate ssm target alias %q", target.Alias)
		}
		seen[target.Alias] = struct{}{}
	}
	return nil
}

// SSMTargetAllowsService / SSMTargetAllowsPath mirror the SSH allow-list checks
// so a verb's service/path parameters are bounded the same way regardless of
// transport.
func SSMTargetAllowsService(target SSMTarget, service string) bool {
	return len(target.AllowedServices) > 0 && slices.Contains(target.AllowedServices, service)
}

func SSMTargetAllowsPath(target SSMTarget, path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.Clean(path)
	if slices.Contains(target.AllowedPaths, clean) {
		return true
	}
	for _, prefix := range target.AllowedPathPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
