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

type SSHTargets struct {
	Version int         `yaml:"version"`
	Targets []SSHTarget `yaml:"targets"`
}

type SSHTarget struct {
	Alias               string   `yaml:"alias"`
	Host                string   `yaml:"host"`
	User                string   `yaml:"user"`
	Port                int      `yaml:"port,omitempty"`
	IdentityFile        string   `yaml:"identity_file,omitempty"`
	ProxyJump           string   `yaml:"proxy_jump,omitempty"`
	AllowedServices     []string `yaml:"allowed_services,omitempty"`
	AllowedPaths        []string `yaml:"allowed_paths,omitempty"`
	AllowedPathPrefixes []string `yaml:"allowed_path_prefixes,omitempty"`
	// AllowedUploadSources lists LOCAL (broker-host) path prefixes the daemon may
	// read and stream to this target for an upload verb (constraint:
	// local_source). Fail-closed: empty means no uploads. Scoped per-target so a
	// grant for one host can't read files staged for another — and never widened
	// to reach secrets/home (the planner blocks that).
	AllowedUploadSources []string `yaml:"allowed_upload_sources,omitempty"`
	// Facts are broker-recorded host observations (os/arch, docker versions),
	// pinned by `openscope apply` when it probes a proposed target. They ground
	// plan review in the host's reality (e.g. "this target runs docker-compose
	// v1") and let the executor enforce artifact platform gates. Never
	// proposal-authored authority — informational, refreshed by re-proposing the
	// target.
	Facts *TargetFacts `yaml:"facts,omitempty"`
	// Criticality is the human-declared tier of this host: "prod", "staging",
	// or "lab". Proposal-authored and human-confirmed at apply, unlike Facts.
	// The planner scales consequence findings with it (a mutating verb on a
	// prod target demands more than one on a lab box).
	Criticality string `yaml:"criticality,omitempty"`
}

// TargetFacts holds probed host observations. All fields are best-effort:
// empty means "not observed", never "absent on the host".
type TargetFacts struct {
	OS       string `yaml:"os,omitempty"`      // uname -s, e.g. Linux
	Arch     string `yaml:"arch,omitempty"`    // uname -m, e.g. x86_64
	Docker   string `yaml:"docker,omitempty"`  // `docker --version` first line
	Compose  string `yaml:"compose,omitempty"` // `docker-compose --version` first line
	ProbedAt string `yaml:"probed_at,omitempty"`
	// Containers are the names running on the host when probed (`docker ps`),
	// the co-tenancy picture that turns "can modify this host" into "shares the
	// host with traefik, which fronts every domain here".
	Containers []string `yaml:"containers,omitempty"`
}

// Platform renders the facts as a normalized os/arch pair ("linux/amd64"),
// mapping uname spellings onto the OCI/docker platform vocabulary. Empty when
// either half is unobserved.
func (f TargetFacts) Platform() string {
	osName := strings.ToLower(strings.TrimSpace(f.OS))
	arch := strings.ToLower(strings.TrimSpace(f.Arch))
	switch arch {
	case "x86_64":
		arch = "amd64"
	case "aarch64", "arm64":
		arch = "arm64"
	case "armv7l", "armv6l":
		arch = "arm"
	case "i386", "i686":
		arch = "386"
	}
	if osName == "" || arch == "" {
		return ""
	}
	return osName + "/" + arch
}

// ComposeMajorV1 reports whether the probed docker-compose is the Python v1
// line (e.g. "docker-compose version 1.29.2, build ..."), whose container
// recreate path is known to crash on images saved by modern Docker.
func (f TargetFacts) ComposeMajorV1() bool {
	c := strings.TrimSpace(f.Compose)
	for _, prefix := range []string{"docker-compose version 1.", "docker-compose version v1."} {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func LoadSSHTargets(path string) (SSHTargets, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SSHTargets{}, fmt.Errorf("read ssh targets file: %w", err)
	}

	var targets SSHTargets
	if err := yaml.Unmarshal(data, &targets); err != nil {
		return SSHTargets{}, fmt.Errorf("parse ssh targets file: %w", err)
	}

	return normalizeSSHTargets(targets), targets.Validate()
}

func LoadSSHTargetsOrDefault(paths config.Paths) (SSHTargets, error) {
	targets, err := LoadSSHTargets(paths.SSHTargetsFile)
	if err == nil {
		return targets, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return SSHTargets{Version: 1, Targets: []SSHTarget{}}, nil
	}
	return SSHTargets{}, err
}

func SaveSSHTargets(path string, targets SSHTargets) error {
	targets = normalizeSSHTargets(targets)
	if targets.Version == 0 {
		targets.Version = 1
	}
	if err := targets.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create admin config dir: %w", err)
	}
	data, err := yaml.Marshal(targets)
	if err != nil {
		return fmt.Errorf("marshal ssh targets file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write ssh targets file: %w", err)
	}
	return nil
}

func SaveDefaultSSHTargets(paths config.Paths, targets SSHTargets) error {
	return SaveSSHTargets(paths.SSHTargetsFile, targets)
}

func AddSSHTarget(paths config.Paths, target SSHTarget) (SSHTargets, bool, error) {
	targets, err := LoadSSHTargetsOrDefault(paths)
	if err != nil {
		return SSHTargets{}, false, err
	}

	target = normalizeSSHTarget(target)
	if err := target.Validate(); err != nil {
		return SSHTargets{}, false, err
	}

	for _, existing := range targets.Targets {
		if existing.Alias == target.Alias {
			return targets, false, nil
		}
	}

	targets.Targets = append(targets.Targets, target)
	if err := SaveDefaultSSHTargets(paths, targets); err != nil {
		return SSHTargets{}, false, err
	}
	return normalizeSSHTargets(targets), true, nil
}

func RemoveSSHTarget(paths config.Paths, alias string) (SSHTargets, bool, error) {
	targets, err := LoadSSHTargetsOrDefault(paths)
	if err != nil {
		return SSHTargets{}, false, err
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
	if err := SaveDefaultSSHTargets(paths, targets); err != nil {
		return SSHTargets{}, false, err
	}
	return normalizeSSHTargets(targets), true, nil
}

func FindSSHTarget(targets SSHTargets, alias string) (SSHTarget, bool) {
	for _, target := range targets.Targets {
		if target.Alias == alias {
			return target, true
		}
	}
	return SSHTarget{}, false
}

func (f SSHTargets) Validate() error {
	if f.Version == 0 {
		return fmt.Errorf("ssh targets version is required")
	}
	seen := map[string]struct{}{}
	for _, target := range f.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
		if _, exists := seen[target.Alias]; exists {
			return fmt.Errorf("ssh target alias %q is duplicated", target.Alias)
		}
		seen[target.Alias] = struct{}{}
	}
	return nil
}

func (t SSHTarget) Validate() error {
	if strings.TrimSpace(t.Alias) == "" {
		return fmt.Errorf("ssh target alias is required")
	}
	if strings.TrimSpace(t.Host) == "" {
		return fmt.Errorf("ssh target %q host is required", t.Alias)
	}
	if strings.TrimSpace(t.User) == "" {
		return fmt.Errorf("ssh target %q user is required", t.Alias)
	}
	if t.Port < 0 || t.Port > 65535 {
		return fmt.Errorf("ssh target %q port must be between 0 and 65535", t.Alias)
	}
	for _, service := range t.AllowedServices {
		if strings.TrimSpace(service) == "" {
			return fmt.Errorf("ssh target %q allowed services must not be empty", t.Alias)
		}
	}
	for _, path := range t.AllowedPaths {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("ssh target %q allowed path %q must be absolute", t.Alias, path)
		}
	}
	for _, prefix := range t.AllowedPathPrefixes {
		if !filepath.IsAbs(prefix) {
			return fmt.Errorf("ssh target %q allowed path prefix %q must be absolute", t.Alias, prefix)
		}
	}
	for _, prefix := range t.AllowedUploadSources {
		if !filepath.IsAbs(prefix) {
			return fmt.Errorf("ssh target %q allowed upload source %q must be absolute", t.Alias, prefix)
		}
	}
	switch t.Criticality {
	case "", "prod", "staging", "lab":
	default:
		return fmt.Errorf("ssh target %q criticality must be prod, staging, or lab, got %q", t.Alias, t.Criticality)
	}
	return nil
}

func normalizeSSHTargets(targets SSHTargets) SSHTargets {
	if targets.Version == 0 {
		targets.Version = 1
	}
	normalized := make([]SSHTarget, 0, len(targets.Targets))
	for _, target := range targets.Targets {
		normalized = append(normalized, normalizeSSHTarget(target))
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Alias < normalized[j].Alias
	})
	targets.Targets = normalized
	return targets
}

// NormalizeSSHTarget exposes the same normalization (trim, clean, dedupe,
// sort) that AddSSHTarget applies before storing — callers comparing a
// proposed target against a stored one must normalize first to avoid spurious
// inequality from unsorted/whitespaced lists.
func NormalizeSSHTarget(target SSHTarget) SSHTarget {
	return normalizeSSHTarget(target)
}

func normalizeSSHTarget(target SSHTarget) SSHTarget {
	target.Alias = strings.TrimSpace(target.Alias)
	target.Host = strings.TrimSpace(target.Host)
	target.User = strings.TrimSpace(target.User)
	target.IdentityFile = strings.TrimSpace(target.IdentityFile)
	target.ProxyJump = strings.TrimSpace(target.ProxyJump)
	target.Criticality = strings.TrimSpace(target.Criticality)
	target.AllowedServices = normalizeStringList(target.AllowedServices)
	target.AllowedPaths = normalizePathList(target.AllowedPaths)
	target.AllowedPathPrefixes = normalizePathList(target.AllowedPathPrefixes)
	target.AllowedUploadSources = normalizePathList(target.AllowedUploadSources)
	return target
}

func normalizeStringList(values []string) []string {
	set := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, seen := set[value]; seen {
			continue
		}
		set[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizePathList(values []string) []string {
	set := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		clean := filepath.Clean(value)
		if _, seen := set[clean]; seen {
			continue
		}
		set[clean] = struct{}{}
		normalized = append(normalized, clean)
	}
	sort.Strings(normalized)
	return normalized
}

func SSHTargetAllowsService(target SSHTarget, service string) bool {
	if len(target.AllowedServices) == 0 {
		return false
	}
	return slices.Contains(target.AllowedServices, service)
}

func SSHTargetAllowsPath(target SSHTarget, path string) bool {
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

// SSHTargetAllowsUploadSource reports whether a LOCAL absolute path is under one
// of the target's allowed_upload_sources prefixes. Fail-closed: an empty list
// allows nothing.
func SSHTargetAllowsUploadSource(target SSHTarget, path string) bool {
	if path == "" || len(target.AllowedUploadSources) == 0 {
		return false
	}
	clean := filepath.Clean(path)
	for _, prefix := range target.AllowedUploadSources {
		if clean == prefix || strings.HasPrefix(clean, prefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
