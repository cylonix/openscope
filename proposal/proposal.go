// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package proposal implements the typed privilege-grant proposal that an agent
// drafts and `openscope plan` reviews, replacing a hand-run `sudo bash
// setup.sh`. A proposal is declarative YAML over the same admin/policy types
// the broker already validates; plan renders consequences + lint findings +
// bounds verdict; apply writes it through the existing admin code paths after
// per-risk confirmation.
package proposal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/policy"
	"gopkg.in/yaml.v3"
)

const Kind = "openscope-proposal"

type Proposal struct {
	Version        int           `yaml:"version"`
	Kind           string        `yaml:"kind"`
	Metadata       Metadata      `yaml:"metadata"`
	SSHTargets     SSHTargetsBlk `yaml:"ssh_targets"`
	SystemCommands SystemBlk     `yaml:"system_commands"`
	Policy         PolicyBlk     `yaml:"policy"`

	// Derived, never serialized.
	SHA256 string `yaml:"-"`
	Source string `yaml:"-"`
}

type Metadata struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	AuthoredBy  AuthoredBy `yaml:"authored_by"`
	CreatedAt   string     `yaml:"created_at"`
}

type AuthoredBy struct {
	Tool    string `yaml:"tool"`
	Model   string `yaml:"model"`
	Session string `yaml:"session"`
}

type SSHTargetsBlk struct {
	Add    []admin.SSHTarget `yaml:"add"`
	Remove []string          `yaml:"remove"`
}

// AddRemove is the add/remove verb pair used by every system allow-list so a
// proposal expresses deltas, not desired state — matching the idempotent
// admin.Add*/Remove* code paths.
type AddRemove struct {
	Add    []string `yaml:"add"`
	Remove []string `yaml:"remove"`
}

type AddRemoveInt struct {
	Add    []int `yaml:"add"`
	Remove []int `yaml:"remove"`
}

type ManagersBlk struct {
	Add    []admin.ManagerConfig `yaml:"add"`
	Remove []string              `yaml:"remove"`
}

type SystemBlk struct {
	Packages struct {
		Managers ManagersBlk `yaml:"managers"`
		Allowed  AddRemove   `yaml:"allowed"`
		Blocked  AddRemove   `yaml:"blocked"`
	} `yaml:"packages"`
	Services struct {
		Allowed        AddRemove `yaml:"allowed"`
		AllowLaunchctl *bool     `yaml:"allow_launchctl"`
	} `yaml:"services"`
	Processes struct {
		AllowedSignals AddRemove `yaml:"allowed_signals"`
		AllowedNames   AddRemove `yaml:"allowed_names"`
		AllowKillByPID *bool     `yaml:"allow_kill_by_pid"`
	} `yaml:"processes"`
	Ports struct {
		Allowed AddRemoveInt `yaml:"allowed"`
	} `yaml:"ports"`
	Files struct {
		AllowedChmodPrefixes AddRemove `yaml:"allowed_chmod_prefixes"`
		AllowedChownPrefixes AddRemove `yaml:"allowed_chown_prefixes"`
	} `yaml:"files"`
	Apps struct {
		AllowedSourcePrefixes AddRemove `yaml:"allowed_source_prefixes"`
		AllowedInstallDirs    AddRemove `yaml:"allowed_install_dirs"`
		AllowedNames          AddRemove `yaml:"allowed_names"`
	} `yaml:"apps"`
	Pkg struct {
		AllowedPrefixes  AddRemove `yaml:"allowed_prefixes"`
		RequireRootOwned *bool     `yaml:"require_root_owned"`
		AllowedTeamIDs   AddRemove `yaml:"allowed_team_ids"`
	} `yaml:"pkg"`
	Builds struct {
		AllowedProjectPrefixes AddRemove `yaml:"allowed_project_prefixes"`
	} `yaml:"builds"`
}

type PolicyBlk struct {
	Add    []policy.Rule `yaml:"add"`
	Remove []policy.Rule `yaml:"remove"`
}

// Load reads, hashes, parses, and validates a proposal file.
func Load(path string) (Proposal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Proposal{}, fmt.Errorf("read proposal: %w", err)
	}
	return Parse(data, path)
}

func Parse(data []byte, source string) (Proposal, error) {
	var p Proposal
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Proposal{}, fmt.Errorf("parse proposal: %w", err)
	}
	sum := sha256.Sum256(data)
	p.SHA256 = hex.EncodeToString(sum[:])
	p.Source = source
	if err := p.Validate(); err != nil {
		return Proposal{}, err
	}
	return p, nil
}

func (p Proposal) Validate() error {
	if p.Version == 0 {
		return fmt.Errorf("proposal version is required")
	}
	if strings.TrimSpace(p.Kind) != Kind {
		return fmt.Errorf("proposal kind must be %q, got %q", Kind, p.Kind)
	}
	for _, t := range p.SSHTargets.Add {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("ssh_targets.add: %w", err)
		}
	}
	for i, r := range p.Policy.Add {
		if r.Effect != "allow" && r.Effect != "deny" {
			return fmt.Errorf("policy.add[%d]: effect must be allow or deny, got %q", i, r.Effect)
		}
		if r.Agent == "" || r.App == "" || r.Action == "" {
			return fmt.Errorf("policy.add[%d]: agent, app, and action are required", i)
		}
	}
	return nil
}

// Agents returns the distinct agent IDs named in the proposal's policy rules.
func (p Proposal) Agents() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range append(append([]policy.Rule{}, p.Policy.Add...), p.Policy.Remove...) {
		if _, ok := seen[r.Agent]; ok || r.Agent == "" {
			continue
		}
		seen[r.Agent] = struct{}{}
		out = append(out, r.Agent)
	}
	return out
}

// EffectiveSystem applies the proposal's system_commands deltas onto a live
// config and returns the result that would be in force after apply.
func (p Proposal) EffectiveSystem(live admin.SystemCommands) admin.SystemCommands {
	s := p.SystemCommands
	out := live
	for _, m := range s.Packages.Managers.Add {
		if _, ok := admin.FindManager(out, m.Name); !ok {
			out.Packages.Managers = append(out.Packages.Managers, m)
		}
	}
	out.Packages.Allowed = mergeStrings(out.Packages.Allowed, s.Packages.Allowed)
	out.Packages.Blocked = mergeStrings(out.Packages.Blocked, s.Packages.Blocked)
	out.Services.Allowed = mergeStrings(out.Services.Allowed, s.Services.Allowed)
	if s.Services.AllowLaunchctl != nil {
		out.Services.AllowLaunchctl = *s.Services.AllowLaunchctl
	}
	out.Processes.AllowedSignals = mergeStrings(out.Processes.AllowedSignals, s.Processes.AllowedSignals)
	out.Processes.AllowedNames = mergeStrings(out.Processes.AllowedNames, s.Processes.AllowedNames)
	if s.Processes.AllowKillByPID != nil {
		out.Processes.AllowKillByPID = *s.Processes.AllowKillByPID
	}
	out.Ports.Allowed = mergeInts(out.Ports.Allowed, s.Ports.Allowed)
	out.Files.AllowedChmodPrefixes = mergeStrings(out.Files.AllowedChmodPrefixes, s.Files.AllowedChmodPrefixes)
	out.Files.AllowedChownPrefixes = mergeStrings(out.Files.AllowedChownPrefixes, s.Files.AllowedChownPrefixes)
	out.Apps.AllowedSourcePrefixes = mergeStrings(out.Apps.AllowedSourcePrefixes, s.Apps.AllowedSourcePrefixes)
	out.Apps.AllowedInstallDirs = mergeStrings(out.Apps.AllowedInstallDirs, s.Apps.AllowedInstallDirs)
	out.Apps.AllowedNames = mergeStrings(out.Apps.AllowedNames, s.Apps.AllowedNames)
	out.Pkg.AllowedPrefixes = mergeStrings(out.Pkg.AllowedPrefixes, s.Pkg.AllowedPrefixes)
	out.Pkg.AllowedTeamIDs = mergeStrings(out.Pkg.AllowedTeamIDs, s.Pkg.AllowedTeamIDs)
	if s.Pkg.RequireRootOwned != nil {
		out.Pkg.RequireRootOwned = *s.Pkg.RequireRootOwned
	}
	out.Builds.AllowedProjectPrefixes = mergeStrings(out.Builds.AllowedProjectPrefixes, s.Builds.AllowedProjectPrefixes)
	return out
}

func mergeStrings(live []string, d AddRemove) []string {
	out := append([]string{}, live...)
	for _, v := range d.Add {
		if !contains(out, v) {
			out = append(out, v)
		}
	}
	if len(d.Remove) == 0 {
		return out
	}
	kept := out[:0] // in-place filter; out is a fresh copy, so live is untouched
	for _, v := range out {
		if !contains(d.Remove, v) {
			kept = append(kept, v)
		}
	}
	return kept
}

func mergeInts(live []int, d AddRemoveInt) []int {
	out := append([]int{}, live...)
	for _, v := range d.Add {
		if !containsInt(out, v) {
			out = append(out, v)
		}
	}
	if len(d.Remove) == 0 {
		return out
	}
	kept := out[:0]
	for _, v := range out {
		if !containsInt(d.Remove, v) {
			kept = append(kept, v)
		}
	}
	return kept
}

func contains(s []string, v string) bool { return slices.Contains(s, v) }

func containsInt(s []int, v int) bool { return slices.Contains(s, v) }
