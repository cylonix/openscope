// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/agent"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/policy"
)

// LiveState is the broker config currently in force, loaded once so lint and
// diff reason about the EFFECTIVE post-apply surface (live ⊕ proposal), never
// the proposal in isolation.
type LiveState struct {
	SSHTargets admin.SSHTargets
	System     admin.SystemCommands
	Policy     policy.File
	Agents     []string
}

func LoadLiveState(paths config.Paths) (LiveState, error) {
	targets, err := admin.LoadSSHTargetsOrDefault(paths)
	if err != nil {
		return LiveState{}, err
	}
	system, err := admin.LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return LiveState{}, err
	}
	pol, err := policy.LoadDefaultOrEmpty(paths)
	if err != nil {
		return LiveState{}, err
	}
	reg, err := agent.LoadDefaultOrEmpty(paths)
	if err != nil {
		return LiveState{}, err
	}
	return LiveState{
		SSHTargets: targets,
		System:     system,
		Policy:     pol,
		Agents:     reg.Agents,
	}, nil
}

// effectiveTargets returns the SSH targets that would exist after apply.
func (p Proposal) effectiveTargets(live admin.SSHTargets) []admin.SSHTarget {
	byAlias := map[string]admin.SSHTarget{}
	var order []string
	for _, t := range live.Targets {
		if _, ok := byAlias[t.Alias]; !ok {
			order = append(order, t.Alias)
		}
		byAlias[t.Alias] = t
	}
	for _, t := range p.SSHTargets.Add {
		// AddSSHTarget keeps the existing target on alias collision, so a
		// proposed re-add does NOT override live — model that faithfully.
		if _, ok := byAlias[t.Alias]; !ok {
			order = append(order, t.Alias)
			byAlias[t.Alias] = t
		}
	}
	for _, alias := range p.SSHTargets.Remove {
		delete(byAlias, alias)
	}
	out := make([]admin.SSHTarget, 0, len(byAlias))
	for _, alias := range order {
		if t, ok := byAlias[alias]; ok {
			out = append(out, t)
		}
	}
	return out
}
