// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package passport

import (
	"fmt"
	"slices"

	"github.com/openscope/openscope/capabilities"
)

// Subset reports whether `requested` is a subset of the issuer's live surface
// (capabilities.Build(issuer, ...).Capabilities). This is the issue-time guard
// behind the "delegating within your own scope needs no root ceremony" rule:
// a passport may only NARROW the issuer's grants. It is the daemon's
// authoritative check (the CLI runs the same check for fast feedback).
//
// Conservative / default-deny: anything it cannot prove ⊆ the issuer surface is
// rejected, so `share` never issues a passport the daemon would then refuse.
func Subset(requested, issuerSurface []capabilities.Capability) (bool, string) {
	for _, req := range requested {
		if ok, why := capInSurface(req, issuerSurface); !ok {
			return false, why
		}
	}
	return true, ""
}

// capInSurface reports whether the requested capability is covered by at least
// one issuer capability for the same verb (same app+action). The issuer may
// hold several rules for one verb; the requested capability must be ⊆ one of
// them in full.
func capInSurface(req capabilities.Capability, surface []capabilities.Capability) (bool, string) {
	matched := false
	for _, iss := range surface {
		if iss.App != req.App || iss.Action != req.Action {
			continue
		}
		matched = true
		if capCovers(iss, req) {
			return true, ""
		}
	}
	if matched {
		return false, fmt.Sprintf("verb %s.%s requests parameters broader than the issuer is allowed", req.App, req.Action)
	}
	return false, fmt.Sprintf("verb %s.%s is not in the issuer's allowed surface", req.App, req.Action)
}

// capCovers reports whether issuer capability `iss` covers requested `req`: every
// requested parameter must be no broader than the matching issuer parameter.
func capCovers(iss, req capabilities.Capability) bool {
	issByKey := make(map[string]capabilities.Param, len(iss.Params))
	for _, p := range iss.Params {
		issByKey[paramKey(p)] = p
	}
	for _, rp := range req.Params {
		ip, ok := issByKey[paramKey(rp)]
		if !ok {
			return false
		}
		if !paramCovers(ip, rp) {
			return false
		}
	}
	return true
}

// paramCovers reports whether issuer param `ip` permits everything requested
// param `rp` could pass.
//
//	issuer free            → covers any request
//	issuer pinned to F     → request must resolve to exactly {F}
//	issuer allow-set S     → request's value set must be ⊆ S
func paramCovers(ip, rp capabilities.Param) bool {
	issuerFree := !ip.Pinned && len(ip.AllowedValues) == 0
	if issuerFree {
		return true
	}

	// Reduce the issuer param to the set of values it permits.
	var allowed []string
	if ip.Pinned {
		allowed = []string{ip.Fixed}
	} else {
		allowed = ip.AllowedValues
	}

	switch {
	case rp.Pinned:
		return slices.Contains(allowed, rp.Fixed)
	case len(rp.AllowedValues) > 0:
		for _, v := range rp.AllowedValues {
			if !slices.Contains(allowed, v) {
				return false
			}
		}
		return true
	default:
		// Requested param is free but the issuer constrains it → broader than
		// the issuer allows.
		return false
	}
}
