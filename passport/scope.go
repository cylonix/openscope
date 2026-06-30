// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package passport

import (
	"fmt"
	"slices"

	"github.com/openscope/openscope/capabilities"
)

// Scope is the in-memory attenuation derived from a passport's sanctioned
// capabilities. It is a deny-only overlay: Permits answers whether a request is
// INSIDE the delegated subset. It is never an authority on its own — the daemon
// also runs policy.Evaluate under the issuer principal and requires BOTH to pass.
type Scope struct {
	caps []capabilities.Capability
}

// NewScope builds a Scope over a copy of the sanctioned capabilities.
func NewScope(caps []capabilities.Capability) Scope {
	return Scope{caps: slices.Clone(caps)}
}

// Capabilities returns the sanctioned capabilities (for projection/display).
func (s Scope) Capabilities() []capabilities.Capability {
	return slices.Clone(s.caps)
}

// Permits reports whether (app, action, policyCtx) is inside the delegated
// scope. policyCtx must be exactly appdef.Definition.PolicyContext(action,
// params) — the same policy-key-keyed map policy.Evaluate consumes — so scope
// and policy speak one language.
//
// Default-deny. The verb must be sanctioned (matching app+action). Because an
// issuer may hold several allow rules for one verb (e.g. service=a and
// service=b), same-verb capabilities form a UNION: the request is permitted if
// ANY sanctioned capability for that verb permits it. For one capability, each
// sanctioned parameter must satisfy:
//   - Pinned: the context value must equal Fixed.
//   - AllowedValues set: a PROVIDED context value must be a member (a narrowing
//     to specific values inside the issuer's surface). An absent value is left
//     to the required-param and policy checks upstream.
//   - free (neither): the passport adds no constraint; policy + executor
//     allow-lists still bound it.
func (s Scope) Permits(app, action string, policyCtx map[string]string) (bool, string) {
	reason := fmt.Sprintf("verb %s.%s is not in the passport scope", app, action)
	for _, c := range s.caps {
		if c.App != app || c.Action != action {
			continue
		}
		if ok, why := capPermits(c, policyCtx); ok {
			return true, ""
		} else {
			reason = why
		}
	}
	return false, reason
}

func capPermits(c capabilities.Capability, policyCtx map[string]string) (bool, string) {
	for _, p := range c.Params {
		val := policyCtx[paramKey(p)]
		switch {
		case p.Pinned:
			if val != p.Fixed {
				return false, fmt.Sprintf("param %q is pinned to %q in this passport", p.Name, p.Fixed)
			}
		case len(p.AllowedValues) > 0:
			if val != "" && !slices.Contains(p.AllowedValues, val) {
				return false, fmt.Sprintf("param %q value %q is not in the passport's allowed set", p.Name, val)
			}
		}
	}
	return true, ""
}

func paramKey(p capabilities.Param) string {
	if p.PolicyKey != "" {
		return p.PolicyKey
	}
	return p.Name
}
