// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package buildinfo exposes the release version of the openscope binaries,
// stamped at build time. The release build (the Xcode Run Script, driven by
// scripts/build_release.sh) injects it via:
//
//	go build -ldflags "-X github.com/openscope/openscope/buildinfo.Version=0.2.1"
//
// When built without the flag (plain `go build`, a developer's `xcodebuild`)
// Version stays "dev" and the commit falls back to the VCS revision Go records
// in the module build info. Stdlib only — the root module is yaml.v3-only.
package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// Version is the release version, stamped via -ldflags. "dev" for untagged
// builds.
var Version = "dev"

// Commit is the short VCS revision, optionally stamped via -ldflags. When
// empty it is derived from the module build info at runtime.
var Commit = ""

// Info is the full build identity, suitable for JSON output (openscope
// version --json, the doctor report).
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Get returns the resolved build identity.
func Get() Info {
	return Info{
		Version: Version,
		Commit:  commit(),
		Go:      runtime.Version(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
}

// String returns a concise one-line build identity, e.g.
// "0.2.1 (a1b2c3d4e5f6) darwin/arm64 go1.23.4".
func String() string {
	i := Get()
	s := i.Version
	if i.Commit != "" {
		s += " (" + i.Commit + ")"
	}
	return s + " " + i.OS + "/" + i.Arch + " " + i.Go
}

// commit returns the stamped commit, or the VCS revision Go embedded in the
// build info, truncated to 12 chars. Empty if neither is available.
func commit() string {
	if Commit != "" {
		return Commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				if len(s.Value) > 12 {
					return s.Value[:12]
				}
				return s.Value
			}
		}
	}
	return ""
}
