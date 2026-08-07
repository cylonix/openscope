// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appdef

import (
	"strings"
	"testing"
)

func contractDef(mutate func(*Action)) Definition {
	a := Action{
		Command: "docker load && docker-compose up -d web",
		Parameters: []Parameter{
			{Name: "target", Type: "string", PolicyKey: "target"},
			{Name: "image", Type: "string", Constraint: "local_source"},
		},
		StdinFile: "image",
	}
	mutate(&a)
	return Definition{
		Version: 1,
		App:     App{Name: "ssh", Executor: "ssh"},
		Actions: map[string]Action{"deploy_web": a},
	}
}

func TestValidateVerifyAndMediaContracts(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Action)
		wantErr string // "" means valid
	}{
		{"valid-full", func(a *Action) {
			a.StdinMedia = "docker-image"
			a.StdinPlatform = "linux/amd64"
			a.Verify = "curl -sf localhost:8003/"
			a.VerifyRetries = 2
			a.VerifyDelaySeconds = 10
		}, ""},
		{"verify-without-command", func(a *Action) {
			a.Command = ""
			a.Script = "x.scpt"
			a.StdinFile = ""
			a.Parameters = a.Parameters[:1]
			a.Verify = "true"
		}, "verify requires a command"},
		{"retries-without-verify", func(a *Action) {
			a.VerifyRetries = 1
		}, "require a verify command"},
		{"retries-out-of-range", func(a *Action) {
			a.Verify = "true"
			a.VerifyRetries = 11
		}, "verify_retries must be between"},
		{"delay-out-of-range", func(a *Action) {
			a.Verify = "true"
			a.VerifyDelaySeconds = 301
		}, "verify_delay_seconds must be between"},
		{"verify-undeclared-param", func(a *Action) {
			a.Verify = "check {nope}"
		}, "undeclared parameter"},
		{"verify-references-local-source", func(a *Action) {
			a.Verify = "check {image}"
		}, "must not appear in the command/stdin/verify template"},
		{"media-without-stdin-file", func(a *Action) {
			a.StdinFile = ""
			a.Parameters = a.Parameters[:1]
			a.StdinMedia = "docker-image"
		}, "stdin_media requires stdin_file"},
		{"unknown-media", func(a *Action) {
			a.StdinMedia = "tarball"
		}, "unknown stdin_media"},
		{"platform-without-media", func(a *Action) {
			a.StdinPlatform = "linux/amd64"
		}, "stdin_platform requires stdin_media"},
		{"malformed-platform", func(a *Action) {
			a.StdinMedia = "docker-image"
			a.StdinPlatform = "amd64"
		}, "must be os/arch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def := contractDef(tc.mutate)
			err := def.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
