// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"strings"
	"testing"
)

// A custom verb that invokes an absolute-path server-side script is ALLOWED
// (this is how existing daily scripts get wrapped) but draws SSH-SCRIPT-OPAQUE:
// plan can't read the script, so the approver owns its behavior.
func TestScriptVerbDrawsOpaqueWarning(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/var/app]}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        deploy:
          description: deploy the app
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: env, type: string}
          command: "/opt/k/deploy.sh {env}"
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: deploy, constraints: {target: prod}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	f, ok := findingByRule(findings, "SSH-SCRIPT-OPAQUE")
	if !ok {
		t.Fatal("expected SSH-SCRIPT-OPAQUE for a server-side-script verb")
	}
	if f.Severity != SevWarn {
		t.Errorf("SSH-SCRIPT-OPAQUE severity = %v, want WARN (allowed with a warning)", f.Severity)
	}
	if f.Resource != "prod:deploy" || !strings.Contains(f.Summary, "/opt/k/deploy.sh") {
		t.Errorf("SSH-SCRIPT-OPAQUE = %+v", f)
	}
	// The opaque script is NOT under the target's writable allow-list, and no
	// path-writer is granted, so it must not be flagged as agent-mutable.
	if _, ok := findingByRule(findings, "SSH-SCRIPT-WRITABLE"); ok {
		t.Error("SSH-SCRIPT-WRITABLE must not fire without a path-writer reaching the script")
	}
}

// An inline command built from standard tools (write_file = `cat > {path}`) is a
// write verb (SSH-WRITE) but NOT an opaque server-side script — the reviewer can
// read the whole template.
func TestInlineWriteVerbIsNotOpaque(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/var/app]}
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: write_file, constraints: {target: prod}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	if _, ok := findingByRule(findings, "SSH-WRITE"); !ok {
		t.Error("expected SSH-WRITE for write_file")
	}
	if f, ok := findingByRule(findings, "SSH-SCRIPT-OPAQUE"); ok {
		t.Errorf("inline write_file must not draw SSH-SCRIPT-OPAQUE, got %+v", f)
	}
}

// The agent-mutable-code gate: a target that grants BOTH a script verb and a
// path-writer (write_file), where the script lives within the target's writable
// allow-list, lets the agent overwrite the script before running it → HIGH.
func TestScriptWritableFlaggedWhenWriterReachesScript(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/opt/k]}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        deploy:
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: env, type: string}
          command: "/opt/k/deploy.sh {env}"
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: deploy, constraints: {target: prod}}
    - {effect: allow, agent: bot, app: ssh, action: write_file, constraints: {target: prod}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")

	f, ok := findingByRule(findings, "SSH-SCRIPT-WRITABLE")
	if !ok {
		t.Fatal("expected SSH-SCRIPT-WRITABLE: write_file can overwrite /opt/k/deploy.sh under the writable prefix")
	}
	if f.Severity != SevHigh || f.Resource != "prod:deploy" {
		t.Errorf("SSH-SCRIPT-WRITABLE = %+v, want HIGH prod:deploy", f)
	}
	// Agent-mutable executed code defeats the typed-broker model — it must block
	// unconditionally, with no bounds escape hatch (like SSH-SHELL-PASSTHROUGH).
	if !isBlocking(DefaultBounds(), f) {
		t.Error("SSH-SCRIPT-WRITABLE must block unconditionally")
	}
}

// No path-writer granted → the script is not agent-mutable through the broker,
// even though it lives under an allow-list prefix.
func TestScriptWritableNotFlaggedWithoutWriter(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/opt/k]}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        deploy:
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: env, type: string}
          command: "/opt/k/deploy.sh {env}"
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: deploy, constraints: {target: prod}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "SSH-SCRIPT-WRITABLE"); ok {
		t.Error("SSH-SCRIPT-WRITABLE must not fire when no path-writer verb is granted on the target")
	}
}

// A path-writer that cannot reach the script (script outside the writable
// allow-list) → not flagged.
func TestScriptWritableNotFlaggedWhenScriptOutsideWritable(t *testing.T) {
	src := `
version: 1
kind: openscope-proposal
metadata: {name: t}
ssh_targets:
  add:
    - {alias: prod, host: p.example.com, user: deploy, identity_file: /var/openscope/ssh/prod, allowed_path_prefixes: [/var/app]}
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        deploy:
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: env, type: string}
          command: "/opt/k/deploy.sh {env}"
policy:
  add:
    - {effect: allow, agent: bot, app: ssh, action: deploy, constraints: {target: prod}}
    - {effect: allow, agent: bot, app: ssh, action: write_file, constraints: {target: prod}}
`
	findings := Analyze(parse(t, src), LiveState{}, minimalDefs(), DefaultBounds(), "/nonexistent-home")
	if _, ok := findingByRule(findings, "SSH-SCRIPT-WRITABLE"); ok {
		t.Error("SSH-SCRIPT-WRITABLE must not fire when the script is outside the writable allow-list (/var/app vs /opt/k)")
	}
}
