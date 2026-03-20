# OpenScope Pilot Guide

OpenScope is a local application access broker for AI agents. It lets authorized agents
access protected apps (like Apple Notes) via a policy-enforced, audited channel — without
repeated macOS automation permission prompts.

## Architecture Overview

```
AI agent
  -> openscope CLI          (thin client, invoked per request)
  -> openscoped daemon      (signed background process, holds macOS automation approval)
  -> Apple Notes         (via in-process AppleScript)
```

- `openscope` — CLI wrapper that sends requests to the daemon
- `openscoped` — signed background daemon, enforces policy, executes app actions, logs audit events

---

## Installation

Double-click `OpenScope-<version>.pkg` and follow the installer. No manual steps are
required — the installer handles:

- Copying `OpenScope.app` to `/Applications`
- Registering and starting the `openscoped` background service
- Installing `openscope` to `/usr/local/bin`
- Creating `~/.openscope/` with a ready-to-use `demo` agent and default policy

After the installer completes, open a terminal and verify:

```bash
openscope status
```

You should see `"running": true` in the output.

### Granting macOS Automation Permission

The first time `openscoped` accesses Apple Notes, macOS will show a one-time prompt.
Accept it. You can also pre-grant via:

**System Settings → Privacy & Security → Automation → OpenScope → Notes ✓**

---

## Quick Start

The installer creates a `demo` agent with full access to Apple Notes. Run these
immediately after install to confirm everything works:

```bash
# List all Note folders
openscope notes list_folders --agent demo

# List notes in a folder (replace "Work" with a real folder name from your Notes)
openscope notes list_notes --agent demo --folder Work

# Read a note
openscope notes read_note --agent demo --folder Work --note "My Note"

# Read just the body (plain text)
openscope notes read_note --agent demo --folder Work --note "My Note" --body-only
```

---

## Managing Agents

Register a new agent:

```bash
openscope agent register my-agent
```

List all registered agents:

```bash
openscope agent list
```

The `demo` agent is pre-registered by the installer.

---

## Managing Policy

Policy rules control which agent can call which action, with optional parameter constraints.
Rules are evaluated in order: `deny` overrides `allow`; no matching `allow` = deny by default.

### Adding allow rules

```bash
# Allow an agent to list all folders
openscope policy allow --agent my-agent --app notes --action list_folders

# Allow access to a specific folder only
openscope policy allow --agent my-agent --app notes --action list_notes --folder Work
openscope policy allow --agent my-agent --app notes --action read_note  --folder Work
```

### Adding deny rules

```bash
# Block access to a specific folder (overrides any allow)
openscope policy deny --agent my-agent --app notes --action list_notes --folder Private
openscope policy deny --agent my-agent --app notes --action read_note  --folder Private
```

### Viewing policy

```bash
# Show all rules
openscope policy list

# Show rules for one agent
openscope policy show --agent demo
```

### Validating policy

```bash
openscope policy validate
```

### Try it: block a folder and verify the deny

1. Create a folder called **Private** in Apple Notes and add a note to it.

2. Confirm the `demo` agent can currently list it:

```bash
openscope notes list_notes --agent demo --folder Private
```

3. Add a deny rule:

```bash
openscope policy deny --agent demo --app notes --action list_notes --folder Private
openscope policy deny --agent demo --app notes --action read_note  --folder Private
```

4. Try again — the request should now be denied:

```bash
openscope notes list_notes --agent demo --folder Private
# expected: {"ok": false, ...}
```

5. Confirm the audit log captured both the allow and deny decisions:

```bash
tail -5 ~/.openscope/audit.jsonl
```

---

## Apple Notes Actions Reference

### `list_folders`

List all note folders.

```bash
openscope notes list_folders --agent <agent-id>
```

```json
{"ok": true, "app": "notes", "action": "list_folders", "agent": "demo",
 "data": {"folders": ["Work", "Personal", "Private"]}}
```

### `list_notes`

List notes in a folder.

```bash
openscope notes list_notes --agent <agent-id> --folder Work
```

```json
{"ok": true, ..., "data": [{"title": "Weekly Notes"}, {"title": "Project Alpha"}]}
```

### `read_note`

Read a note's body.

```bash
openscope notes read_note --agent <agent-id> --folder Work --note "Weekly Notes"
```

```json
{"ok": true, ..., "data": {"title": "Weekly Notes", "body": "..."}}
```

Body-only mode (plain text, useful for piping into other tools):

```bash
openscope notes read_note --agent <agent-id> --folder Work --note "Weekly Notes" --body-only
```

---

## Checking Status

```bash
openscope status
```

Shows daemon liveness, socket path, config directory, and registered agent/app counts.

---

## Diagnostics

```bash
openscope doctor
```

Runs checks on config layout, policy validity, daemon reachability, and agent registry.

---

## Reviewing the Audit Log

Every allow and deny decision is recorded in `~/.openscope/audit.jsonl`.

```bash
tail -20 ~/.openscope/audit.jsonl
```

Each line includes: timestamp, agent, app, action, parameters, decision, and reason.

---

## Troubleshooting

### Daemon is not running

```bash
# Check daemon log
cat /tmp/com.ezblock.openscope.openscoped.stderr.log

# Restart the daemon
launchctl kickstart -k gui/$(id -u)/com.ezblock.openscope.openscoped
```

### Request denied unexpectedly

```bash
# Check what rules apply to your agent
openscope policy show --agent demo

# Check the audit log for the deny reason
tail -5 ~/.openscope/audit.jsonl
```

### macOS Automation permission missing

- Ensure `OpenScope.app` is in `/Applications` (signed copy, not a dev build).
- Open **System Settings → Privacy & Security → Automation**, find OpenScope, enable Notes.

### `daemon unavailable` error

```bash
ls ~/.openscope/run/openscoped.sock   # should exist
openscope status
```

If the socket is missing, restart via `launchctl kickstart` (see above).

---

## Configuration Directory

```
~/.openscope/
  agents.yaml          # registered agent identities
  policies.yaml        # access rules
  audit.jsonl          # append-only audit log
  apps.d/              # user-defined app definitions (optional)
  state/
    enabled_apps.yaml  # which user-defined apps are enabled
  run/
    openscoped.sock       # daemon Unix socket
```

---

## App Management (Advanced)

```bash
openscope app list                          # list all apps (bundled + user-defined)
openscope app show notes                    # show details for a specific app
openscope app validate /path/to/myapp.yaml  # validate a custom app definition
openscope app enable myapp                  # enable a user-defined app
openscope app disable myapp                 # disable a user-defined app
```

Bundled apps (like `notes`) are always enabled.
