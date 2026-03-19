# AgentScope

AgentScope is a local application access broker for AI agents on macOS. It lets
authorized agents access protected apps — starting with Apple Notes — through a
policy-enforced, audited channel, without repeated macOS automation prompts.

## Architecture

```
AI agent
  → ascope CLI          (thin client, one invocation per request)
  → ascoped daemon      (signed background process, holds macOS Automation approval)
  → asapple helper      (Swift binary that executes AppleScript in-process)
  → Apple Notes
```

- **`ascope`** — CLI wrapper that sends requests to the daemon over a Unix socket
- **`ascoped`** — signed broker daemon: validates requests, enforces policy, executes
  actions, appends audit events, returns results
- **`asapple`** — compiled Swift helper co-located with `ascoped` inside the signed app
  bundle; the only process that directly touches Apple automation APIs

App behavior is declared in YAML — actions, parameters, scripts — so new integrations
can be added without changing Go code.

## Build

```bash
go build ./...
go test ./...
go vet ./...
```

The `asapple` Swift helper and the signed macOS app bundle are built via Xcode.
See [`macos/XcodeSetup.md`](macos/XcodeSetup.md) for setup instructions.

To package for distribution:

```bash
# Step 1: Xcode → Product → Archive → Distribute App → Developer ID → export to dist/export/
# Step 2:
scripts/build_pkg.sh --version 0.1.0   # produces dist/AgentScope-0.1.0.pkg
```

## Quick Start

After installing the `.pkg`, a `demo` agent is pre-registered with default Notes access:

```bash
# Verify the daemon is running
ascope status

# List Note folders
ascope notes list_folders --agent demo

# List notes in a folder
ascope notes list_notes --agent demo --folder Work

# Read a note
ascope notes read_note --agent demo --folder Work --note "My Note"

# Read just the body (plain text, suitable for piping)
ascope notes read_note --agent demo --folder Work --note "My Note" --body-only
```

## Commands

```bash
# Protected app actions
ascope <app> <action> --agent <agent-id> [flags]

# App management
ascope app list
ascope app show <app>
ascope app enable <app>          # user-defined apps only
ascope app disable <app>
ascope app validate [--file <path>]

# Policy management
ascope policy list
ascope policy show --agent <agent-id>
ascope policy validate
ascope policy allow --agent <id> --app <app> --action <action> [--<param> <value> ...]
ascope policy deny  --agent <id> --app <app> --action <action> [--<param> <value> ...]

# Agent registry
ascope agent register <agent-id>
ascope agent list

# Diagnostics
ascope status
ascope doctor
```

## Policy

Rules control which agent may call which action, with optional parameter constraints.
`deny` overrides `allow`; no matching `allow` defaults to deny.

```bash
# Allow an agent to list all Note folders
ascope policy allow --agent my-agent --app notes --action list_folders

# Allow access to a specific folder only
ascope policy allow --agent my-agent --app notes --action list_notes --folder Work
ascope policy allow --agent my-agent --app notes --action read_note  --folder Work

# Block a folder (overrides any allow)
ascope policy deny --agent my-agent --app notes --action list_notes --folder Private
```

Policy is stored in `~/.agentscope/policies.yaml`. Every allow and deny decision is
appended to `~/.agentscope/audit.jsonl`.

## Configuration Layout

```
~/.agentscope/
  agents.yaml            # registered agent IDs
  policies.yaml          # allow/deny rules
  audit.jsonl            # append-only decision log
  apps.d/                # user-defined app definitions (YAML)
  state/
    enabled_apps.yaml    # which user-defined apps are enabled
  run/
    ascoped.sock         # daemon Unix socket
```

## Adding a Custom App

1. Create a YAML manifest following the schema in [`resources/bundled/apps/notes.yaml`](resources/bundled/apps/notes.yaml).
2. Place AppleScript files alongside it (or reference them via the `script:` field).
3. Copy the manifest to `~/.agentscope/apps.d/myapp.yaml`.
4. Enable it: `ascope app enable myapp`

Bundled apps (like `notes`) are always enabled and live in [`resources/bundled/`](resources/bundled/).

## macOS Automation Permission

The first time `ascoped` accesses Apple Notes, macOS shows a one-time permission
prompt. Accept it, or pre-grant via:

**System Settings → Privacy & Security → Automation → AgentScope → Notes ✓**

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 2 | invalid command or parameters |
| 3 | denied by policy |
| 4 | target not found |
| 5 | executor or automation failure |
| 6 | configuration or manifest error |
| 7 | daemon unavailable or IPC failure |

## Troubleshooting

```bash
ascope doctor          # runs all diagnostic checks
ascope status          # daemon liveness, socket path, config summary

# Restart the daemon
launchctl kickstart -k gui/$(id -u)/com.ezblock.agentscope.ascoped

# Reset Notes Automation permission (triggers a fresh prompt on next use)
tccutil reset AppleEvents com.ezblock.agentscope && open /Applications/AgentScope.app
```

See [`docs/pilot_guide.md`](docs/pilot_guide.md) for a full walkthrough.

## OpenClaw Integration

If you want to use AgentScope as the security boundary for an OpenClaw agent:

- use the runtime instructions in [`docs/openclaw/SKILL.md`](docs/openclaw/SKILL.md)
- use the setup guide in [`docs/openclaw_user_guide.md`](docs/openclaw_user_guide.md)

For local setups, AgentScope agent names are best treated as policy and audit
labels. For enterprise deployments, registration and policy should be centrally
managed and distributed to devices rather than created ad hoc on each machine.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
