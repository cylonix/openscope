# OpenScope

OpenScope is a local application access broker for AI agents on macOS. It lets
authorized agents access protected apps — starting with Apple Notes — through a
policy-enforced, audited channel, without repeated macOS automation prompts.

## Architecture

```
AI agent
  → openscope CLI          (thin client, one invocation per request)
  → openscoped daemon      (signed background process, holds macOS Automation approval)
  → asapple helper      (Swift binary that executes AppleScript in-process)
  → Apple Notes
```

- **`openscope`** — CLI wrapper that sends requests to the daemon over a Unix socket
- **`openscoped`** — signed broker daemon: validates requests, enforces policy, executes
  actions, appends audit events, returns results
- **`asapple`** — compiled Swift helper co-located with `openscoped` inside the signed app
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
scripts/build_pkg.sh --version 0.1.0   # produces dist/OpenScope-0.1.0.pkg
```

## Quick Start

After installing the `.pkg`, a `demo` agent is pre-registered with default Notes access:

```bash
# Verify the daemon is running
openscope status

# List Note folders
openscope notes list_folders --agent demo

# List notes in a folder
openscope notes list_notes --agent demo --folder Work

# Read a note
openscope notes read_note --agent demo --folder Work --note "My Note"

# Read just the body (plain text, suitable for piping)
openscope notes read_note --agent demo --folder Work --note "My Note" --body-only
```

## Commands

```bash
# Protected app actions
openscope <app> <action> --agent <agent-id> [flags]

# App management
openscope app list
openscope app show <app>
openscope app enable <app>          # user-defined apps only
openscope app disable <app>
openscope app validate [--file <path>]

# Policy management
openscope policy list
openscope policy show --agent <agent-id>
openscope policy validate
openscope policy allow --agent <id> --app <app> --action <action> [--<param> <value> ...]
openscope policy deny  --agent <id> --app <app> --action <action> [--<param> <value> ...]

# Agent registry
openscope agent register <agent-id>
openscope agent list

# Diagnostics
openscope status
openscope doctor
```

## Policy

Rules control which agent may call which action, with optional parameter constraints.
`deny` overrides `allow`; no matching `allow` defaults to deny.

```bash
# Allow an agent to list all Note folders
openscope policy allow --agent my-agent --app notes --action list_folders

# Allow access to a specific folder only
openscope policy allow --agent my-agent --app notes --action list_notes --folder Work
openscope policy allow --agent my-agent --app notes --action read_note  --folder Work

# Block a folder (overrides any allow)
openscope policy deny --agent my-agent --app notes --action list_notes --folder Private
```

Policy is stored in `~/.openscope/policies.yaml`. Every allow and deny decision is
appended to `~/.openscope/audit.jsonl`.

## Configuration Layout

```
~/.openscope/
  agents.yaml            # registered agent IDs
  policies.yaml          # allow/deny rules
  audit.jsonl            # append-only decision log
  apps.d/                # user-defined app definitions (YAML)
  state/
    enabled_apps.yaml    # which user-defined apps are enabled
  run/
    openscoped.sock         # daemon Unix socket
```

## Adding a Custom App

1. Create a YAML manifest following the schema in [`resources/bundled/apps/notes.yaml`](resources/bundled/apps/notes.yaml).
2. Place AppleScript files alongside it (or reference them via the `script:` field).
3. Copy the manifest to `~/.openscope/apps.d/myapp.yaml`.
4. Enable it: `openscope app enable myapp`

Bundled apps (like `notes`) are always enabled and live in [`resources/bundled/`](resources/bundled/).

## macOS Automation Permission

The first time `openscoped` accesses Apple Notes, macOS shows a one-time permission
prompt. Accept it, or pre-grant via:

**System Settings → Privacy & Security → Automation → OpenScope → Notes ✓**

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
openscope doctor          # runs all diagnostic checks
openscope status          # daemon liveness, socket path, config summary

# Restart the daemon
launchctl kickstart -k gui/$(id -u)/com.ezblock.openscope.openscoped

# Reset Notes Automation permission (triggers a fresh prompt on next use)
tccutil reset AppleEvents com.ezblock.openscope && open /Applications/OpenScope.app
```

See [`docs/pilot_guide.md`](docs/pilot_guide.md) for a full walkthrough.

## OpenClaw Integration

If you want to use OpenScope as the security boundary for an OpenClaw agent:

- use the runtime instructions in [`docs/openclaw/SKILL.md`](docs/openclaw/SKILL.md)
- use the setup guide in [`docs/openclaw_user_guide.md`](docs/openclaw_user_guide.md)

For local setups, OpenScope agent names are best treated as policy and audit
labels. For enterprise deployments, registration and policy should be centrally
managed and distributed to devices rather than created ad hoc on each machine.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
