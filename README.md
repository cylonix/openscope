# OpenScope

**Capability broker for AI agents. Execution containment, not traffic 
governance.** Instead of filtering the dangerous primitive when it 
appears in the agent's traffic, OpenScope removes it from the agent's 
reach entirely. The agent gets named, parameter-checked actions like 
`restart_service()` or `read_note()`; credentials, automation approval, 
and key material stay inside the broker.

This repo is the local-tier broker that ships today (v0.1.0) — a signed 
macOS daemon plus CLI, brokering Apple Notes, Apple Mail, shell, and 
SSH for agents like OpenClaw, Codex, and Claude Code. The team/enterprise 
tier (control plane, policy + audit service, out-of-band circuit breaker, 
prompt-side PII router) is in active development.

→ [openscopeai.com](https://openscopeai.com) — full positioning, 
comparison with gateways and MCP brokers, design partner program.
## Architecture

```
AI agent
  → openscope CLI          (thin client, one invocation per request)
  → openscoped daemon      (signed background process, holds macOS Automation approval)
  → asapple helper      (Swift binary that executes AppleScript in-process)
  → Apple Notes / Apple Mail
```

- **`openscope`** — CLI wrapper that sends requests to the daemon over a Unix socket
  or an optional localhost HTTP bridge
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

After installing the `.pkg`, an `openclaw` agent is pre-registered with default
scoped access to Apple Notes and Apple Mail:

```bash
# Verify the daemon is running
openscope status

# List notes in a folder
openscope notes list_notes --agent openclaw --folder Work

# Read a note
openscope notes read_note --agent openclaw --folder Work --note "My Note"

# Read just the body (plain text, suitable for piping)
openscope notes read_note --agent openclaw --folder Work --note "My Note" --body-only

# List up to 20 unread messages in Inbox
openscope mail list_messages --agent openclaw --mailbox Inbox --limit 20 --unread true

# Read a message by id
openscope mail read_message --agent openclaw --mailbox Inbox --id "<message-id>"

# Read just the message body
openscope mail read_message --agent openclaw --mailbox Inbox --id "<message-id>" --body-only

# Opt in to bundled passthrough apps such as Calendar
sudo openscope app activate --agent openclaw calendar reminders

# Validate the installed setup end to end
openscope-diag
```

## Commands

```bash
# Protected app actions
openscope <app> <action> --agent <agent-id> [flags]

# Reset user config to the current app defaults
openscope init --force

# App management
openscope app list
openscope app show <app>
openscope app enable <app>          # user-defined apps only
openscope app disable <app>
sudo openscope app activate --agent <agent-id> <app> [app...]
sudo openscope app deactivate --agent <agent-id> <app> [app...]
openscope app validate [--file <path>]

# Policy management
openscope policy list
openscope policy show --agent <agent-id>
openscope policy validate
sudo openscope policy allow --agent <id> --app <app> --action <action> [--<param> <value> ...]
sudo openscope policy deny  --agent <id> --app <app> --action <action> [--<param> <value> ...]

# Agent registry
openscope agent register <agent-id>
openscope agent list

# Capabilities — what an agent may do, as ready-to-run commands (generated live
# from policy + app definitions + targets). This is what an agent consults to
# learn the current actions and exact command format; it tracks policy changes.
openscope capabilities --agent <agent-id>          # add --json for structured output

# Protected Notes folder blacklist
openscope notes blacklist list
sudo openscope notes blacklist add private
sudo openscope notes blacklist remove hidden

# Mail sender-domain allowlist
openscope mail domains list
sudo openscope mail domains add mycompany.com
sudo openscope mail domains remove gmail.com

# Root-owned HTTP profiles
openscope http profiles list
sudo openscope http profiles add --name jira-work --base-url https://example.atlassian.net --headers "Authorization=Basic <token>,Accept=application/json"
sudo openscope http profiles remove jira-work

# Root-owned SSH targets
openscope ssh targets list
sudo openscope ssh targets add --alias prod-api-1 --host prod-api-1.internal --user deploy --services web --path-prefixes /var/log/app
sudo openscope ssh targets remove prod-api-1

# Diagnostics
openscope status
openscope doctor
```

## Policy

Rules control which agent may call which action, with optional parameter constraints.
`deny` overrides `allow`; no matching `allow` defaults to deny.

```bash
# Allow access to a specific folder only
sudo openscope policy allow --agent my-agent --app notes --action list_notes --folder Work
sudo openscope policy allow --agent my-agent --app notes --action read_note  --folder Work

# Block a folder (overrides any allow)
sudo openscope policy deny --agent my-agent --app notes --action list_notes --folder Private
```

Policy is stored root-owned in the admin dir (`/Library/Application Support/OpenScope`
on macOS, `/etc/openscope` elsewhere) and written only via `sudo openscope apply` /
`sudo openscope policy`, so a process running as your user cannot edit the rules that
confine it. Every allow and deny decision is appended to `~/.openscope/audit.jsonl`.

OpenScope also enforces a root-owned protected-folder blacklist in
`/Library/Application Support/OpenScope/protected_folders.yaml`. By default,
folders whose names contain `private` or `hidden` are denied even if the user
policy would otherwise allow them.

For brokered HTTP integrations such as Jira, root-owned HTTP profiles live in
`/Library/Application Support/OpenScope/http_profiles.yaml`. For brokered SSH
integrations, named targets live in
`/Library/Application Support/OpenScope/ssh_targets.yaml`.

The SSH verb set is **not fixed**. Seven curated actions ship with structured
output (`check_host`, `host_metrics`, `service_status`, `tail_logs`,
`read_file`, `list_dir`, `restart_service`), plus a `write_file` action — but
any action can be defined by the app YAML. An action declares a remote command
template whose `{param}` placeholders are substituted with shell-quoted
parameter values (injection-safe), optionally piping a parameter to the
command's stdin; a parameter may be bound to the target's allow-lists with
`constraint: path` or `constraint: service`. Define your own verbs in a user app
under `~/.openscope/apps.d/<app>.yaml` with `executor: ssh` (see the bundled
`write_file` for the pattern). OpenScope brokers what the YAML declares and a
root-applied policy allows — `openscope plan` surfaces every non-inspection verb
as an `SSH-WRITE` finding to confirm before apply — rather than capping the verb
set.

For Mail, the default `openclaw` policy is read-only and constrained to the
`Inbox` mailbox. No attachment access is provided in the bundled app, and you can
optionally restrict readable messages to specific sender domains with
`/Library/Application Support/OpenScope/mail_filters.yaml` or the
`openscope mail domains` CLI.

If you want to reset your user-owned OpenScope YAML files to the current app
defaults, run `openscope init --force`.

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

For a worked example of a custom HTTP-backed app, see [`docs/jira_over_http.md`](docs/jira_over_http.md).

## macOS Automation Permission

The first time `openscoped` accesses Apple Notes or Apple Mail, macOS may show a
one-time Automation prompt. Accept it, or pre-grant via:

**System Settings → Privacy & Security → Automation → OpenScope → Notes ✓ / Mail ✓**

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

## Coding Agent Integration

To govern a coding agent — Claude Code, Codex CLI, OpenCode, Gemini CLI, or
anything else that runs shell commands — with brokered SSH, sudo-free system
actions, and per-agent policy, see the guide in
[`web/public/docs/coding-agents.md`](web/public/docs/coding-agents.md)
(published at [/docs/coding-agents](https://open-scope.org/docs/coding-agents))
and the working Claude Code files in
[`docs/examples/claude-code/`](docs/examples/claude-code/).

**Teach the agent once, let it discover the rest.** Don't hand the agent a static
list of actions that drifts when policy changes. Instead give it a small, stable
guide and a self-describing CLI:

- The guide is a skill — [`docs/examples/claude-code/skills/openscope/SKILL.md`](docs/examples/claude-code/skills/openscope/SKILL.md).
  Copy it to `~/.claude/skills/openscope/` (Claude Code), or adapt the same text
  into `AGENTS.md` for other tools. It teaches one rule: *for privileged or
  production access, route through `openscope`, and ask the broker what you may do
  before calling.*
- The agent then discovers the live surface with
  `openscope capabilities --agent <id>` — generated from the root-owned policy +
  app definitions + targets, so a new or removed action shows up immediately with
  no change to the agent. The agent fills the command, caches it, and re-checks
  only when a call returns exit 3 (denied) or 4 (action moved).

A PreToolUse guard hook ([`docs/examples/claude-code/openscope-guard.sh`](docs/examples/claude-code/openscope-guard.sh))
backs this up: it denies raw `ssh`/`sudo` to governed hosts and points the agent
at the skill. The skill teaches, the broker is the authority, the hook is the net.

## OpenClaw Integration

If you want to use OpenScope as the security boundary for an OpenClaw agent:

- use the runtime instructions in [`docs/openclaw/SKILL.md`](docs/openclaw/SKILL.md)
- use the setup guide in [`docs/openclaw_user_guide.md`](docs/openclaw_user_guide.md)
- use the sandbox bridge guide in [`docs/nemoclaw_socket_demo.md`](docs/nemoclaw_socket_demo.md) for NemoClaw/OpenShell
- use the install guide in [`docs/nemoclaw_install.md`](docs/nemoclaw_install.md) for client-only sandbox installs
- use the architecture note in [`docs/cylonix_openscope_architecture.md`](docs/cylonix_openscope_architecture.md) for the Cylonix + OpenScope model

For local native agents, keep using the `openscope` CLI directly. For sandboxed
agents, use the same CLI and point it at either:

- `OPENSCOPE_SOCKET` for a provisioned Unix socket
- `OPENSCOPE_HTTP_URL` for a localhost bridge such as `http://host.docker.internal:42357`

For local setups, OpenScope agent names are best treated as policy and audit
labels. For enterprise deployments, registration and policy should be centrally
managed and distributed to devices rather than created ad hoc on each machine.

Common Apple apps such as Calendar, Reminders, Contacts, Safari, and Messages
are now bundled as brokered passthrough apps. They are still denied by default
until you opt in with `sudo openscope app activate --agent openclaw <app>`.

For Notes, a practical default is to name sensitive folders with `Private` or
`Hidden`, or add more protected keywords with
`sudo openscope notes blacklist add <keyword>`. For Mail, keep the default
scope to `Inbox` and optionally add sender-domain restrictions with
`sudo openscope mail domains add <domain>`.

## License

BSD 3-Clause — see [LICENSE](LICENSE).

## Maintainer

Built and maintained by [Randy Huang](https://linkedin.com/in/randyhuang-0b71968) 
Contact: randy@cylonix.io · [github.com/cylonix](https://github.com/cylonix)
