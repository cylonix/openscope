# OpenScope

**Capability broker for AI agents. Execution containment, not traffic
governance.** Instead of filtering the dangerous primitive when it appears in
the agent's traffic, OpenScope removes it from the agent's reach entirely. The
agent gets named, parameter-checked actions like `restart_service()` or
`read_note()`; credentials, automation approval, and key material stay inside
the broker.

This repo is the broker that ships today: a signed macOS daemon plus CLI that
brokers Apple Notes, Apple Mail and other Apple apps, local system operations,
SSH, AWS SSM, and HTTP for agents like Claude Code, OpenClaw, and Codex. The
same daemon runs headless on Linux as a network broker for VPC and CI use. The
team/enterprise tier (control plane, policy and audit service, out-of-band
circuit breaker, prompt-side PII router) is in active development.

→ [openscopeai.com](https://openscopeai.com) for full positioning, comparison
with gateways and MCP brokers, and the design partner program.

## What it brokers

| Executor | Surface |
|---|---|
| `applescript` | Apple Notes, Mail, Calendar, Reminders, Contacts, Safari, Messages (via the signed `asapple` helper) |
| `system` | Local sudo-free ops: packages, services, processes, ports, file perms, app install/launch, `.pkg` install, `xcodebuild` |
| `ssh` | Governed remote hosts through named targets and reviewed command templates (no ambient shell, no key material reaches the agent) |
| `ssm` | Commands on EC2 instances over AWS Systems Manager (no SSH, no inbound ports, no keys) |
| `http` | Brokered HTTP APIs such as Jira, through root-owned profiles that hold the credentials |

New verbs are added in YAML (actions, parameters, command templates) and pinned
root-owned by a reviewed `sudo openscope apply`, so the broker is not capped to
a fixed verb set and an agent still cannot rewrite the rules that confine it.

## Architecture

```
AI agent  (Claude Code, OpenClaw, Codex, ...)
  → openscope CLI          thin client, one invocation per request
  → openscope-mcp          MCP front-end: brokered verbs as schema-typed tools
  → HTTP bridge            network broker with Bearer agent tokens (VPC / CI)
  → reflector              outbound-only tunnel for scoped cross-org sharing
       ↓
  openscoped daemon        signed broker: validates the action, enforces policy,
                           executes, appends audit, returns the result
       ↓
  applescript → asapple → Apple Notes / Mail / Calendar / ...
  system                 → packages, services, processes, ports, files, apps, builds
  ssh                    → governed remote hosts
  ssm                    → EC2 over AWS Systems Manager
  http                   → brokered HTTP APIs
```

- **`openscope`** is the CLI wrapper that sends requests to the daemon over a
  Unix socket or an optional localhost HTTP bridge.
- **`openscoped`** is the signed broker daemon: it validates requests, enforces
  policy, executes actions, appends audit events, and returns results.
- **`asapple`** is a compiled Swift helper co-located with `openscoped` inside
  the signed app bundle; it is the only process that touches Apple automation
  APIs.
- **`openscope-mcp`** is an unprivileged MCP front-end that re-exposes the
  agent's currently-allowed verbs as native, schema-typed MCP tools. It holds no
  keys and no policy authority; every call still flows through the daemon.

App behavior is declared in YAML (actions, parameters, scripts, command
templates), so new integrations can be added without changing Go code.

## Build

This repo holds two Go modules in a `go.work` workspace. The root module is the
broker; `router/` is the separate AI router and console.

```bash
go build ./... && go test ./... && go vet ./...    # root module (broker)
cd router && go build ./... && go test ./...        # router module
GOOS=linux go build ./...                           # Linux network-broker cross-build
```

The `asapple` Swift helper and the signed macOS app bundle are built via Xcode.
See [`macos/XcodeSetup.md`](macos/XcodeSetup.md) for setup.

To build, sign, notarize, and package in one command (requires `.env.local`,
see `.env.local.example`):

```bash
scripts/build_release.sh --version 0.2.17              # archive → export → notarize → pkg → verify
scripts/build_release.sh --version 0.2.17 --install    # also install the pkg and run `openscope doctor`
scripts/build_release.sh --version 0.2.17 --skip-notarize   # fast local build (Gatekeeper will reject it elsewhere)
```

To re-package an already-exported app without re-archiving:
`scripts/build_pkg.sh --version 0.2.17`. The PKG installs `openscope`,
`openscoped`, `asapple`, and `openscope-mcp`.

## Quick Start

After installing the `.pkg`, an `openclaw` agent is pre-registered with default
scoped access to Apple Notes and Apple Mail:

```bash
# Verify the daemon is running
openscope status

# Ask the broker what an agent may do right now (live, policy-filtered)
openscope capabilities --agent openclaw

# List notes in a folder
openscope notes list_notes --agent openclaw --folder Work

# Read a note (--body-only for plain text suitable for piping)
openscope notes read_note --agent openclaw --folder Work --note "My Note" --body-only

# List up to 20 unread Inbox messages
openscope mail list_messages --agent openclaw --mailbox Inbox --limit 20 --unread true

# Read a message body by id
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

# Setup and diagnostics
openscope init [--force]            # reset user config to current app defaults
openscope version [--json]
openscope status
openscope doctor [--json] [--no-color]

# Proposal-based privilege review (the reviewed way to add verbs/targets/policy)
openscope plan  --file <proposal.yaml> [--json | --html [path]] [--skip-bypass-check]
sudo openscope apply --file <proposal.yaml> [--skip-bypass-check]

# Capabilities: what an agent may do, as ready-to-run commands, generated live
# from policy + app definitions + targets. This is what an agent consults to
# learn the current actions and exact command format.
openscope capabilities --agent <agent-id> [--json]

# Agent registry and network-broker tokens
openscope agent register <agent-id>
openscope agent list
openscope agent skills --agent <agent-id>          # raw JSON of provisioned actions
openscope agent token mint [--rotate] <agent-id>   # shown once
openscope agent token list
openscope agent token revoke <id|prefix>

# Cross-org sharing (scoped, ephemeral delegation over an outbound tunnel)
openscope share open --agent <issuer> --verb app.action[:k=v,...] (--to <alias> | --bearer) [--ttl 30m]
openscope share list
openscope share extend --agent <issuer> --id <osp_...> --verb app.action
openscope share revoke --id <osp_...>
openscope contact add <alias> <pubkey-base64> [--note <text>]
openscope contact list
openscope contact remove <alias>

# App management
openscope app list
openscope app show <app>
openscope app enable <app>          # user-defined apps only
openscope app disable <app>
sudo openscope app activate   --agent <agent-id> <app> [app...]
sudo openscope app deactivate --agent <agent-id> <app> [app...]
openscope app validate [--file <path>]

# Policy management
openscope policy list
openscope policy show --agent <agent-id>
openscope policy validate
sudo openscope policy allow --agent <id> --app <app> --action <action> [--<param> <value> ...]
sudo openscope policy deny  --agent <id> --app <app> --action <action> [--<param> <value> ...]

# Root-owned SSH targets
openscope ssh targets list
sudo openscope ssh targets add --alias prod-api-1 --host prod-api-1.internal --user deploy \
    [--port 22] [--identity-file <path>] [--proxy-jump <host>] \
    [--services web,worker] [--paths /etc/app.conf] [--path-prefixes /var/log/app]
sudo openscope ssh targets remove prod-api-1
openscope ssh check-bypass [--target <alias>] [--live-auth] [--json]   # does a ~/.ssh key reach a brokered host?

# Root-owned HTTP profiles (credentials stay in the profile)
openscope http profiles list
sudo openscope http profiles add --name jira-work --base-url https://example.atlassian.net \
    --headers "Authorization=Basic <token>,Accept=application/json"
sudo openscope http profiles remove jira-work

# System command bounds (which managers/packages/services/apps/build-prefixes are allowed)
openscope system commands list
sudo openscope system commands add-manager --name brew --binary /opt/homebrew/bin/brew [--sudo]
sudo openscope system commands add-package <name>
sudo openscope system commands add-service <name>
sudo openscope system commands add-app <name>
sudo openscope system commands add-build-prefix <path>
openscope system sudoers              # print sudoers entries for sudo-enabled managers

# Admin filters
openscope notes blacklist list
sudo openscope notes blacklist add <keyword>
openscope mail domains list
sudo openscope mail domains add <domain>

# Control plane (optional)
openscope enroll --control-plane <url> --code <code>
```

## Policy

Rules control which agent may call which action, with optional parameter
constraints. `deny` overrides `allow`; no matching `allow` defaults to deny.

```bash
# Allow access to a specific folder only
sudo openscope policy allow --agent my-agent --app notes --action list_notes --folder Work
sudo openscope policy allow --agent my-agent --app notes --action read_note  --folder Work

# Block a folder (overrides any allow)
sudo openscope policy deny --agent my-agent --app notes --action list_notes --folder Private
```

Policy is stored root-owned in the admin dir (`/Library/Application
Support/OpenScope` on macOS, `/etc/openscope` elsewhere) and written only via
`sudo openscope apply` / `sudo openscope policy`, so a process running as your
user cannot edit the rules that confine it. Every allow and deny decision is
appended to `~/.openscope/audit.jsonl`.

OpenScope also enforces a root-owned protected-folder blacklist. By default,
folders whose names contain `private` or `hidden` are denied even if the user
policy would otherwise allow them.

## Brokered surfaces

### SSH

The SSH verb set is **not fixed**. Seven curated actions ship with structured
output (`check_host`, `host_metrics`, `service_status`, `tail_logs`,
`read_file`, `list_dir`, `restart_service`), plus a `write_file` action, but any
action can be defined by an app definition. An action declares a remote command
template whose `{param}` placeholders are substituted with shell-quoted
parameter values (injection-safe), optionally piping a parameter to the
command's stdin; a parameter may be bound to the target's allow-lists with
`constraint: path` or `constraint: service`.

Define your own verbs the reviewed way: add them to a proposal's **`apps.add:`**
block (`executor: ssh`, a fixed `command:` template, see
[`docs/examples/claude-code/setup.proposal.yaml`](docs/examples/claude-code/setup.proposal.yaml)).
`openscope plan` shows the exact command as an `SSH-WRITE` finding, and
`sudo openscope apply` pins the definition root-owned in the admin dir, so a
same-uid agent cannot rewrite an approved command afterward. A generic-runner
template (a bare `{cmd}`, `bash -c {x}`, or `eval`) is rejected as
`SSH-SHELL-PASSTHROUGH`. `openscope ssh check-bypass` verifies that no key in
your `~/.ssh` can reach a brokered host out of band; `apply` re-runs that check
before adding a new target.

### System (sudo-free local operations)

The `system` executor lets an agent perform privileged local operations without
ever holding `sudo`. Verbs include `manage_packages`
(install/uninstall/upgrade/list), `manage_services` (start/stop/restart/status),
`manage_processes` (kill/list), `check_port` / `release_port`, `manage_files`
(chmod/chown), `manage_apps` (launch/quit/install/symlink/uninstall),
`install_pkg` (install a signed `.pkg` as root), and `build` (`xcodebuild`).

Each verb is gated by root-owned bounds: which package managers, packages,
services, app names, and build-path prefixes are allowed, plus install gates
such as `apps.allowed_team_ids` and `require_root_owned_source`. `system`
command templates never use a shell: the template is tokenized into a fixed
argv, each `{param}` lands in exactly one element, and `argv[0]` must be a
literal absolute path to a non-user-writable program. The executor refuses to
run any non-root-applied template while privileged.

### SSM (AWS Systems Manager)

The `ssm` executor runs governed Run Command on EC2 instances over AWS Systems
Manager: no SSH, no inbound ports, no key material. Curated actions ship
(`check_host`, `tail_logs`, `read_file`) and more can be added by definition.
The broker holds the AWS credentials; the IAM role is paired with an
agent-deny contract and a guard-hook defense-in-depth layer so the agent's own
identity cannot call SSM directly. Targets are root-owned in `ssm_targets.yaml`
and added through a reviewed proposal (the `ssm` plan lint surfaces the rendered
command). See [`deploy/broker/iam/`](deploy/broker/iam/) for the policy
contract.

### HTTP

For brokered HTTP integrations such as Jira, root-owned HTTP profiles hold the
base URL and credential headers; the agent names a profile and an action, never
the secret. See [`docs/jira_over_http.md`](docs/jira_over_http.md) for a worked
example.

### Mail

The default `openclaw` policy is read-only and constrained to the `Inbox`
mailbox. No attachment access is provided in the bundled app, and you can
optionally restrict readable messages to specific sender domains with the
`openscope mail domains` CLI.

## MCP front-end and Claude Code plugin

`openscope-mcp` exposes the broker's verbs to any MCP-speaking agent as native,
schema-typed tools. Each verb the agent is currently allowed to run appears as a
tool named `<app>_<action>` (for example `ssh_tail_logs`) with a JSON Schema
derived from the action's parameters, so there is no `--agent` flag and no
flag-string assembly. The tool list is exactly the agent's policy-filtered
surface, and when `sudo openscope apply` adopts a new verb the server emits
`tools/list_changed` and the new tool appears live, no restart. A policy denial
comes back as a tool error whose text ends with `(exit 3)`, mirroring the CLI's
exit-3 contract.

The `openscope` Claude Code plugin bundles the MCP server, the teaching skill,
and the guard hook in one install:

```
/plugin marketplace add cylonix/openscope
/plugin install openscope@openscope
```

Plugins cannot grant permissions, so add the allow-list to your Claude settings
once:

```json
{ "permissions": { "allow": ["mcp__plugin_openscope_openscope__*", "Bash(openscope:*)"] } }
```

The wildcard covers all current and future verbs, so a later
`sudo openscope apply` needs no re-approval. For any other MCP client:
`claude mcp add openscope -- openscope-mcp --agent claude-code`. Full details in
[`docs/mcp.md`](docs/mcp.md) and [`plugins/openscope/README.md`](plugins/openscope/README.md).

## Cross-org sharing (reflector)

`openscope share` lets an internal developer delegate a precise subset of their
own scope to an external agent or operator, without opening an inbound port or
pasting logs into a gist. The local daemon establishes an outbound-only tunnel
to an untrusted **reflector** proxy; the external party runs only the
pre-sanctioned verbs, streams scoped output, and is structurally blinded to the
network underlay, the shell, and raw credentials. Sessions self-destruct at a
TTL (default 30 minutes).

```bash
# Recipient generates an identity and sends you their public key
openscope-reflect-client keygen

# You register them as a contact, then open a scoped, time-boxed session
openscope contact add acme-vendor <pubkey-base64>
openscope share open --agent me --verb ssh.tail_logs:target=prod-api-1 --to acme-vendor --ttl 30m

# Recipient connects with the passport handle (no network access to your VPC)
openscope-reflect-client --passport <handle> --pin-fingerprint sha256:...
```

The reflector reads nothing in plaintext: payloads are sealed to the recipient's
key, so a leaked handle is useless to anyone else and the relay is a blind
forwarder. See [`remote-cross-org-support.md`](remote-cross-org-support.md) for
the full design.

## Network broker and enterprise

The daemon's HTTP listener turns a headless `openscoped` into a network broker
for VPC and CI use. It requires Bearer agent tokens
(`openscope agent token mint`) and derives the agent identity from the token;
TLS is configured via `OPENSCOPE_HTTP_TLS_CERT` / `_KEY`. On the server side the
broker can authenticate the human user behind a request (SSO via an
oauth2-proxy front, or per-user tokens) and record that identity in the audit
log. See [`docs/enterprise-broker.md`](docs/enterprise-broker.md) and the
packaging in [`deploy/broker/`](deploy/broker/). Enterprise vs personal is
configuration, not a build edition.

The optional control plane (usage metering, signed manifest fetch, enrollment)
is enabled with `openscope enroll` and is a no-op until configured.

## Configuration Layout

```
~/.openscope/                 # user-owned
  agents.yaml                 # registered agent IDs
  audit.jsonl                 # append-only decision log
  apps.d/                     # user-defined app definitions (YAML)
  contacts.yaml               # cross-org recipient public keys
  state/enabled_apps.yaml     # which user-defined apps are enabled
  run/openscoped.sock         # daemon Unix socket

<AdminDir>/                   # root-owned (/Library/Application Support/OpenScope on
  policies.yaml               #   macOS, /etc/openscope elsewhere); written only via
  protected_folders.yaml      #   `sudo openscope apply` / `sudo openscope policy`, so a
  ssh_targets.yaml            #   same-uid agent cannot edit the rules that confine it
  ssm_targets.yaml
  http_profiles.yaml
  mail_filters.yaml
  system_commands.yaml
  app_definitions.yaml        # pinned, root-owned custom verbs
  applied_state.yaml
```

`policies.yaml` is root-owned in `<AdminDir>`; the daemon reads it
(world-readable) but only root can write it. An install upgraded before its next
`sudo openscope apply` keeps reading the legacy `~/.openscope/policies.yaml`;
`apply` migrates it.

To reset your user-owned OpenScope YAML files to the current app defaults, run
`openscope init --force`.

## Adding a Custom App

1. Create a YAML manifest following the schema in [`resources/bundled/apps/notes.yaml`](resources/bundled/apps/notes.yaml).
2. Place AppleScript files alongside it (or reference them via the `script:` field).
3. Copy the manifest to `~/.openscope/apps.d/myapp.yaml`.
4. Enable it: `openscope app enable myapp`

Bundled apps (like `notes`) are always enabled and live in
[`resources/bundled/`](resources/bundled/).

To add a custom **ssh / system / ssm command verb** under a root daemon, do not
hand-edit `apps.d/`. Carry it in a proposal's `apps.add:` block so it is reviewed
and pinned root-owned (see the SSH section above and
[`setup.proposal.yaml`](docs/examples/claude-code/setup.proposal.yaml)). Under a
root daemon, agent-writable command verbs in `apps.d/` are ignored in favor of
the pinned registry.

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
| 8 | rate limited |

A denial (exit 3) is final: report it and stop, rather than retrying under a
different identity or running the raw command directly.

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

To govern a coding agent (Claude Code, Codex CLI, OpenCode, Gemini CLI, or
anything else that runs shell commands) with brokered SSH, sudo-free system
actions, AWS SSM, and per-agent policy, the fastest path is the Claude Code
plugin above. For other tools, see the guide in
[`web/public/docs/coding-agents.md`](web/public/docs/coding-agents.md)
(published at [/docs/coding-agents](https://open-scope.org/docs/coding-agents))
and the working Claude Code files in
[`docs/examples/claude-code/`](docs/examples/claude-code/).

**Teach the agent once, let it discover the rest.** Don't hand the agent a static
list of actions that drifts when policy changes. Instead give it a small, stable
guide and a self-describing surface:

- The guide is a skill, [`docs/examples/claude-code/skills/openscope/SKILL.md`](docs/examples/claude-code/skills/openscope/SKILL.md).
  Copy it to `~/.claude/skills/openscope/`, or adapt the same text into
  `AGENTS.md` for other tools. It teaches one rule: for privileged or production
  access, route through `openscope`, and ask the broker what you may do before
  calling.
- The agent then discovers the live surface with the MCP tool list or
  `openscope capabilities --agent <id>`, generated from the root-owned policy,
  app definitions, and targets, so a new or removed action shows up immediately
  with no change to the agent.

A PreToolUse guard hook
([`docs/examples/claude-code/openscope-guard.sh`](docs/examples/claude-code/openscope-guard.sh))
backs this up: it denies raw `ssh` / `sudo` to governed hosts and direct edits
of broker config, and points the agent at the skill. The MCP server offers the
sanctioned path, the skill teaches, the broker is the authority, and the hook is
the net.

## OpenClaw Integration

To use OpenScope as the security boundary for an OpenClaw agent:

- runtime instructions: [`docs/openclaw/SKILL.md`](docs/openclaw/SKILL.md)
- setup guide: [`docs/openclaw_user_guide.md`](docs/openclaw_user_guide.md)
- sandbox bridge (NemoClaw / OpenShell): [`docs/nemoclaw_socket_demo.md`](docs/nemoclaw_socket_demo.md)
- client-only sandbox install: [`docs/nemoclaw_install.md`](docs/nemoclaw_install.md)
- Cylonix + OpenScope architecture: [`docs/cylonix_openscope_architecture.md`](docs/cylonix_openscope_architecture.md)

For local native agents, use the `openscope` CLI directly. For sandboxed agents,
use the same CLI and point it at either `OPENSCOPE_SOCKET` for a provisioned Unix
socket or `OPENSCOPE_HTTP_URL` for a localhost bridge such as
`http://host.docker.internal:42357`.

Common Apple apps such as Calendar, Reminders, Contacts, Safari, and Messages are
bundled as brokered passthrough apps. They are denied by default until you opt in
with `sudo openscope app activate --agent openclaw <app>`.

## License

BSD 3-Clause, see [LICENSE](LICENSE).

## Maintainer

Built and maintained by [Randy Huang](https://linkedin.com/in/randyhuang-0b71968)
Contact: randy@cylonix.io · [github.com/cylonix](https://github.com/cylonix)
</content>
</invoke>
