# OpenScope MCP front-end (`openscope-mcp`)

`openscope-mcp` exposes the broker's verbs to any MCP-speaking coding agent
(Claude Code, and other MCP clients) as native, schema-typed tools. It is a thin,
unprivileged front-end: it speaks MCP over stdio and forwards each tool call to
`openscoped` over the same Unix socket the `openscope` CLI uses. **It holds no
keys and no policy authority** — policy evaluation, credential custody, and audit
all stay in the daemon. MCP is additive ergonomics on top of the existing
enforcement (the guard hook + root-owned key custody), not a replacement for it.

## What it gives the agent

- **A self-describing tool surface.** Each verb the agent is currently allowed to
  run appears as an MCP tool named `<app>_<action>` (e.g. `ssh_tail_logs`), with a
  JSON Schema derived from the action's parameters. No `--agent` flag, no
  flag-string assembly.
- **A per-agent, policy-filtered list.** The tool list is exactly the agent's
  allowed surface (the same data as `openscope capabilities --agent <id>`), so
  what the agent can see is what policy permits. A parameter pinned by policy is
  injected automatically and hidden from the schema; values that vary (or come
  from a target's allow-lists) become an `enum`.
- **Dynamic updates.** When `sudo openscope apply` adopts a new verb (or a
  `policy allow` changes the surface), the server emits `tools/list_changed` and
  the client re-fetches — the new tool appears live, no restart.
- **Faithful denials.** A policy denial comes back as an MCP tool error whose text
  ends with `(exit 3)`, mirroring the CLI's exit-3 contract: final, not to be
  worked around.

The tool schema is an advisory convenience; the daemon re-evaluates policy on
every call, so a loose enum or an unexpected argument combination can still be
denied at execution time.

## Install (Claude Code)

The `openscope` plugin registers the server automatically:

```
/plugin marketplace add cylonix/openscope
/plugin install openscope@openscope
```

This requires the `openscope-mcp` binary on `PATH` — the OpenScope PKG installs it
at `/usr/local/bin/openscope-mcp`. Then add the permission allow-list (plugins
cannot grant permissions) to `~/.claude/settings.json`:

```json
{ "permissions": { "allow": ["mcp__plugin_openscope_openscope__*"] } }
```

The wildcard covers all current and future verbs from the server, so a later
`sudo openscope apply` needs no re-approval.

### Manual registration (any MCP client)

```
claude mcp add openscope -- openscope-mcp --agent claude-code
```

## Agent identity

The server resolves its agent identity from, in order: the `--agent` flag,
`OPENSCOPE_AGENT_ID`, `OPENSCOPE_AGENT`, then the default `claude-code` (matching
the guard hook's convention). On the local Unix socket the identity is asserted
in the request, trusted because it is same-uid — exactly as the CLI does.

## Scope

v1 targets the **local, co-located** deployment: the MCP server runs on the same
host as the daemon and reads the policy/app-definition/ssh-target files directly
to build the tool list. A remote split (server on a laptop, broker in a VPC) is a
follow-up: tool *execution* already works over the daemon's token-authenticated
HTTP listener via `ipc.Call`, but tool *discovery* would need a daemon-side
capabilities endpoint so the list can be fetched over HTTP rather than read from
local files.

## How it relates to the CLI

`openscope-mcp` and the `openscope capabilities` command share one
implementation (the `capabilities` package), so the MCP tool surface and the CLI
surface never drift. The CLI remains the fallback path and the thing the guard
hook redirects raw commands to.
