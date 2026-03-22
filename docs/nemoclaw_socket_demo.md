# OpenScope + NemoClaw Local Bridge Demo

This guide shows how to let a sandboxed NemoClaw or OpenShell deployment use the
host OpenScope broker while keeping `openscope` as the CLI interface inside the
sandbox.

## Goal

Recreate the important brokered parts of [`scripts/pilot_test.sh`](../scripts/pilot_test.sh)
from inside a sandboxed agent environment:

- verify the mounted OpenScope socket is reachable
- verify the default `openclaw` Notes and Mail policy works through the broker
- verify policy denials still apply from the sandbox

This setup does not give the sandbox direct host shell or `osascript` access.
All Notes and Mail access still flows through the host `openscoped` daemon.

The intended deployment model is:

- host macOS runs `openscoped`
- sandbox installs only the `openscope` CLI
- sandbox does not run its own daemon
- sandbox reaches the host broker through either a provisioned mounted socket or
  a localhost HTTP bridge

## Transport Choices

OpenScope already uses JSON over a Unix domain socket between `openscope` and
`openscoped`.

That gives two sandbox bridge options:

1. Unix socket bridge
2. Localhost HTTP bridge

The CLI stays the same in both cases.

## Required Interface

The sandboxed client only needs:

- a broker endpoint
- the `openscope` CLI or another client that speaks the same JSON request/response protocol

Environment variables:

- `OPENSCOPE_SOCKET`
  Overrides the default socket path and should point at the mounted host socket.
- `OPENSCOPE_HTTP_URL`
  Optional localhost bridge URL such as `http://host.docker.internal:42357`.
- `OPENSCOPE_CONFIG_DIR`
  Optional. Use this when mounting the host `~/.openscope` config directory read-only.
- `OPENSCOPE_ADMIN_DIR`
  Optional. Use this when mounting the host admin config directory read-only.

The request shape is:

```json
{
  "app": "mail",
  "action": "list_messages",
  "agent": "openclaw",
  "params": {
    "mailbox": "Inbox",
    "limit": "20",
    "unread": "true"
  },
  "mode": "json"
}
```

## Option 1: Unix Socket Bridge

Minimum mount:

- host `~/.openscope/run/`
- container `/var/run/openscope/`

Recommended optional read-only mounts:

- host `~/.openscope/`
- container `/host/openscope-config/`
- host `/Library/Application Support/OpenScope/`
- container `/host/openscope-admin/`

These optional mounts let the sandbox validate host-side config without granting
it write access.

## Option 2: Localhost HTTP Bridge

This is often easier to reason about with Docker Desktop style runtimes.

Host:

```bash
export OPENSCOPE_HTTP_LISTEN=127.0.0.1:42357
```

Sandbox:

```bash
export OPENSCOPE_HTTP_URL=http://host.docker.internal:42357
```

You can still mount host config/admin directories read-only for inspection.

## Client-Only Install Model

For NemoClaw or OpenShell, the recommended local setup is a **client-only**
OpenScope install inside the sandbox:

- install only the `openscope` CLI binary in the sandbox
- do not install `openscoped` inside the sandbox
- do not try to run a second broker in the container
- let the host macOS broker remain the single policy and execution authority

This keeps the agent model simple:

- native OpenClaw uses local `openscope`
- sandboxed OpenClaw also uses `openscope`

Only the transport path differs.

## Environment In The Sandbox

Set:

```bash
export OPENSCOPE_SOCKET=/var/run/openscope/openscoped.sock
export OPENSCOPE_CONFIG_DIR=/host/openscope-config
export OPENSCOPE_ADMIN_DIR=/host/openscope-admin
```

For HTTP bridge mode, set `OPENSCOPE_HTTP_URL` instead of `OPENSCOPE_SOCKET`.
Only one transport variable is required.

## Colima On An External Volume

If your internal disk is tight, keep Colima state on the external volume.

Example:

```bash
mkdir -p /Volumes/2TB-1/colima/openshell
mkdir -p /Volumes/2TB-1/openscope-nemoclaw-demo
```

The repo includes helper scripts under `scripts/` to prepare a client-only demo
bundle and wrapper commands for this external-volume layout.

Recommended host-side demo root:

```text
/Volumes/2TB-1/openscope-nemoclaw-demo/
  bin/              # linux openscope client build
  workspace/        # mounted sandbox workspace
  env.sh            # exported OPENSCOPE_* variables
```

## Validation From Inside The Sandbox

Run:

```bash
bash scripts/nemoclaw_pilot_test.sh --folder Work --note "Sprint Plan"
```

This validates:

- mounted socket reachability
- `openclaw` Notes folder enumeration deny
- Notes read/list through the host broker
- Mail `Inbox` list/read through the host broker
- non-`Inbox` Mail deny
- unregistered-agent reject
- unknown-app reject

If `OPENSCOPE_CONFIG_DIR` and `OPENSCOPE_ADMIN_DIR` are mounted, it also checks:

- host `openclaw` registration
- default Notes + Mail `Inbox` policy
- presence of the host admin config files

## What This Does Not Do

This does not attempt to recreate host-only installation checks from
[`scripts/pilot_test.sh`](../scripts/pilot_test.sh), such as:

- app bundle presence under `/Applications`
- LaunchAgent status
- local host TCC/Automation database inspection

Those remain host-side checks and should still be run with the regular pilot
test on macOS.
