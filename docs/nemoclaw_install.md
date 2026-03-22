# OpenScope Client Install For NemoClaw

This guide describes the recommended way to use OpenScope from a sandboxed
NemoClaw or OpenShell deployment.

## Deployment Model

For sandboxed deployments, install only the `openscope` CLI inside the sandbox.

Do not install:

- `openscoped`
- the macOS app bundle
- `asapple`

Those stay on the host or protected endpoint where OpenScope actually executes
the scoped action.

The client inside the sandbox talks to a provisioned broker:

- over a mounted Unix socket when the sandbox shares a host filesystem boundary
- or over a localhost HTTP bridge when the runtime makes direct socket reuse awkward

The CLI remains the interface in both cases.

## Release Artifact

Build a Linux client tarball from the OpenScope repo:

```bash
scripts/build_client_release.sh --version 0.1.0 --goos linux --goarch arm64
```

Example output:

```text
dist/client/openscope-0.1.0-linux-arm64.tar.gz
```

The archive contains:

- `bin/openscope`
- `LICENSE`
- `README.txt`

## Install In The Sandbox

Inside the NemoClaw or OpenShell image/bootstrap:

1. Download or copy the matching OpenScope client tarball
2. Extract it
3. Place `openscope` on `PATH`
4. Set one broker transport variable

Example:

```bash
tar -xzf openscope-0.1.0-linux-arm64.tar.gz
install -m 0755 openscope-linux-arm64/bin/openscope /usr/local/bin/openscope
```

## Transport Options

### Option 1: Mounted Unix Socket

```bash
export OPENSCOPE_SOCKET=/var/run/openscope/openscoped.sock
```

Optional read-only mounts:

```bash
export OPENSCOPE_CONFIG_DIR=/host/openscope-config
export OPENSCOPE_ADMIN_DIR=/host/openscope-admin
```

### Option 2: Localhost HTTP Bridge

Host:

```bash
export OPENSCOPE_HTTP_LISTEN=127.0.0.1:42357
```

Sandbox:

```bash
export OPENSCOPE_HTTP_URL=http://host.docker.internal:42357
```

The CLI stays the same:

```bash
openscope status
openscope notes list_notes --agent openclaw --folder Work
openscope mail list_messages --agent openclaw --mailbox Inbox --limit 20 --unread true
```

## App Security Modes

The broker supports two app security modes:

- `protected`
  Parameter constraints participate in policy evaluation. Use this for apps like
  Notes and Mail, where folder or mailbox scoping matters.
- `passthrough`
  Policy applies only at the app/action level. Use this for lower-risk apps that
  still need brokering through OpenScope, but do not yet have a refined scoped model.

The CLI surface does not change. The mode is declared in the app manifest and
enforced by the broker.

## Guidance For OpenClaw

Inside NemoClaw, prefer:

- `openscope` for protected local app access
- `openscope` for future brokered remote operations
- never raw `osascript` for apps OpenScope already brokers
- never direct raw `ssh` when a scoped OpenScope operation exists
