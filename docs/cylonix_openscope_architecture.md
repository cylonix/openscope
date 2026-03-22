# Cylonix + OpenScope Architecture

This note describes how Cylonix and OpenScope fit together as a combined security
model for OpenClaw deployments.

## Core Split

The clean product boundary is:

- **Cylonix** provides secure reach
- **OpenScope** provides secure action brokering

In other words:

- Cylonix answers: "Can this agent reach this environment right now?"
- OpenScope answers: "Given that reach, what exact actions may it perform?"

This avoids overlap:

- Cylonix is the network and environment access layer
- OpenScope is the execution and policy layer

## Why Both Layers Matter

Network reach alone is not enough.

If an agent can reach a laptop, jump host, or production server, it still should
not receive broad raw powers such as:

- unrestricted Apple Events on macOS
- unrestricted shell on a server
- unrestricted SSH into production

That is the gap OpenScope fills.

## Combined Security Story

### Cylonix

Cylonix provides:

- identity-bound, auditable reach
- task-scoped connectivity
- mesh access into private environments
- reduced standing trust
- environment isolation

### OpenScope

OpenScope provides:

- named capabilities exposed as CLI actions
- allow/deny policy at the action level
- scoped parameters such as Notes folder, Mail mailbox, or future service names
- audit logs for allow and deny decisions
- a broker that executes approved actions instead of handing raw access to the agent

## Local macOS Example

For local app access:

```text
OpenClaw
-> openscope notes read_note --agent openclaw ...
-> openscoped
-> Apple Notes
```

OpenScope is the broker for the local protected app.

## Local NemoClaw / OpenShell Example

For a sandboxed local container:

```text
OpenClaw in sandbox
-> openscope CLI in sandbox
-> mounted host OpenScope Unix socket
-> host openscoped
-> Apple Notes / Apple Mail
```

The sandbox does not get direct host shell or raw `osascript`.

## Remote Support Example

For remote support or private infrastructure:

```text
OpenClaw
-> Cylonix mesh access to on-prem environment
-> openscope ssh restart_service --target prod-app-1 --service api
-> openscoped near the protected resource
-> scoped remote executor
```

In this model:

- Cylonix provides network path
- OpenScope decides which operations are allowed once that path exists

## Design Principle

OpenScope should prefer **scoped capabilities**, not just renamed raw access.

Good examples:

- `openscope notes read_note --folder Work --note Sprint`
- `openscope mail list_messages --mailbox Inbox --limit 20`
- `openscope ssh restart_service --target prod-api --service web`
- `openscope ssh tail_logs --target prod-api --service web --lines 200`

Less desirable examples:

- `openscope ssh root@server arbitrary-shell-command`

The product value comes from replacing dangerous powers with narrower brokered
operations.

## Deployment Classes

### 1. Native Local

- `openscope` CLI installed locally
- `openscoped` daemon installed locally
- Unix socket transport

### 2. Local Sandboxed

- `openscope` CLI installed in the sandbox only
- no daemon inside the sandbox
- host `openscoped` remains the only broker
- sandbox talks to a provisioned host socket

### 3. Remote / On-Prem

- Cylonix provides just-in-time route into the environment
- OpenScope runs close to the protected resource
- OpenClaw calls OpenScope instead of holding raw credentials or raw SSH

## Near-Term Recommendation

For the current product phase:

- keep CLI + Unix socket as the primary integration model
- support client-only installs for NemoClaw/OpenShell
- use Cylonix as the reach plane and OpenScope as the broker plane
- defer broader remote deployment changes until the scoped executor model grows

## Long-Term Direction

Over time, OpenScope can evolve from a local app broker into a general scoped
capability broker with multiple executor types, for example:

- `applescript`
- `ssh`
- `systemd`
- `kubernetes`
- `http`

The core responsibility stays the same:

**OpenScope should be the policy and audit layer that gates what the agent may do
once connectivity already exists.**
