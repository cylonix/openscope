# Design: macOS privileged helper (local privilege separation)

Status: **proposed** — phase 1 implemented (privilege-model detection + `doctor` surfacing); phases 2–4 outstanding.
Date: 2026-06-11.
Related: [`enterprise-broker.md`](enterprise-broker.md), `executor/sshexec/keyaudit.go`, `executor/systemexec/system.go`, the `proposal` bounds (`SSH-KEY-READABLE`, `SYS-SUDO-MANAGER`).

## Problem

OpenScope's security model is **execution containment**: the agent never holds the raw privileged primitive (raw ssh, raw sudo, raw Apple Events), only narrow brokered actions. That holds only if the agent cannot reach the primitive by another path.

On macOS the broker daemon `openscoped` is a **per-user LaunchAgent** (`gui/$(id -u)`, `~/Library/LaunchAgents/`). It runs as the **same uid** as the agent (Claude Code, etc.). With no uid boundary between daemon and agent, two privileged paths leak:

1. **SSH key custody.** For the daemon to use an ssh key it must read it; if the daemon (the user) can read it, the same-uid agent can too — and ssh directly, bypassing every policy rule. A root-owned `0600` key would be unreadable by the user-level daemon itself, so there is *no* file-permission configuration that is both daemon-usable and agent-unreadable. (`SSH-KEY-READABLE` now blocks this in `plan`/`doctor`, but on a per-user LaunchAgent it can never pass.)

2. **Privileged system commands.** `systemexec.run` escalates via `/usr/bin/sudo -n <binary> …` (`system.go:781`) backed by a NOPASSWD sudoers wildcard that `GenerateSudoers` writes for the daemon's user (`system.go:854`):

   ```
   <username> ALL=(root) NOPASSWD: <binary> <op> *
   ```

   That grant belongs to the **uid**, so the same-uid agent can run the identical `sudo` command directly. (`SYS-SUDO-MANAGER` already flags this HIGH/blocking.)

Both are the same gap: **on a same-uid box, privilege belongs to the uid, and the agent shares it.**

## Threat model

- **In scope:** a local, non-root agent process running as the *same user* as the daemon, trying to reach brokered hosts/commands without going through policy. The agent can read any file the user can, connect to any socket the user can, and run any command the user can (including `sudo` NOPASSWD entries).
- **Assumed:** the agent is *not* already root and cannot itself escalate (no unrelated local-root exploit). If the agent is root, nothing contains it; that is out of scope.
- **Not in scope here:** the enterprise/VPC broker, where the agent is **remote** (token-authed HTTPS) and the daemon runs as a dedicated service user with no local same-uid agent. There, file ownership by the service user already contains the (nonexistent) local agent — see *Scope* below.

## Why the obvious fixes do not work on a same-uid box

| Mechanism | Why it fails |
|---|---|
| `sudo` / NOPASSWD sudoers | The grant is keyed to the uid; the agent shares it and runs the same command. `sudo` cannot tell "the daemon asked" from "the agent asked" — both are one uid. |
| Tighter file permissions on the key | The daemon must read the key; same uid ⇒ agent reads it too. No mode/owner satisfies both. |
| Shared-secret token over a socket | A secret the non-root daemon can read is readable by the same-uid agent. |
| Unix-socket group permissions | Any process of that user/group connects — including the agent. |
| Peer-credential check (`SO_PEERCRED`/`getpeereid`) | Returns the **uid**, which is identical for daemon and agent. Insufficient when they share a uid. |

The common thread: every uid-based or secret-based mechanism collapses when daemon and agent are the same uid. The conclusion is **not** "find a stronger way to authenticate the caller" — it is that we **do not authenticate the caller at all**. Containment comes from **credential custody + policy** (below): the privileged primitive lives only in a root component that never hands it back and runs every request through a **root-owned** policy the agent cannot widen.

## Decision

Introduce a **root privileged helper**, started by `launchd` as root, that owns credentials and performs all privileged work. Keep a minimal **user-session component** for the one thing that genuinely must run in the user's GUI session (Apple-automation / TCC). Escalation comes from **launchd running the helper as root — never from `sudo`** (so no user-invokable NOPASSWD wildcard exists for the agent to abuse).

### Two components

- **Root helper (`LaunchDaemon` / `SMAppService` daemon, runs as root).**
  Owns the ssh keys (`/var/openscope/lib/.ssh`, root `0600`), performs ssh, runs privileged `system` commands **directly as root (no sudo)**, and — see below — owns the policy engine, audit log, and the socket the CLI talks to.
- **User-session helper (`LaunchAgent`, runs as the user).**
  Holds the per-user Apple-automation TCC grant and runs `asapple`. macOS TCC Automation approval is per-user and GUI-session-bound; a root daemon cannot hold it, so this must stay in the user session. It is a thin Apple-Events executor the root helper *calls into*.

### Transport: a Unix socket, not XPC

Daemon↔helper communication is a **Unix domain socket** carrying the existing `ipc.Request`/`ipc.Response` frames (`ipc.Call`) — the same machinery the CLI↔daemon path already uses. We do **not** use XPC: it buys nothing for transport, its connection-invalidation / MachServices-registration semantics are finicky and hard to debug, and (critically) it does not gate access any better — a same-uid agent can look up the same Mach service in the shared bootstrap namespace, exactly as it can `connect()` to a socket. Keeping transport on our own IPC keeps it unit-testable on Linux and consistent with the rest of the broker.

### Authentication: none — confinement by policy + custody

The helper runs as root and the agent shares the daemon's uid, so the agent can `connect()` to the helper socket. We deliberately **do not authenticate the caller**, and do not need to. A local caller can only ask the helper to perform actions, and:

- the helper **never returns the credential** — it performs ssh/system *with* the root-owned key; the key never crosses the socket; and
- the helper **runs every request through policy**, keyed to the caller's self-declared agent ID, exactly as the CLI→daemon path does today.

So a process connecting straight to the helper is confined to the same policy as if it used the CLI — it gains nothing. This matches the existing model: on the local Unix socket the agent ID is already self-asserted (`--agent <id>` is unauthenticated; only the HTTP path's bearer tokens authenticate identity). One agent **spoofing another agent's ID** is explicitly out of scope here — a separate "agent authentication" discussion — and is no worse than today.

> We investigated authenticating the connecting process by code signature (XPC `xpc_connection_set_peer_code_signing_requirement`, or `LOCAL_PEERTOKEN`→`SecCode` over a socket) and found that on a same-uid box no socket option is both supported and race-free — the audit token (`LOCAL_PEERTOKEN`, XNU `<sys/un.h>` `0x006`) is undocumented SPI, and the public `LOCAL_PEERPID` path is racy (connect → queue bytes → `execve` the signed binary). It is **moot**: confinement is policy + custody, not peer identity, so the whole question — and any XPC dependency — is dropped.

### The keystone: root-owned config and audit

"Confined by policy" is only true if the agent cannot **widen its own policy** or **erase its tracks**. Today it can, at the OS level:

- `openscope policy allow/deny`, `ssh targets add/remove`, etc. already require root (`requireRootForMutation`) — good; the *commands* are gated.
- **But** `applyProposal`/`chownTreeToInvoker` chowns `policies.yaml`, `agents.yaml`, and `audit.jsonl` back to the *invoking user*, so a same-uid agent can edit them **directly** with a text editor, sidestepping the root-gated CLI. Only the harness guard hook — not the OS — stops that today. (`ssh_targets`/`system_commands`/`bounds` already live root-owned in the admin dir.)

**The fix — and the load-bearing control of this whole design — is to make `policies.yaml`, `agents.yaml`, and `audit.jsonl` root-owned:** world-readable so the daemon reads them, root-writable so `sudo openscope apply` is the only mutation path; the audit log becomes root-append-only so the agent cannot delete its own actions. With config + audit root-owned, the existing `applied_state.yaml` attestation becomes belt-and-suspenders instead of the only defense. This is pure-Go, cross-platform, testable, and **independent of any macOS native work** — the highest-value next step.

```
openscope CLI ──connect──→ root daemon socket ──(policy, audit, ssh, system as root)
 (any local uid,             │  enforces root-owned policy on the self-declared agent ID
  no caller auth)            └─unix socket→ user LaunchAgent (asapple, holds TCC) → Apple Events
```

### `GenerateSudoers` / the sudo path

The NOPASSWD sudoers path is only safe when the daemon's user ≠ the agent's user. As of phase 3 it is **gated**: a root daemon runs privileged commands directly (no sudoers needed), and a non-root daemon refuses the `sudo -n` escalation unless `OPENSCOPE_ALLOW_SUDO_ESCALATION=1` is set — the explicit, documented opt-in for a separated-user deployment. `GenerateSudoers` / `openscope system sudoers` remains only for that opt-in case.

## Packaging

- **Preferred: `SMAppService`** (macOS 13+) — register the daemon with `SMAppService.daemon(plistName:)`; the helper plist ships in the app bundle's `Contents/Library/LaunchDaemons/`. Cleaner lifecycle than `SMJobBless`, user-approvable in System Settings → Login Items.
- **Legacy: `SMJobBless`** for older macOS — helper in `Contents/Library/LaunchServices/`, `SMPrivilegedExecutables`/`SMAuthorizedClients` code-signing requirements must match exactly between app and helper.
- Both require an **admin authorization prompt at install** and exact code-signing-requirement matching. The existing Xcode Run Script phase (which builds `openscope`/`openscoped`/`asapple` into `Contents/Resources/bin/`) gains a build of the helper and the daemon plist.

## Phased plan

- **Phase 1 (done):** privilege-model detection (`privsep.Detect`) + `doctor` reports whether the install is privilege-separated and flags local privileged brokering that isn't. No behavior change; surfaces the gap. `SSH-KEY-READABLE` (plan/doctor) and `SYS-SUDO-MANAGER` (plan) already block the two concrete bypasses.
- **Phase 2 — the keystone (DONE for `policies.yaml`):** `policies.yaml` moved from user-owned `~/.openscope/` to the root-owned `AdminDir` (world-readable so the daemon reads it; written only via root-gated `apply`/`policy`). `chownTreeToInvoker` no longer hands it back to the user; `apply` migrates an existing legacy copy and removes it; `policy.LoadDefault` reads the legacy location read-only until then. Without this, "confined by policy" was circular. **Still open:** `agents.yaml` (entangled with the non-root `agent register`/`token mint` flow; not an escalation vector on its own since a capability needs an allow *rule*, not just registration) and `audit.jsonl` root-append-only (needs the root daemon — phase 3 — since the current user-daemon must append to it).
- **Phase 3 — Go core DONE; deployment remains:** `systemexec` now runs a privileged (`sudo`-flagged) command **directly when the daemon is root** (no `sudo` wrapper, so no NOPASSWD wildcard), refuses a user-writable privileged binary on either path, and **refuses the legacy `sudo -n` escalation when non-root** unless `OPENSCOPE_ALLOW_SUDO_ESCALATION=1` is set (the separated-user deployment, daemon-uid ≠ agent-uid). The CLI socket is **world-connectable when the daemon is root** (`socketMode`), confined by policy not socket ownership; 0600 otherwise. **Remaining (deployment, needs the real env):** actually run `openscoped` as root (macOS `LaunchDaemon`/`SMAppService`; the Linux `deploy/broker` unit currently sets `User=openscope`+`NoNewPrivileges`), relocate the socket out of the invoking user's home to a system path, and the user-session `asapple` TCC shim.
- **Phase 4 — the two-daemon PKG install (full spec below).** One PKG installs **both** launchd jobs; they coexist and split by privilege domain. **No features dropped:** Notes/Mail keep working via the user-session agent, ssh/system/keys via the root daemon.

## Phase 4: the two-daemon PKG install

The PKG installs two coexisting launchd jobs that split by privilege domain. The root daemon is the single policy/audit decision point and the single CLI entry socket; it delegates *only Apple-event execution* to a user-session agent, because that is the one operation that must run in the GUI session to hold the per-user TCC grant.

### Components

- **Root broker — `openscoped` as a `LaunchDaemon`** (`/Library/LaunchDaemons/com.ezblock.openscope.openscoped.plist`, runs as **root**, `RunAtLoad`). Owns the policy engine, audit log, key custody, the ssh + system executors, and the CLI socket.
- **Session agent — `openscoped --session-helper` as a `LaunchAgent`** (`/Library/LaunchAgents/com.ezblock.openscope.session.plist`, runs as the **console user**, `LimitLoadToSessionType=Aqua`). Holds the Notes/Mail Automation (TCC) grant and runs `asapple`. Serves **only** the applescript executor — no policy, ssh, or system. Reuses the `openscoped` binary in a serve mode; no new binary.

### Request flow

```
ssh / system :  openscope CLI ─► root daemon (policy+audit, runs as root) ─► ssh/system executor
Notes / Mail :  openscope CLI ─► root daemon (policy+audit) ─► applescript executor
                                   └─► session agent socket ─► asapple in GUI session (TCC) ─► Notes/Mail
```

### The applescript-executor handoff (core code change)

Today the applescript executor spawns `asapple` directly (same uid + GUI session). A root daemon is not in the user's GUI session, so it cannot give `asapple` the TCC grant. The executor therefore gets a transport:
- **in-session** (non-root daemon — the legacy/personal model): spawn `asapple` directly, unchanged.
- **root daemon**: forward the `runnerRequest` over the session-agent socket; the agent runs `asapple` in-session and returns the result.

Policy/audit still happen once, in the root daemon, before delegation. The session agent is a dumb Apple-event executor with no policy of its own.

### Sockets

- **Root daemon CLI socket** — system path `/var/run/openscope/openscoped.sock`, mode `0666` (world-connectable, confined by policy — phase-3 `socketMode`).
- **Session agent socket** — user-session path (e.g. `~/Library/Application Support/OpenScope/run/session.sock`); root connects *down* to it. **This is the one socket that needs an access gate:** the session agent holds the Notes/Mail TCC grant and runs *no policy* (policy ran in the root daemon), so an unauthenticated socket here would be a TCC oracle a same-uid agent could use to bypass Notes/Mail policy. The gate is the **socket mode `0000`**: root bypasses DAC and connects (it's the root broker), and the kernel denies `connect(2)` to every other uid — including the same-uid agent, which a peer-uid check cannot exclude anyway. This needs **no peer-credential syscall and no new dependency** (the module stays yaml.v3-only). Built + tested in `executor/applescript/session.go`; the round-trip and the root-only gate (a non-root connect is denied with `permission denied`) are verified on darwin.
- **Resolution rule** (`config`, used by both CLI and daemon so they agree): `OPENSCOPE_SOCKET` wins; else the system socket when present (root-daemon install); else the per-user `~/.openscope/run/openscoped.sock` (legacy/personal).

### Config + audit ownership (finishes phase 2)

With the broker now root, `audit.jsonl` moves to the root-owned `AdminDir`, append-only by root — the phase-2 piece deferred because the user-daemon had to append to it. With policy/ssh_targets/system_commands/bounds already root-owned, **all control state is now root-owned**: the agent reads but cannot write.

### PKG / installer

- App bundle ships both plists in `Contents/Resources/launchd/`.
- `preinstall` (root): bootout any existing OpenScope LaunchAgent/LaunchDaemon.
- `postinstall` (root): create the root-owned `AdminDir` and `/var/run/openscope`; migrate `~/.openscope/policies.yaml` → `AdminDir` (finishing phase-2 at install); install the LaunchDaemon → `/Library/LaunchDaemons` + `launchctl bootstrap system/…`; install the session LaunchAgent → `/Library/LaunchAgents` + `launchctl bootstrap gui/<console-uid>/…`.
- `build_pkg.sh` validates both plists are present in the bundle.

### Build/verify split

- **Testable in Go now:** socket-path resolution; the applescript-executor transport seam (injectable, defaults to direct-spawn so the current path is unchanged); the `--session-helper` serve mode; audit root-ownership (guarded on the daemon being root).
- **Verify by build + install (signing / launchd / TCC env):** both launchd jobs load; the root→session Apple-event handoff preserves the Notes TCC grant; Gatekeeper/notarization via `build_release.sh`.

## Alternatives considered

- **Run `openscoped` itself as a root LaunchDaemon.** This is essentially the chosen direction (phase 3) — the only nuance is the small user-session shim that must remain for Apple-automation TCC, which a root daemon can't hold.
- **Keep `sudo`/NOPASSWD.** Rejected: it *is* the bypass on a same-uid box, and the project already flags it HIGH/blocking. The root daemon runs privileged commands directly, so no NOPASSWD wildcard exists.
- **Sandbox the agent (App Sandbox / container) instead of separating the daemon.** Complementary, not a substitute — the personal-Mac story today relies on the agent-harness guard hook (deny raw ssh/sudo) for exactly this reason. A privilege boundary in the broker is defense the harness hook can't provide once the agent has shell.
- **Authenticate the connecting process by code identity (XPC `set_peer_code_signing_requirement` / `LOCAL_PEERTOKEN`→`SecCode`).** Considered and **dropped**: unnecessary (confinement is policy + custody — the helper never returns the credential and enforces a root-owned policy), and on a same-uid box no socket option is both supported and race-free anyway (`LOCAL_PEERTOKEN` is SPI; `LOCAL_PEERPID` is racy). Removing it also removes the XPC dependency.

## Security considerations / residual risks

- The root daemon is high-value attack surface: it must validate every argument against policy (no passthrough), expose only narrow actions, and **never return a credential** or run an arbitrary command. Its safety rests on the action surface, not on who connects.
- **Root-owned config + audit is the load-bearing control.** If `policies.yaml`/`agents.yaml`/`audit.jsonl` are agent-writable, the no-caller-auth model collapses (the agent widens its own policy or erases its tracks). This must hold at the OS level, not just via the harness guard hook.
- **Agent-ID is self-asserted on the local socket** (unchanged from today). One agent impersonating another agent's ID is out of scope here; if needed, bring the HTTP path's bearer-token agent authentication to the local socket — a separate effort.
- Phase-1 detection reflects the uid that `doctor`/the daemon runs as; for a local install that equals the agent's uid, which is the case that matters. It intentionally does not flag the HTTP/VPC topology (remote agents).

## Scope

This is the **local** model (agent and daemon on the same machine, same uid: personal Mac, local Linux dev box). The **enterprise/VPC broker is unaffected**: the agent is remote over token-authed HTTPS, `openscoped` runs as a dedicated `openscope` user with `NoNewPrivileges=yes`, and key/credential ownership by that service user already contains the (nonexistent) local agent. Enterprise vs personal remains *configuration, not edition*.
