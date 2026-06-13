---
name: openscope
description: >
  Use OpenScope (the `openscope` CLI) for any privileged or production access:
  SSH to governed/production hosts, sudo / local system changes (install or
  upgrade packages, manage services, kill processes, free ports, change file
  perms, install apps or .pkg files), and brokered macOS apps (Notes, Mail).
  When you need any of those, run `openscope capabilities --agent <id>` to learn
  the CURRENT allowed actions and the exact command form before calling — the
  surface is policy-driven and changes without notice, so never assume it.
---

# OpenScope — privileged access broker

OpenScope is the approved path for elevated access on this machine. A short-lived
CLI (`openscope`) talks to a signed root daemon that enforces a root-owned policy,
holds the SSH keys and macOS Automation grants, and audits every call. Raw `ssh`
to a governed host and raw `sudo` are blocked by a guard hook and redirected here.

**Your agent id on this machine: `claude-code`.** Always pass `--agent claude-code`.

## When to use this

Reach for `openscope` — do **not** run the raw command — whenever you need:

- SSH to a **governed / production** host (read files, tail logs, service status,
  restart a service, write a file). Raw `ssh`/`scp`/`rsync` to those hosts is denied.
- Any **`sudo` / local system** action: install/upgrade/list packages, start/stop/
  restart services, kill processes, check/free ports, chmod/chown, install an app
  or a `.pkg`, run a build. Raw `sudo` is denied.
- Brokered **macOS apps** (Apple Notes, Apple Mail, and any activated passthrough app).

Raw `ssh` to **ungoverned lab hosts** (e.g. `10.0.0.x`, adb devices) is fine — the
broker is only for governed/production and privileged-local operations.

## How to use it — discover, don't memorize

The list of actions you're allowed to run, and their exact command format, is
**generated live from the policy**. It changes when the policy changes, so never
hardcode it. Instead:

1. **Discover** the current surface:
   ```bash
   openscope capabilities --agent claude-code        # readable; --json for structured
   ```
   It prints, per allowed action, a ready-to-run command with fixed values already
   filled in (e.g. `--target kidfence-prod`) and hints for the free parameters
   (valid services, allowed path prefixes, …).
2. **Run** the command it shows, filling any `<placeholder>` from the hint. For
   valid values you can also consult `openscope ssh targets list` and
   `openscope system commands list`.
3. **Cache** what you learned for the rest of the task — no need to re-discover
   each call. Re-run `capabilities` only when something changed (see exit codes).

## Exit codes — the cache-invalidation signal

- **0** — success.
- **3** — denied by policy. Expected security behavior: report it to the user and
  stop. Do **not** work around it, switch agent labels, or run the raw command.
- **4** — unknown action/target: the surface likely changed. Re-run
  `openscope capabilities --agent claude-code` and use the current form.

## Do not edit the broker's config

`~/.openscope/` and the admin config dir (`/Library/Application Support/OpenScope/`)
are root-owned control state — do not edit them directly (the guard hook denies it).
To widen or change scope, draft a proposal and let the user review and apply it:

```bash
openscope plan  --file <proposal>.yaml      # review: consequences + lint + bounds (no sudo)
sudo openscope apply --file <proposal>.yaml  # the USER runs this, after reviewing
```
