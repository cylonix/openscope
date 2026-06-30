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

A proposal carries deltas to `ssh_targets`, `system_commands`, `policy`, and
`apps` (custom verbs). See `setup.proposal.yaml` in this example dir for a fully
annotated template to copy from.

### Defining a NEW action (a custom verb)

`capabilities` lists actions you may already run. To add a brokered command that
does **not exist yet**, granting a policy rule alone is not enough — the command
itself must be defined and reviewed, or `plan` flags the rule dead
(`POLICY-DEAD-RULE`). Put **both** in the proposal:

- an **`apps.add`** entry — a fixed `command:` template (`executor: ssh`) with
  typed `{param}` arguments. Never a generic `bash -c {cmd}` / bare `{cmd}` /
  `eval` (blocked as `SSH-SHELL-PASSTHROUGH`); use `constraint: path|service` to
  bind a param to the target's allow-lists.
- a **`policy.add`** allow rule naming the same `app`/`action`.

`plan` shows the exact command as an `SSH-WRITE` finding for the user to confirm;
`apply` pins it root-owned so it can't be altered after approval. Minimal shape:

```yaml
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        gen_promo:
          description: Generate a promo code on the host
          parameters:
            - {name: target, type: string, policy_key: target}
            - {name: code,   type: string}
          command: "/opt/kidfence/bin/gen-promo --code {code}"
policy:
  add:
    - {effect: allow, agent: claude-code, app: ssh, action: gen_promo, constraints: {target: kidfence-prod}}
```

#### Uploading a large local file (e.g. a docker image)

`--content`-style params are config-file sized (~1 MiB). To stream a large local
artifact — say a built image tar into `docker load` — give the verb a
**`stdin_file`** that names a parameter with **`constraint: local_source`**: the
daemon opens that local file and streams it straight to the remote command's
stdin (no size limit, no broker buffering). The local path is fenced by the
target's **`allowed_upload_sources`** (fail-closed; the planner blocks a source
that reaches home/`~/.ssh`/secrets). Note: the daemon reads the file on the
broker host, and a root daemon can't read external/removable volumes — stage the
file on an internal path. Keep the verb scoped and the dangerous logic (image
re-tag, isolated run) in a fixed server-side script, never agent-chosen.

```yaml
ssh_targets:
  add:
    - alias: kidfence-test
      host: api.kidfence.ai
      user: deploy
      identity_file: /var/openscope/ssh/kidfence-test
      allowed_upload_sources: [/private/tmp/kidfence-build]   # internal, fenced
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        load_test_build:
          description: Stream a local image tar into an ISOLATED test sandbox (never prod)
          stdin_file: tar                                      # tar's VALUE is a local file, streamed to stdin
          command: "/opt/kidfence/bin/load-test-build.sh {build_id}"
          parameters:
            - {name: target,   type: string, policy_key: target}
            - {name: tar,      type: string, constraint: local_source}
            - {name: build_id, type: string}
policy:
  add:
    - {effect: allow, agent: claude-code, app: ssh, action: load_test_build, constraints: {target: kidfence-test}}
```

See `docs/transfer-actions.md` for the full design (scoping, the helper script
that forces a sandbox tag + isolated run, and the network-broker caveat).
