# Spec: SSM executor + code-immutability governance

Status: **Phases 1–4 implemented** (branch `phase1-code-custody`, commits
`3ebf53f`, `c789d8e`, `b6045f0`, `3c87928`). This document is the design of
record; those commits are the code. One deviation from the original sketch: the
SSH code-custody check is plan-time (the executed script lives on the remote
target, not a local file), so Phase 1 shipped as lint rather than an executor
file-stat — see Phase 1 below. Remaining follow-ups are under "Out of scope".

## Why

Govern **agentic access to AWS instances**. AWS SSM is an excellent keyless
transport (no inbound ports, no SSH keys, CloudTrail + Session Manager
recording) but a *coarse* authorization layer: `AWS-RunShellScript` is arbitrary
root, IAM is instance/document-grained, and the agent typically holds the AWS
credential itself. OpenScope adds what's missing — **per-verb least privilege,
human-behind-the-agent attribution, and credential custody** — uniformly with
the SSH/system executors, under one policy + audit + `plan` plane.

A second goal, equally important for adoption: stop forcing teams to decompose
their daily SSH/SSM scripts into new typed verbs. We relax the prior "no opaque
server-side scripts" stance — safely — via a **code-immutability rule**.

**Non-goals:** not a session-recording engine (use native Session Manager); not
a credential vendor to the agent (that defeats custody); not a replacement for
SSM transport. Interactive shells/tunnels are explicitly out of the verb model.

## Core principle: custody of *code* (agent-mutable vs immutable)

The line that matters is **not opaque vs inspectable — it's agent-mutable vs
immutable.** This is the SSH-key custody principle applied to the executed
artifact: the key must be agent-*unreadable*; the executed code must be
agent-*unwritable*.

- **Agent can influence what runs** — inline `bash -c {cmd}`, a param `eval`'d,
  or a script under an agent-writable path → **block** (arbitrary execution in
  disguise).
- **Server-resident, agent-immutable artifact** — a fixed binary/script
  (`/opt/ops/x.sh {env}`) or a pinned SSM document, with only typed/constrained
  params flowing in → **allow, with a warning.** `plan` can't read its behavior,
  but the agent can't alter it, so it's trusted server config.

Per-transport, "immutable" is established differently:

| Transport | Executed artifact | Immutability mechanism | Who enforces |
|---|---|---|---|
| inline template | command string | pinned root-owned in the applied registry | `apply` (existing) |
| SSH server-side script | `/abs/path/script` | root-owned / not agent-writable (file + dir + symlinks) | executor at point-of-use (new; `keyaudit` sibling) |
| SSM | custom document | agent denied `ssm:UpdateDocument` (IAM) | AWS IAM (deployment contract) |

**plan-warn / executor-enforce split** (mirrors `keyaudit` today): `plan` warns
from the agent/user vantage ("runs a server-side script I can't inspect — ensure
it's root-owned, agent-unwritable, and treats params as data"); the **root
executor enforces** at run time (refuse if the script is agent-writable —
catches TOCTOU). For SSM the enforcement is IAM, verified at deploy, reminded at
`plan`.

### Honest limits (the warning must say these)

Immutability is **necessary, not sufficient** for behavioral safety:
1. **Behavioral opacity** — the script may be destructive; immutability only
   proves the agent didn't write it, not that the approver was wise.
2. **Transitive trust** — sourced files, binaries in agent-writable dirs,
   `curl|bash` inside. The executor audits the file + its dir; it can't chase the
   full dependency graph.
3. **Params-as-code** — a script that `eval`s a param re-opens arbitrary exec.
   OpenScope's `constraint`/quoting stops shell-arg breakout, not the script
   misusing its own inputs.
4. **External IAM state** — `plan` can't verify the agent's AWS identity is
   actually SSM-denied. It reminds; it can't guarantee.

`plan` **advises**; for the worst classes it **blocks**. It never claims a
guarantee it can't make.

---

## Phase 1 — code-immutability rule + SSH retrofit (no AWS; ship first) ✅ DONE
<!-- Shipped as plan-time lint (3ebf53f): SSH-SCRIPT-OPAQUE (warn, allow opaque
server-side scripts) + SSH-SCRIPT-WRITABLE (unconditional block — a writer verb
can overwrite a run-script = agent-mutable code). The remote-script reality made
a local executor file-stat N/A; the composition gate covers it. -->


This lands value immediately, de-risks the principle, and is fully unit-testable.

Today a verb that wraps a server-side script (e.g. `command: /opt/ops/x.sh
{env}`) is **silently allowed** — `/opt/ops/x.sh` is not a shell/deputy
(`proposal/lint.go` `systemDeputies`), so `SSH-SHELL-PASSTHROUGH` doesn't fire,
and nothing audits whether the script is agent-writable. We add:

- **Executor (`executor/sshexec/`)** — a script-tamper audit, sibling to
  `keyaudit.go` (reuse `pathIsUnder`, symlink-following, `syscall.Stat_t`
  owner/mode checks). When a verb's resolved command invokes an absolute-path
  script/binary, audit the file + its directory: root-owned, not group/world-
  writable, not under an agent-writable/`~`-owned path, symlinks resolved. Codes
  (sshexec `KeyWarning`-style): `ScriptAgentWritable` (critical → executor
  **refuses**, like an agent-readable key), `ScriptLooseDir` (warning).
- **Lint (`proposal/lint.go`)** — new findings:
  - `SSH-SCRIPT-OPAQUE` (`SevWarn`) — verb runs a server-side script `plan`
    can't inspect; lists the four residual responsibilities above. Always emitted
    for script-wrapping verbs.
  - `SSH-SCRIPT-WRITABLE` (`SevHigh`) — when the planner *can* see the script is
    agent-writable (user-vantage); the executor still enforces at runtime for the
    0700-dir case it can't see (same split as `SSH-KEY-READABLE`).
- **Tests** — agent-writable script → executor refuses; root-owned immutable
  script → runs, `plan` warns; symlink-to-writable caught.

Net: wrapping an existing immutable script becomes **first-class** for SSH —
"point a verb at your script, accept a warning that you own its behavior."

---

## Phase 2 — `ssmexec` executor ✅ DONE
<!-- c789d8e: executor/ssmexec (aws CLI shell-out, no SDK) + credaudit + admin
ssm_targets + bundled ssm app (check_host/tail_logs/read_file) + Dockerfile
awscli. Deferred: pinned custom-document verbs (appdef Document field), structured
built-in output, request-id/user in the SSM --comment. -->


Mirror `executor/sshexec/` with SSM as transport.

- **Transport: shell out to the `aws` CLI** (`aws ssm send-command` +
  `aws ssm get-command-invocation`), via the pluggable `CommandRunner` pattern
  `sshexec` uses. **No AWS SDK** → the root module stays `yaml.v3`-only
  (CLAUDE.md dependency policy); the broker Dockerfile adds `awscli` exactly as
  it adds `openssh-client`. This matches `sshexec` shelling out to `ssh`.
- **Targets (`admin/ssm_targets.go`, new):** `SSMTarget{ alias, instance_id (or
  tag selector), region, allowed_documents, allowed_services, allowed_paths,
  allowed_path_prefixes }`. No host/identity_file/key custody — SSM needs none.
- **Verb shapes:**
  1. **Built-in read-only verbs** (`check_host`, `host_metrics`, `tail_logs`,
     `service_status`, `read_file`, `list_dir`) — run **broker-fixed** commands
     via `AWS-RunShellScript`. Safe because the command is broker-controlled, not
     agent input (same as the SSH built-ins).
  2. **Custom pinned-document verbs (preferred)** — `document: <name>` +
     parameters; agent picks the document (from `allowed_documents`) + typed
     params, never the command body. Smallest analysis surface for `plan`.
  3. **Custom inline-template verbs** — a fixed `command:` template run via
     `AWS-RunShellScript`; subject to the *same* passthrough/disruptive lint as
     SSH (no `bash -c {cmd}`).
- **Credential resolution + cred-audit:** the broker uses a **custodied** AWS
  identity — the EC2 **instance role** on the broker box (no static secret), or a
  **root-owned 0600 creds file** off-EC2 (`AWS_SHARED_CREDENTIALS_FILE` in the
  root daemon's env only). A `credaudit` (the `keyaudit` analog) refuses to run
  if the resolved creds come from an agent-readable/ambient source. On a
  co-located box, IMDS must be locked to root (IMDSv2 + hop-limit + iptables
  owner-match); in the remote-agent topology the agent never touches that box.
- **Audit correlation:** stamp the OpenScope `request_id` + `user` into the SSM
  `--comment` so CloudTrail/Session-Manager logs carry the human, tied to the
  OpenScope audit row.
- **Registration:** add `"ssm"` to `daemon/executors_darwin.go` /
  `executors_default.go` and the `service_test.go` stub; `app.executor: ssm` in
  appdef.

---

## Phase 3 — SSM `plan` lint ruleset (tiered) ✅ DONE
<!-- b6045f0: SSM-RUNSHELL-ARBITRARY (block), SSM-DEPLOY-CONTRACT (warn),
SSM-BROAD-SCOPE (warn); proposals may now ship executor: ssm verbs. -->


Reuse `proposal/lint.go` (`Severity`, `systemDeputies`, `systemWriters`,
`placeholderRE`). Tiers: **block** (un-approvable) / **recommend-reject**
(`SevHigh`/`SevMedium`, loud, human decides) / **info** (`SevWarn`).

| Code | Sev | Fires when |
|---|---|---|
| `SSM-RUNSHELL-ARBITRARY` | High → **block** | document is `AWS-RunShellScript` with an agent-supplied `commands` param, or an inline `{cmd}` passthrough. The #1 SSM check. |
| `SSM-SHELL-PASSTHROUGH` | High → **block** | inline template uses a shell/deputy (reuse `systemDeputies`). |
| `SSM-CRED-AMBIENT` | High | broker AWS creds resolve from an ambient/agent-readable source (cred-audit; runtime-enforced, `plan`-warned). |
| `SSM-BROAD-IAM` | Medium | proposal's broker role grants `ssm:SendCommand` on `Resource:*` or permits arbitrary documents (when IAM is in the proposal). |
| `SSM-BROAD-SCOPE` | Warn | policy rule grants the verb with no instance/target constraint. |
| `SSM-AGENT-NOT-DENIED` | Warn | reminder: `plan` can't verify the agent identity is SSM-denied; points to the boundary/SCP template. |
| `SSM-DISRUPTIVE` | Warn | destructive shape in an inline template (reuse `systemWriters` + a denylist: `rm -rf`, `dd`, `mkfs`, `shutdown`, sudoers/systemd/authorized_keys writes). |
| `SSM-DOC-PINNED` | Pass | uses a named custom document — the good path. |

Plus the cross-transport `SSH-SCRIPT-OPAQUE`/`-WRITABLE` from Phase 1 apply to
SSM document/script references conceptually (SSM immutability is IAM, so it
surfaces as `SSM-AGENT-NOT-DENIED` rather than a file check).

---

## Phase 4 — deployment contract + defense-in-depth ✅ DONE
<!-- 3c87928: deploy/broker/iam/ (agent-ssm-deny boundary/SCP + least-priv
broker-ssm-role + README) and the guard hook denying raw aws ssm send-command /
start-session and ssh i-…; docs/enterprise-broker.md SSM section. -->


- **Agent-deny is the load-bearing control.** Ship an IAM **permission-boundary
  / SCP template** that denies the agent principal `ssm:SendCommand` /
  `ssm:StartSession` / `ssm:UpdateDocument` on governed instances/documents.
  Custody of the broker's creds is necessary-not-sufficient; this is the binding
  constraint. Airtight only in the remote-agent topology (agent holds no AWS
  identity in the account).
- **Least-privilege broker role:** scope to specific instance ARNs + a custom
  document; deny `AWS-RunShellScript` where possible.
- **Guard hook** denies raw `aws ssm send-command` / `start-session` (and
  `ssh i-*` over SSM ProxyCommand) from the agent and redirects to `openscope` —
  defense-in-depth, not the boundary (can't hook boto3/SDK).

## Out of scope (documented, not built)

- **Interactive shells / port-forwarding** → native Session Manager with S3/
  CloudWatch recording. OpenScope may gate the *start* (a coarse allow/deny verb
  + attribution) but never governs in-session. Don't reinvent session recording.
- **Migration assist (optional later):** mine CloudTrail `SendCommand` history /
  runbooks → draft candidate verbs; scaffold-a-verb-from-a-script. Turns "rewrite
  everything" into "review drafts." Compelling adoption demo; not v1.

## Files to change (ascope)

- `executor/sshexec/`: add `scriptaudit.go` (sibling to `keyaudit.go`); wire the
  refusal into `Run`.
- `executor/ssmexec/` (new): `ssm.go`, `credaudit.go`; reuse the script/code
  audit helper.
- `admin/ssm_targets.go` (new): `SSMTargets`/`SSMTarget` + load/normalize, like
  `ssh_targets.go`.
- `daemon/executors_darwin.go` + `executors_default.go` + `service_test.go`:
  register `"ssm"`.
- `proposal/lint.go`: `SSH-SCRIPT-OPAQUE/-WRITABLE` + the `SSM-*` rules.
- `resources/bundled/apps/`: an `ssm.yaml` app manifest (built-in read-only verbs
  + an example pinned-document custom verb).
- Dockerfile(s) (`deploy/broker/Dockerfile`): `apk add aws-cli`.
- `docs/enterprise-broker.md`: SSM section + the IAM boundary/SCP template.

## Phasing & verification

1. **Phase 1 (SSH retrofit + code rule)** — pure broker, unit-tested
   (agent-writable → refuse; immutable → warn+run; symlink case). Ship first.
2. **Phase 2 (`ssmexec`)** — `CommandRunner` fake in tests asserts the
   `aws ssm send-command` argv + output parsing; no live AWS needed.
3. **Phase 3 (lint)** — table-driven `plan` tests per finding code.
4. **Phase 4 (contract + hook)** — IAM template + guard-hook rule; live demo
   against the demo's two EC2 instances over SSM (no SSH, no open port 22).

All under `go build/test/vet`, `GOOS=linux build`, `GOWORK=off`.

## Open questions

- Built-in read-only verbs via `AWS-RunShellScript` vs requiring a pinned
  read-only document — trade convenience for a tighter IAM (deny RunShellScript
  entirely). Lean: offer both; recommend pinned-document in hardened mode.
- Tag-selector targets (fan-out to many instances) — powerful but widens blast
  radius; gate behind a `plan` finding + an explicit max-instances bound
  (`POLICY-MAX-TARGETS` analog).
