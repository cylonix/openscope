# Design spec: upload-capable ("transfer") SSH actions

Status: draft / design. Target: a new SSH executor capability that lets a
reviewed, scoped verb move a **large local file** to a target without the broker
buffering the bytes — the enabling mechanism behind verbs like `load_test_build`
(ship an agent-built docker image into an isolated test sandbox).

## Motivation

`write_file` is the config-file primitive: content rides as a CLI `--content`
arg (macOS `ARG_MAX` ≈ 1 MiB) and as an in-memory JSON param (HTTP transport
caps bodies at 1 MiB, `daemon/http.go:52`). That is correct for small text and
useless for a multi-hundred-MB image tar.

The fix is **not** to stream bytes through the broker (CLI → unix socket →
daemon as a param). The principle is: **the broker orchestrates the transfer; it
never proxies the bytes.** The verb param carries a *local path* (a tiny string);
the executor — daemon-side — opens that file and streams it host→host. The IPC
only ever carried the path.

## The new capability: two mechanisms, one action kind

An "upload-capable" SSH action moves a local file to the target one of two ways:

1. **`stdin_file`** — stream the local file straight into a remote command's
   stdin. Ideal for `docker load` (no temp tar on remote disk, no cleanup). This
   is the existing command-template action with its stdin sourced from a file
   instead of a rendered string.
2. **`put_file`** — sftp the local file to a bounded remote path (a generic file
   drop). Lands a file; no remote command.

v1 ships **`stdin_file`** (covers `load_test_build`); `put_file` is phase 2.

### Schema additions (`appdef`)

`Action` gains (all optional, mutually exclusive with each other / `stdin:`):

```go
type Action struct {
    // ...existing: Description, Parameters, Output, Script, Command, Stdin...

    // StdinFile names a parameter whose VALUE is a local file path; the executor
    // opens that file and streams it to the remote Command's stdin (no buffering).
    // The referenced param must carry `constraint: local_source`. Mutually
    // exclusive with Stdin. Requires Command.
    StdinFile string `yaml:"stdin_file"`

    // PutFile (phase 2) is an sftp file drop: copy Source (a local_source param)
    // to Dest (a path param). No Command/Script.
    PutFile *PutSpec `yaml:"put_file"`
}

type PutSpec struct {
    Source string `yaml:"source"` // "{param}", param has constraint: local_source
    Dest   string `yaml:"dest"`   // "{param}", param has constraint: path
}
```

`Parameter.Constraint` gains a third value: **`local_source`** — binds the param
to the target's local-source allow-list (see below), enforced executor-side,
exactly as `path`/`service` are today.

```go
// Validate() additions:
//  - constraint ∈ {"", path, service, local_source}
//  - StdinFile and Stdin are mutually exclusive; StdinFile requires Command;
//    StdinFile must name a declared param whose constraint == local_source.
//  - PutFile.Source/Dest each name a declared param with the right constraint;
//    PutFile excludes Command/Script/Stdin/StdinFile.
//  - placeholder→param checks still apply.
```

### Scoping — BOTH ends are bound

Remote end (unchanged model): a transfer mutates the host, so `openscope plan`
surfaces it as **`SSH-WRITE`** (it falls out of the existing "non-inspection ssh
verb" rule automatically). `put_file`'s `dest` is `constraint: path` (the
target's `allowed_paths`/`allowed_path_prefixes`), same as `write_file`.

Local end (NEW, and the subtle one): the daemon runs as **root** and would now
open an arbitrary local file and ship it off-box — a data-exfil channel
(`tar: /etc/shadow` → attacker host). So the local source is fail-closed:

```go
// admin.SSHTarget gains:
AllowedUploadSources []string `yaml:"allowed_upload_sources,omitempty"`

// admin.SSHTargetAllowsUploadSource(t, absPath) bool — exact file or under a
// prefix, filepath.Clean'd, like SSHTargetAllowsPath. Empty list ⇒ deny all.
```

Per-target (not global) so a compromised grant for target A can't read local
files staged for target B. The executor validates `local_source` params against
the *resolved* target's `allowed_upload_sources` before opening the file —
`requireAllowedUploadSource()`, mirroring `requireAllowedPath` in
`executor/sshexec/ssh.go`.

### Executor changes (`executor/sshexec`)

One cross-cutting refactor: the runner stdin becomes an `io.Reader` so a file
streams instead of buffering as a string.

```go
// before: Run(name string, args []string, stdin string)
// after:  Run(name string, args []string, stdin io.Reader)
//   existing string callers wrap with strings.NewReader(s); "" → nil reader.
```

`runCommandAction`: if `action.StdinFile != ""`, resolve the named param →
`requireAllowedUploadSource(target, path)` → `os.Open` → pass the `*os.File` as
the stdin reader to `runRemote`. The file streams CLI-local-path → daemon → ssh
→ remote command. No ARG_MAX (param is a path), no IPC streaming (param is a
path), no broker buffering (executor streams the open file).

`put_file` (phase 2): a new branch that shells `sftp` (NOT legacy `scp` — its
protocol is deprecated in OpenSSH 8.8+ and carried the CVE-2019-6111
path-traversal class) with the target's `-i/-P/-o ProxyJump` and a `put <src>
<dest>` batch.

### CLI surface

Essentially unchanged — the param is a normal string that happens to be a local
path; the *executor* opens it:

```
openscope ssh load_test_build --agent claude-code --target kidfence-test \
  --tar /Volumes/2TB-1/src/kidfence/build/img.tar --build_id pr-1421
```

`openscope capabilities` should hint that a `local_source` param is "a local
file path under <allowed_upload_sources>".

### Review / lint (`proposal/lint.go`)

- **`SSH-WRITE`** — automatic (transfer verbs aren't inspection verbs).
- **`SSH-UPLOAD-SECRET`** (NEW) — grade the local source scope, mirroring the
  read-side secret classifier: an `allowed_upload_sources` prefix that reaches a
  secret/home/key path (`bounds.ssh.secret_absolute_paths`, `~`, `~/.ssh`) →
  **HIGH/blocking** (it's an exfil channel); a narrow build dir → pass/acknowledge.
- **`POLICY-DEAD-RULE`** extension — a transfer verb granted on a target with an
  empty `allowed_upload_sources` can never succeed (like the no-services case).
- The passthrough guard still applies to the remote command (the helper is a
  fixed program, so it's clean).

### Network-broker caveat

`stdin_file`/`put_file` read a file on the **daemon's** host. In the normal
local-socket deployment the daemon and the calling agent are co-located, so "the
local path" is what the agent means. Over the HTTP/VPC broker the source is on
the *broker* host, not the caller's — so transfer actions are a co-located-broker
feature; document them as such (and the 1 MiB HTTP body cap stays for param-only
requests).

## Worked example: `load_test_build`

Ship an agent-built image into an **isolated** sandbox — never prod. The verb is
a thin, typed trigger; all the dangerous decisions (the tag, the run context)
live in a fixed, root-owned server-side helper the agent cannot rewrite.

### The verb (proposal `apps.add`)

```yaml
apps:
  add:
    - version: 1
      app: {name: ssh, executor: ssh}
      actions:
        load_test_build:
          description: Stream a local image tar into an isolated test sandbox (never prod)
          stdin_file: tar                                   # NEW: stream this local file to stdin
          command: "/opt/kidfence/bin/load-test-build.sh {build_id}"
          parameters:
            - {name: target,   type: string, required: true, policy_key: target}
            - {name: tar,      type: string, required: true, constraint: local_source}  # local build tarball
            - {name: build_id, type: string, required: true}                            # [a-z0-9-]; sandbox tag suffix
```

### The target (proposal `ssh_targets.add`)

```yaml
ssh_targets:
  add:
    - alias: kidfence-test
      host: api.kidfence.ai          # or a dedicated non-prod host
      user: deploy                   # NOT root; least privilege
      identity_file: /var/openscope/ssh/kidfence-test
      allowed_upload_sources:        # NEW: the only local dir the daemon may read+ship here
        - /Volumes/2TB-1/src/kidfence/build
```

### The grant (proposal `policy.add`)

```yaml
policy:
  add:
    - {effect: allow, agent: claude-code, app: ssh, action: load_test_build, constraints: {target: kidfence-test}}
```

### The server-side helper (root-owned, reviewed ONCE; the real safety lives here)

`/opt/kidfence/bin/load-test-build.sh` — installed/owned by root, not
agent-writable. It bakes in what the verb structurally must not let the agent
choose:

```bash
#!/usr/bin/env bash
set -euo pipefail
BUILD_ID="${1:?build_id required}"
[[ "$BUILD_ID" =~ ^[a-z0-9][a-z0-9-]{0,38}$ ]] || { echo "bad build_id" >&2; exit 2; }

SANDBOX_REPO="kidfence-agent-test"
TAG="${SANDBOX_REPO}:${BUILD_ID}"
PROJECT="kidfence-test-${BUILD_ID}"          # isolated compose project name
PORT=$(( 18000 + RANDOM % 1000 ))            # ephemeral, non-prod port range

# 1) Load the tar from STDIN; capture the loaded image ID (by digest, not tag).
img_id=$(docker load -q | sed -n 's/^Loaded image.*sha256:\([0-9a-f]\{12\}\).*/\1/p' | head -n1)
[ -n "$img_id" ] || { docker load -q; echo "no image loaded" >&2; exit 1; }

# 2) Force the sandbox tag, and STRIP every tag the tar carried — so the build
#    can NEVER resolve to a prod ref (the tag-collision defense).
for t in $(docker image inspect --format '{{range .RepoTags}}{{println .}}{{end}}' "$img_id"); do
  [ "$t" = "$TAG" ] || docker rmi --no-prune "$t" >/dev/null 2>&1 || true
done
docker tag "$img_id" "$TAG"

# 3) Run ONLY isolated: own project/network, non-prod data, unprivileged, no host
#    mounts, read-only rootfs, resource-limited, ephemeral port. Never the prod
#    service, network, or volumes.
docker rm -f "$PROJECT" >/dev/null 2>&1 || true
docker run -d --name "$PROJECT" \
  --network kidfence-test-net \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --cpus 1 --pids-limit 256 \
  -e KIDFENCE_ENV=test \
  -p "127.0.0.1:${PORT}:8080" \
  "$TAG" >/dev/null

# 4) Report (JSON-ish; the broker returns stdout).
printf '{"tag":"%s","image":"%s","project":"%s","url":"http://127.0.0.1:%s"}\n' \
  "$TAG" "$img_id" "$PROJECT" "$PORT"
```

Properties this guarantees, regardless of what the agent ships:
- the build is re-tagged into a fenced repo and **every prod tag it carried is
  stripped** → no collision, no silent prod overwrite;
- it runs **unprivileged, no host mounts, isolated network/data, ephemeral
  port** → blast radius is the sandbox;
- **staging ≠ promotion** — this never touches the prod service; promoting to
  prod stays a separate, human-gated step.

## Security summary (both ends bound)

| End | Bound by | Review |
|---|---|---|
| Remote command | the fixed root-owned helper (pinned via `apps.add`) | `SSH-WRITE` (confirm) |
| Remote path (`put_file`) | `constraint: path` → `allowed_path_prefixes` | `SSH-WRITE` + path classifier |
| Local source | `constraint: local_source` → per-target `allowed_upload_sources` (fail closed) | `SSH-UPLOAD-SECRET` (blocks on secret/home/key reach) |
| Run context | the helper: unprivileged, isolated, non-prod | n/a (server-side) |

## Implementation sequencing

1. **Schema** — `Action.StdinFile` + `local_source` constraint + `Validate`
   rules (`appdef/appdef.go`); tests.
2. **Admin** — `SSHTarget.AllowedUploadSources` + `SSHTargetAllowsUploadSource`
   (`admin/ssh_targets.go`); carried by proposals already (ssh_targets block).
3. **Executor** — runner stdin → `io.Reader`; `stdin_file` branch +
   `requireAllowedUploadSource` (`executor/sshexec/ssh.go`); tests.
4. **Lint/bounds** — `SSH-UPLOAD-SECRET` source classifier, dead-rule on empty
   `allowed_upload_sources`; reuse `bounds.ssh.secret_absolute_paths` (+ home /
   `~/.ssh`); tests.
5. **CLI/capabilities** — `local_source` hint; no flag changes.
6. **Phase 2** — `put_file` (sftp) mode for generic file drops.

The `load_test_build` verb + helper ship as docs/config on top of 1–5; no further
code once the `stdin_file` mechanism exists.
