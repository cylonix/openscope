# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test

This repo holds two Go modules in a `go.work` workspace:
- root `github.com/openscope/openscope` — the broker (CLI + daemon + executors). Dependency policy: **yaml.v3 only**; anything needing AWS/pgx lives in `router/`.
- `router/` `github.com/openscope/openscope/router` — the AI router + console (`replace`s the root module with `../`).

```bash
go build ./... && go test ./... && go vet ./...        # root module
cd router && go build ./... && go test ./...           # router module
go test ./daemon/...          # single package
go test -run TestServiceHandle ./daemon/...  # single test
GOOS=linux go build ./...     # Linux broker cross-build (build-tag split must stay green)
cd router && make smoke       # full-stack Docker smoke test, mock provider, no AWS
```

CI runs each module with `GOWORK=off` to prove self-containment.

The vendor control plane lives in the **private** sibling repo `../openscope-enterprise` (open-core split: only vendor-side code is closed; its go.mod `replace`s the public module with `../ascope`).

The Xcode project in `macos/OpenScopeApp/` builds the signed macOS app bundle. Its Run Script phase calls `go build` for `openscope` and `openscoped`, and `swiftc` for `asapple`, placing all binaries into `Contents/Resources/bin/`. Build the bundle via Xcode or trigger the phase indirectly — do not manually copy binaries into a bundle.

To package for distribution (two steps):
```bash
# Step 1: Xcode → Product → Archive → Distribute App → Developer ID → Export to dist/export/
# Step 2:
scripts/build_pkg.sh --version 0.1.0   # produces dist/OpenScope-0.1.0.pkg
```

## Architecture

OpenScope is a **split-process broker**: a short-lived CLI (`openscope`) and a persistent signed daemon (`openscoped`). The daemon is the only process that holds macOS Automation approval for Apple Notes — all execution must flow through it.

### Request flow

```
openscope CLI  →(JSON over Unix socket)→  openscoped daemon  →(JSON over stdin/stdout)→  asapple
```

1. `openscope` parses CLI args, resolves `~/.openscope/run/openscoped.sock`, sends an `ipc.Request` JSON frame, reads an `ipc.Response` frame.
2. `openscoped` (`daemon.Service.Handle`) validates the app/action, checks agent registration, evaluates policy, executes via the registered `executor.Runner`, appends to the audit log, returns an `ipc.Response`.
3. The `applescript` executor spawns `asapple` (a compiled Swift binary co-located with `openscoped`). It writes a `runnerRequest` JSON to `asapple`'s stdin; `asapple` renders the AppleScript template, executes it in-process via `NSAppleScript`, and returns the result on stdout.

### Key design decisions

- **`asapple` is the Automation permission holder.** It must be co-located with `openscoped` inside the signed `OpenScope.app` bundle. The executor finds it via `os.Executable()` + sibling lookup, overridable with `OPENSCOPE_APPLESCRIPT_HELPER` for tests.
- **Bundled scripts are embedded** in the Go binary via `resources.FS` (`go:embed`). For bundled apps, `materializeScript` writes the embedded script to a temp file before passing it to `asapple`.
- **Policy constraints use `policy_key`** from the action's parameter declarations, not raw CLI flag names. `Action.PolicyContext()` maps params through `policy_key` before evaluation.
- **Deny overrides allow** in `policy.Evaluate`. Rules are scanned linearly; the first matching deny wins immediately, the first matching allow is recorded and returned only if no deny matched.
- **User-defined apps** live in `~/.openscope/apps.d/` and must be explicitly enabled via `openscope app enable <name>`. Bundled apps are always enabled (`def.Bundled = true` bypasses the enabled-apps check).

### Package responsibilities

| Package | Role |
|---|---|
| `cmd/openscope` | CLI entry point — calls `cli.Run` |
| `cmd/openscoped` | Daemon entry point — calls `daemon.ListenAndServe` |
| `cli` | Top-level command dispatch; `policy allow/deny` writes rules via `policy.AddRule` |
| `daemon` | Unix socket server (`server.go`) + request handler (`service.go`); owns exit codes |
| `ipc` | Shared `Request`/`Response` types and `Call()` client |
| `policy` | YAML policy file, `Evaluate`, `AddRule`, `Save` |
| `appdef` | YAML app definition schema, validation, `PolicyContext` |
| `executor/applescript` | Spawns `asapple`, materializes embedded scripts to temp files |
| `resources` | `go:embed` FS for bundled app YAMLs and AppleScript files |
| `agent` | Agent registry YAML — `Register`, `IsRegistered` |
| `audit` | Append-only JSONL audit log (+ optional transport metadata fields) |
| `config` | `Paths` struct and `~/.openscope/` layout; `AdminDir` is platform-split (`/etc/openscope` off-macOS) |
| `authtoken` | Shared osk_* token scheme (mint/hash/parse, HMAC+pepper) + YAML file store for broker agent tokens |
| `cpclient` | Control-plane client: non-blocking usage metering with disk spool, signed manifest fetch, enrollment. No-op unless configured |
| `router/...` | Separate module: AI router (`/v1/chat[,/completions]`, `/v1/messages`, `/v1/scan`), DLP, Ed25519 receipts, budgets, console + dashboards. See `router/README.md` |

### Enterprise/VPC topology

- The daemon's HTTP listener (`daemon/http.go`) requires Bearer agent tokens (`openscope agent token mint`) and derives the agent identity FROM the token; TLS via `OPENSCOPE_HTTP_TLS_CERT/_KEY`; plaintext on non-loopback needs `OPENSCOPE_HTTP_PLAINTEXT_OK=1`; legacy anon bridge (`OPENSCOPE_HTTP_ALLOW_ANON=1`) is loopback-only. Docs: `docs/enterprise-broker.md`, packaging: `deploy/broker/`.
- Linux builds exclude the applescript executor via build tags (`daemon/executors_*.go`); `executorFor` errors on unknown executors instead of falling back.
- Enterprise vs personal is configuration, not edition — no build-time flags.

### Adding a new app

1. Create a YAML manifest (see `resources/bundled/apps/notes.yaml` as reference) and place AppleScript files alongside it under `resources/bundled/scripts/<appname>/`.
2. The `go:embed` glob in `resources/resources.go` picks them up automatically.
3. The executor looks up the script path relative to `bundled/scripts/` using the `script:` field in the action definition.

### Adding a new executor type

Implement `executor.Runner`, register it by name in `daemon/executors_darwin.go` and/or `daemon/executors_default.go` (platform-split `defaultExecutors`), and in `daemon/service_test.go`'s stub. The `app.executor` YAML field selects it.

## Runtime Files

```
~/.openscope/
  agents.yaml            # registered agent IDs
  policies.yaml          # allow/deny rules
  audit.jsonl            # append-only decision log
  apps.d/                # user app definitions
  state/enabled_apps.yaml
  run/openscoped.sock       # Unix domain socket
```

## Tests

Tests use `t.TempDir()` and a manually constructed `config.Paths` — never the real `~/.openscope`. The daemon service tests inject a `stubExecutor` to avoid requiring a real macOS Automation prompt. There are no integration tests that require `asapple` or a live Notes database.
