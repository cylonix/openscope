# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test

```bash
go build ./...
go test ./...
go test ./daemon/...          # single package
go test -run TestServiceHandle ./daemon/...  # single test
go vet ./...
```

The Xcode project in `macos/AgentScopeApp/` builds the signed macOS app bundle. Its Run Script phase calls `go build` for `ascope` and `ascoped`, and `swiftc` for `asapple`, placing all binaries into `Contents/Resources/bin/`. Build the bundle via Xcode or trigger the phase indirectly — do not manually copy binaries into a bundle.

To package for distribution (two steps):
```bash
# Step 1: Xcode → Product → Archive → Distribute App → Developer ID → Export to dist/export/
# Step 2:
scripts/build_pkg.sh --version 0.1.0   # produces dist/AgentScope-0.1.0.pkg
```

## Architecture

AgentScope is a **split-process broker**: a short-lived CLI (`ascope`) and a persistent signed daemon (`ascoped`). The daemon is the only process that holds macOS Automation approval for Apple Notes — all execution must flow through it.

### Request flow

```
ascope CLI  →(JSON over Unix socket)→  ascoped daemon  →(JSON over stdin/stdout)→  asapple
```

1. `ascope` parses CLI args, resolves `~/.agentscope/run/ascoped.sock`, sends an `ipc.Request` JSON frame, reads an `ipc.Response` frame.
2. `ascoped` (`daemon.Service.Handle`) validates the app/action, checks agent registration, evaluates policy, executes via the registered `executor.Runner`, appends to the audit log, returns an `ipc.Response`.
3. The `applescript` executor spawns `asapple` (a compiled Swift binary co-located with `ascoped`). It writes a `runnerRequest` JSON to `asapple`'s stdin; `asapple` renders the AppleScript template, executes it in-process via `NSAppleScript`, and returns the result on stdout.

### Key design decisions

- **`asapple` is the Automation permission holder.** It must be co-located with `ascoped` inside the signed `AgentScope.app` bundle. The executor finds it via `os.Executable()` + sibling lookup, overridable with `ASCOPE_APPLESCRIPT_HELPER` for tests.
- **Bundled scripts are embedded** in the Go binary via `resources.FS` (`go:embed`). For bundled apps, `materializeScript` writes the embedded script to a temp file before passing it to `asapple`.
- **Policy constraints use `policy_key`** from the action's parameter declarations, not raw CLI flag names. `Action.PolicyContext()` maps params through `policy_key` before evaluation.
- **Deny overrides allow** in `policy.Evaluate`. Rules are scanned linearly; the first matching deny wins immediately, the first matching allow is recorded and returned only if no deny matched.
- **User-defined apps** live in `~/.agentscope/apps.d/` and must be explicitly enabled via `ascope app enable <name>`. Bundled apps are always enabled (`def.Bundled = true` bypasses the enabled-apps check).

### Package responsibilities

| Package | Role |
|---|---|
| `cmd/ascope` | CLI entry point — calls `cli.Run` |
| `cmd/ascoped` | Daemon entry point — calls `daemon.ListenAndServe` |
| `cli` | Top-level command dispatch; `policy allow/deny` writes rules via `policy.AddRule` |
| `daemon` | Unix socket server (`server.go`) + request handler (`service.go`); owns exit codes |
| `ipc` | Shared `Request`/`Response` types and `Call()` client |
| `policy` | YAML policy file, `Evaluate`, `AddRule`, `Save` |
| `appdef` | YAML app definition schema, validation, `PolicyContext` |
| `executor/applescript` | Spawns `asapple`, materializes embedded scripts to temp files |
| `resources` | `go:embed` FS for bundled app YAMLs and AppleScript files |
| `agent` | Agent registry YAML — `Register`, `IsRegistered` |
| `audit` | Append-only JSONL audit log |
| `config` | `Paths` struct and `~/.agentscope/` layout |

### Adding a new app

1. Create a YAML manifest (see `resources/bundled/apps/notes.yaml` as reference) and place AppleScript files alongside it under `resources/bundled/scripts/<appname>/`.
2. The `go:embed` glob in `resources/resources.go` picks them up automatically.
3. The executor looks up the script path relative to `bundled/scripts/` using the `script:` field in the action definition.

### Adding a new executor type

Implement `executor.Runner`, register it by name in `daemon.NewService`'s `Executors` map and in `daemon/service_test.go`'s stub. The `app.executor` YAML field selects it.

## Runtime Files

```
~/.agentscope/
  agents.yaml            # registered agent IDs
  policies.yaml          # allow/deny rules
  audit.jsonl            # append-only decision log
  apps.d/                # user app definitions
  state/enabled_apps.yaml
  run/ascoped.sock       # Unix domain socket
```

## Tests

Tests use `t.TempDir()` and a manually constructed `config.Paths` — never the real `~/.agentscope`. The daemon service tests inject a `stubExecutor` to avoid requiring a real macOS Automation prompt. There are no integration tests that require `asapple` or a live Notes database.
