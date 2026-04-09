# Local Validation Runbook

This runbook documents the shared validation flows for this repository.
Machine-specific paths, preferred runtimes, tokens, and host-only notes should
live in an untracked `.codex-local/` directory instead of tracked docs.

## Where To Put Local Notes

Keep host-specific details in files under:

```text
.codex-local/
```

Examples:

- local Docker or VM binary paths
- preferred demo roots or external-volume locations
- required environment variables for local services
- machine-specific SSH targets used for validation

## Packaged Validation

Run the packaged validation flow with:

```bash
./scripts/pilot_test.sh
```

This validates the installed CLI and daemon, runs `openscope doctor`, and
checks the supported local app surfaces.

## OpenClaw Messaging Validation

If you want to validate the OpenClaw Cylonix plugin path, provide a real
authentication token and run:

```bash
export CYLONIX_AUTH_TOKEN="<token>"
bash scripts/openclaw_cylonix_plugin_test.sh
```

If this fails with `Authentication failed`, the plugin flow is wired up but the
token was not accepted by the local Cylonix service.

## NemoClaw Container Validation

Use the helper that starts a temporary host HTTP bridge and runs the NemoClaw
pilot in a container:

```bash
scripts/run_nemoclaw_http_bridge_test.sh
```

Optional pilot arguments are forwarded through:

```bash
scripts/run_nemoclaw_http_bridge_test.sh --folder Notes --note Example
```

Useful environment overrides:

- `ASCOPE_LOCAL_ROOT`
- `NEMOCLAW_DEMO_ROOT`
- `DOCKER_BIN`
- `OPENSCOPE_HTTP_PORT`
- `PPTXGENJS_PATH`

## SSH Validation

For scoped SSH validation, you need:

- a configured SSH target alias in root-owned admin config
- a scoped policy rule for the action and target
- the specific service or approved path you want to validate

Typical setup:

```bash
sudo openscope ssh targets add \
  --alias target-name \
  --host example.internal \
  --user root \
  --services myservice

sudo openscope policy allow \
  --agent openclaw \
  --app ssh \
  --action service_status \
  --target target-name \
  --service myservice
```

Then validate with:

```bash
openscope ssh service_status --agent openclaw --target target-name --service myservice
```
