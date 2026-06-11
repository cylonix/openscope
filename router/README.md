# OpenScope AI Router

The governed LLM proxy of OpenScope: every agent/model call flows through
**auth → model policy → budget → DLP → provider → signed receipt**, in your
own VPC. Together with the OpenScope broker (`openscoped`, the action
side), it forms the agent trust perimeter: what agents *see* and what
agents *do*.

- **Agent-compatible endpoints** — OpenAI dialect (`/v1/chat/completions`:
  Cursor, Codex CLI, Cline, Aider, Continue) and Anthropic dialect
  (`/v1/messages`: Claude Code) over one governed pipeline, plus the native
  `/v1/chat` and a standalone `/v1/scan`.
- **DLP at the perimeter** — built-in IP-exfiltration tiers (HDL/EDA
  sources, export-control markers, secrets, PII), extensible/replaceable
  via YAML (`configs/dlp.example.yaml`). Deny-by-default restricted
  workspaces block by channel, not classifier luck.
- **Signed receipts** — Ed25519 over canonical JSON: model, region,
  decision, rule IDs, token counts, body *hashes* (never bodies), policy +
  ruleset versions. Verifiable offline by auditors (`pkg/receipts`).
- **Privacy boundary in Postgres** — `vendor_reader` cannot SELECT
  `sensitive.*`; the database engine refuses, not application middleware.
- **Budgets** — per-tenant monthly soft caps (`monthly_budget_usd`,
  deployment default via env), designed to pair with a cloud-side hard cap
  (`deploy/iam-bedrock.md`).
- **Providers** — AWS Bedrock (assume-role + external ID into your own
  account) or `mock` for offline evaluation; the `provider.Invoker`
  interface is the seam for Anthropic/OpenAI/Azure direct.
- **Dashboards** — developer / IT / vendor-ops views (`web/`), backed by
  the role-scoped console API.

## Run it

```bash
cd deploy
../scripts/generate_secrets.sh > .env
echo OPENSCOPE_PROVIDER=mock >> .env     # offline eval; drop for Bedrock
docker compose --env-file .env up --build -d
```

See `deploy/README.md` (VPC deployment), `deploy/tls.md`,
`deploy/iam-bedrock.md`, and the repo-level `docs/enterprise-broker.md`
for the action-broker half.

## Develop

```bash
make db-up migrate   # postgres + embedded-SQL migrations
make test            # pure unit tests, no Postgres/AWS needed
make smoke           # full-stack offline smoke test (Docker)
go run ./internal/dlp/gen   # regenerate configs/dlp.example.yaml
```

This directory is its own Go module (`github.com/openscope/openscope/router`);
the repo root remains the dependency-free broker module.
