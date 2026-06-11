# Deploying the OpenScope Router Stack in Your VPC

Components: **router** (governed LLM proxy, :8080), **console** (dashboard
API, :8081), **dashboard** (Next.js, :3000), **Postgres** (the privacy
boundary lives in its role grants — see `../db/migrations/0001_init.sql`).

## Quick start (Docker Compose)

```bash
cd router/deploy
../scripts/generate_secrets.sh > .env
# offline evaluation without AWS: echo OPENSCOPE_PROVIDER=mock >> .env
docker compose --env-file .env up --build -d
open http://localhost:3000
```

Mint keys: `POST /api/v1/admin/keys` with the `OPENSCOPE_ADMIN_TOKEN`
(see `../scripts/seed_test_keys.sh`), then point agents at:

- OpenAI-style agents (Cursor, Codex CLI, Aider): `http://host:8080/v1/chat/completions`
- Anthropic-style agents (Claude Code): `http://host:8080/v1/messages`

## Production notes

- TLS: `tls.md`. Bedrock IAM: `iam-bedrock.md`.
- systemd path (no Docker): `make release-linux`, copy the tarball, run
  `./install.sh` — migrations run automatically before the router starts.
- Upgrades: pull/build new images, `docker compose up -d` (the one-shot
  `migrate` service applies pending migrations first); or untar + 
  `./install.sh --upgrade`. Migrations are forward-only and additive.
- Per-tenant budgets: `PATCH /api/v1/admin/tenants/{id}/budget`
  (`{"monthly_budget_usd": 50}` or `null` for the deployment default).
- Custom DLP rules: copy `/etc/openscope/dlp.example.yaml`, set
  `OPENSCOPE_DLP_RULES_FILE`. The active ruleset hash is stamped on every
  receipt.
- Key rotation: new `OPENSCOPE_RECEIPT_PRIVATE_KEY` + bumped
  `OPENSCOPE_RECEIPT_PUBLIC_KEY_ID`; old receipts verify with the old
  published key.
- Smoke test: `make smoke` (mock provider, no AWS needed).
