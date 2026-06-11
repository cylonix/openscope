-- 0001_init.sql — privacy boundary lives here.
--
-- Three schemas, four DB roles. The load-bearing guarantee is that
--   SET ROLE vendor_reader;
--   SELECT prompt_text FROM sensitive.prompt_records LIMIT 1;
-- returns ERROR: permission denied for schema sensitive — enforced by the
-- Postgres engine itself, not by application middleware.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid()

-- ============================================================
-- ROLES
-- ============================================================
-- Local dev passwords are set by scripts/migrate.sh after this migration runs.
-- Production uses RDS IAM-authenticated tokens; no passwords on disk.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_rw') THEN
    -- Router-side role. BYPASSRLS lets the router write to any tenant's data.
    CREATE ROLE app_rw WITH LOGIN BYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'tenant_reader') THEN
    -- Console-side role for developer + IT requests. RLS-scoped via current_setting('app.tenant_id').
    CREATE ROLE tenant_reader WITH LOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vendor_reader') THEN
    -- Console-side role for OpenScope-engineer requests. Cross-tenant on app+vendor
    -- schemas. ZERO GRANTs on sensitive.*; the database refuses the query.
    CREATE ROLE vendor_reader WITH LOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'openscope_admin') THEN
    -- Migrations + ops only. Never used at request time.
    CREATE ROLE openscope_admin WITH LOGIN CREATEDB CREATEROLE;
  END IF;
END $$;

-- ============================================================
-- SCHEMAS
-- ============================================================
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS sensitive;
CREATE SCHEMA IF NOT EXISTS vendor;

REVOKE ALL ON SCHEMA public    FROM PUBLIC;
REVOKE ALL ON SCHEMA app       FROM PUBLIC;
REVOKE ALL ON SCHEMA sensitive FROM PUBLIC;
REVOKE ALL ON SCHEMA vendor    FROM PUBLIC;

GRANT USAGE ON SCHEMA app       TO app_rw, tenant_reader, vendor_reader;
GRANT USAGE ON SCHEMA sensitive TO app_rw, tenant_reader;
-- NOTE: vendor_reader is intentionally excluded from sensitive.* USAGE.
GRANT USAGE ON SCHEMA vendor    TO app_rw, tenant_reader, vendor_reader;

-- ============================================================
-- TABLES — app (operational data; readable by both reader roles)
-- ============================================================

CREATE TABLE app.tenants (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug            text NOT NULL UNIQUE,
  name            text NOT NULL,
  bedrock_account text,  -- AWS account ID of the per-tenant Bedrock account; null for shared
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.api_keys (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES app.tenants(id),
  role            text NOT NULL CHECK (role IN ('developer','it','engineer','admin')),
  recipient_email text,
  key_prefix      text NOT NULL,        -- first 12 chars, indexed for lookup
  key_hash        bytea NOT NULL,       -- argon2id of the full token
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz,
  revoked_at      timestamptz,
  last_used_at    timestamptz
);
CREATE INDEX api_keys_prefix_idx ON app.api_keys (key_prefix);
CREATE INDEX api_keys_tenant_role_idx ON app.api_keys (tenant_id, role)
  WHERE revoked_at IS NULL;

-- View that hides key_hash from non-admin readers.
CREATE VIEW app.api_keys_safe AS
  SELECT id, tenant_id, role, recipient_email, key_prefix,
         created_at, expires_at, revoked_at, last_used_at
  FROM app.api_keys;

CREATE TABLE app.router_events (
  id            bigserial PRIMARY KEY,
  ts            timestamptz NOT NULL DEFAULT now(),
  request_id    uuid NOT NULL,
  tenant_id     uuid NOT NULL REFERENCES app.tenants(id),
  api_key_id    uuid REFERENCES app.api_keys(id),
  role          text NOT NULL,
  agent         text,
  endpoint      text NOT NULL,           -- /v1/scan or /v1/chat
  model         text,
  decision      text NOT NULL CHECK (decision IN ('allow','deny')),
  result        text NOT NULL,           -- success, dlp_block, upstream_error
  reason        text,
  dlp_rule_ids  text[],
  bytes_in      int,
  bytes_out     int
);
CREATE INDEX router_events_tenant_ts_idx ON app.router_events (tenant_id, ts DESC);
CREATE INDEX router_events_ts_idx        ON app.router_events (ts DESC);
CREATE INDEX router_events_request_idx   ON app.router_events (request_id);

CREATE TABLE app.usage_metrics (
  id              bigserial PRIMARY KEY,
  ts              timestamptz NOT NULL DEFAULT now(),
  tenant_id       uuid NOT NULL REFERENCES app.tenants(id),
  api_key_id      uuid REFERENCES app.api_keys(id),
  request_id      uuid NOT NULL,
  model           text NOT NULL,
  input_tokens    int NOT NULL DEFAULT 0,
  output_tokens   int NOT NULL DEFAULT 0,
  input_cost_usd  numeric(12,6) NOT NULL DEFAULT 0,
  output_cost_usd numeric(12,6) NOT NULL DEFAULT 0,
  total_cost_usd  numeric(12,6) GENERATED ALWAYS AS (input_cost_usd + output_cost_usd) STORED
);
CREATE INDEX usage_metrics_tenant_ts_idx ON app.usage_metrics (tenant_id, ts DESC);
CREATE INDEX usage_metrics_ts_idx        ON app.usage_metrics (ts DESC);

CREATE TABLE app.receipts (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id    uuid NOT NULL UNIQUE,
  tenant_id     uuid NOT NULL REFERENCES app.tenants(id),
  ts            timestamptz NOT NULL DEFAULT now(),
  payload       jsonb NOT NULL,        -- canonical signed JSON (no bodies)
  signature     bytea NOT NULL,        -- Ed25519 signature
  public_key_id text NOT NULL          -- which signing key (rotation support)
);
CREATE INDEX receipts_tenant_ts_idx ON app.receipts (tenant_id, ts DESC);

-- ============================================================
-- TABLES — sensitive (vendor_reader has zero GRANTs here)
-- ============================================================

CREATE TABLE sensitive.prompt_records (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id    uuid NOT NULL UNIQUE,
  tenant_id     uuid NOT NULL REFERENCES app.tenants(id),
  ts            timestamptz NOT NULL DEFAULT now(),
  prompt_text   text NOT NULL,
  prompt_sha256 bytea NOT NULL,
  dlp_findings  jsonb
);
CREATE INDEX prompt_records_tenant_ts_idx ON sensitive.prompt_records (tenant_id, ts DESC);
CREATE INDEX prompt_records_request_idx   ON sensitive.prompt_records (request_id);

CREATE TABLE sensitive.response_records (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id    uuid NOT NULL UNIQUE REFERENCES sensitive.prompt_records(request_id),
  tenant_id     uuid NOT NULL REFERENCES app.tenants(id),
  ts            timestamptz NOT NULL DEFAULT now(),
  response_text text,
  finish_reason text,
  model         text NOT NULL
);
CREATE INDEX response_records_tenant_ts_idx ON sensitive.response_records (tenant_id, ts DESC);

CREATE TABLE sensitive.uploaded_documents (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id     uuid NOT NULL,
  tenant_id      uuid NOT NULL REFERENCES app.tenants(id),
  ts             timestamptz NOT NULL DEFAULT now(),
  filename       text NOT NULL,
  content_text   text,
  content_sha256 bytea NOT NULL,
  dlp_findings   jsonb
);
CREATE INDEX uploaded_documents_tenant_ts_idx ON sensitive.uploaded_documents (tenant_id, ts DESC);

-- ============================================================
-- GRANTS — the privacy boundary
-- ============================================================

-- app_rw: write-side. Router needs INSERT everywhere; SELECT for read-back on the same request.
GRANT SELECT, INSERT, UPDATE ON ALL TABLES    IN SCHEMA app       TO app_rw;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES    IN SCHEMA sensitive TO app_rw;
GRANT USAGE, SELECT          ON ALL SEQUENCES IN SCHEMA app       TO app_rw;

-- tenant_reader: developer + IT dashboards. Scoped via RLS, no raw key_hash access.
GRANT SELECT ON app.tenants, app.router_events, app.usage_metrics,
                app.receipts, app.api_keys_safe TO tenant_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA sensitive TO tenant_reader;

-- vendor_reader: OpenScope-engineer dashboard. Cross-tenant on operational data only.
-- NO GRANT on sensitive.*; NO GRANT on app.receipts (those would let us reconstruct
-- per-request metadata about specific tenants beyond what aggregates need).
GRANT SELECT ON app.tenants, app.router_events, app.usage_metrics,
                app.api_keys_safe TO vendor_reader;

-- openscope_admin: migrations and ops only.
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA app       TO openscope_admin;
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA sensitive TO openscope_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA app       TO openscope_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA sensitive TO openscope_admin;

-- Default privileges for future tables (so 0002+ migrations don't have to repeat GRANTs).
ALTER DEFAULT PRIVILEGES IN SCHEMA app       GRANT SELECT, INSERT, UPDATE ON TABLES TO app_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA sensitive GRANT SELECT, INSERT, UPDATE ON TABLES TO app_rw;

-- ============================================================
-- ROW LEVEL SECURITY — tenant_reader is scoped; vendor_reader sees cross-tenant
-- ============================================================

-- Tables that carry tenant_id get RLS turned on. app_rw has BYPASSRLS at the role level
-- so the router writes are unaffected.
ALTER TABLE app.tenants                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.api_keys                ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.router_events           ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.usage_metrics           ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.receipts                ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensitive.prompt_records    ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensitive.response_records  ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensitive.uploaded_documents ENABLE ROW LEVEL SECURITY;

-- tenant_reader policies: only rows matching current_setting('app.tenant_id').
-- The console SETs this via `SET LOCAL app.tenant_id = $1` per request from the validated session.
CREATE POLICY tenant_isolation_tenants       ON app.tenants
  FOR SELECT TO tenant_reader USING (id        = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_api_keys      ON app.api_keys
  FOR SELECT TO tenant_reader USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_router_events ON app.router_events
  FOR SELECT TO tenant_reader USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_usage_metrics ON app.usage_metrics
  FOR SELECT TO tenant_reader USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_receipts      ON app.receipts
  FOR SELECT TO tenant_reader USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_prompts       ON sensitive.prompt_records
  FOR SELECT TO tenant_reader USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_responses     ON sensitive.response_records
  FOR SELECT TO tenant_reader USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_uploads       ON sensitive.uploaded_documents
  FOR SELECT TO tenant_reader USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- vendor_reader policies: cross-tenant on app tables. (No policy on sensitive.* — no GRANT either.)
CREATE POLICY vendor_cross_tenant_tenants    ON app.tenants
  FOR SELECT TO vendor_reader USING (true);
CREATE POLICY vendor_cross_tenant_events     ON app.router_events
  FOR SELECT TO vendor_reader USING (true);
CREATE POLICY vendor_cross_tenant_usage      ON app.usage_metrics
  FOR SELECT TO vendor_reader USING (true);

COMMIT;
