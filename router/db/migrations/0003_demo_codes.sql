-- 0003_demo_codes.sql — short demo codes that resolve to a full token.
--
-- A demo code is an 8-character Crockford-base32 string the prospect types
-- at the login screen instead of the long osk_… token. The console looks
-- it up, retrieves the bound api_key plaintext, and proceeds with normal
-- token resolution. The web stores the resolved plaintext in sessionStorage
-- so subsequent /v1/scan and /v1/chat calls to the router work unchanged.
--
-- Storing plaintext here is intentional. The api_keys row stores an argon2
-- hash; the demo_codes row carries the original plaintext so the code is
-- usable as a lookup key. Demo-only convenience — production would mint
-- per-prospect rather than aliasing existing keys.

BEGIN;

CREATE TABLE IF NOT EXISTS app.demo_codes (
  code            text PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES app.tenants(id) ON DELETE CASCADE,
  role            text NOT NULL CHECK (role IN ('developer','it','engineer','admin')),
  api_key_id      uuid NOT NULL REFERENCES app.api_keys(id) ON DELETE CASCADE,
  plaintext_token text NOT NULL,
  label           text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz,
  last_used_at    timestamptz,
  revoked_at      timestamptz
);

CREATE INDEX IF NOT EXISTS demo_codes_tenant_role_active_idx
  ON app.demo_codes (tenant_id, role)
  WHERE revoked_at IS NULL;

-- Only the admin pool reads/writes this table (login flow uses AdminPool).
GRANT SELECT, INSERT, UPDATE ON app.demo_codes TO openscope_admin;

COMMIT;
