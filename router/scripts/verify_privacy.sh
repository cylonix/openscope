#!/usr/bin/env bash
# Verify the privacy boundary end-to-end. Runs five proofs:
#   1. vendor_reader denied on sensitive.* schema
#   2. vendor_reader denied on raw app.api_keys (must use app.api_keys_safe view)
#   3. vendor_reader CAN read app.router_events (operational metadata)
#   4. tenant_reader RLS-scoped: with app.tenant_id = A, sees only A's data
#   5. tenant_reader RLS-scoped: with app.tenant_id = B, sees only B's data
#
# Exits non-zero on any unexpected outcome. Safe to re-run.

set -euo pipefail

DB_CONTAINER="${DB_CONTAINER:-openscope-demo-postgres}"
DB_NAME="${DB_NAME:-openscope}"

# Connection helpers — all go through docker exec.
admin()  { docker exec -i -e PGPASSWORD=dev_admin_password         "$DB_CONTAINER" psql -U openscope_admin -d "$DB_NAME" --no-psqlrc -v ON_ERROR_STOP=1 -t -A "$@"; }
vendor() { docker exec -i -e PGPASSWORD=dev_vendor_reader_password "$DB_CONTAINER" psql -U vendor_reader   -d "$DB_NAME" --no-psqlrc -t -A "$@"; }
tenant() { docker exec -i -e PGPASSWORD=dev_tenant_reader_password "$DB_CONTAINER" psql -U tenant_reader   -d "$DB_NAME" --no-psqlrc -t -A "$@"; }

pass() { echo "    PASS: $1"; }
fail() { echo "    FAIL: $1" >&2; exit 1; }

echo "==> seeding two tenants with one router_event each (as openscope_admin)"
admin <<'SQL' >/dev/null
DELETE FROM app.router_events WHERE tenant_id IN (
  SELECT id FROM app.tenants WHERE slug IN ('acme', 'globex')
);
DELETE FROM app.tenants WHERE slug IN ('acme', 'globex');
INSERT INTO app.tenants (slug, name) VALUES ('acme',   'Acme Corp');
INSERT INTO app.tenants (slug, name) VALUES ('globex', 'Globex Inc');
INSERT INTO app.router_events (request_id, tenant_id, role, endpoint, decision, result)
  SELECT gen_random_uuid(), id, 'developer', '/v1/scan', 'allow', 'success'
  FROM app.tenants WHERE slug = 'acme';
INSERT INTO app.router_events (request_id, tenant_id, role, endpoint, decision, result)
  SELECT gen_random_uuid(), id, 'developer', '/v1/scan', 'allow', 'success'
  FROM app.tenants WHERE slug = 'globex';
SQL

ACME_ID=$(admin   -c "SELECT id FROM app.tenants WHERE slug = 'acme';")
GLOBEX_ID=$(admin -c "SELECT id FROM app.tenants WHERE slug = 'globex';")

echo "==> Proof 1: vendor_reader denied on sensitive.* schema (THE load-bearing proof)"
out=$(vendor -c "SELECT prompt_text FROM sensitive.prompt_records LIMIT 1;" 2>&1 || true)
echo "$out" | grep -q "permission denied for schema sensitive" \
  && pass "got 'permission denied for schema sensitive'" \
  || fail "vendor_reader was NOT denied on sensitive.*; got: $out"

echo "==> Proof 2: vendor_reader denied on raw app.api_keys (only api_keys_safe is granted)"
out=$(vendor -c "SELECT key_hash FROM app.api_keys LIMIT 1;" 2>&1 || true)
echo "$out" | grep -q "permission denied for table api_keys" \
  && pass "got 'permission denied for table api_keys'" \
  || fail "vendor_reader was NOT denied on raw api_keys; got: $out"

echo "==> Proof 3: vendor_reader CAN read app.router_events cross-tenant"
count=$(vendor -c "SELECT count(*) FROM app.router_events;" 2>&1)
[[ "$count" == "2" ]] \
  && pass "vendor_reader sees 2 events across both tenants" \
  || fail "expected 2 events; got: $count"

echo "==> Proof 4: tenant_reader scoped to acme (app.tenant_id = $ACME_ID) sees exactly 1 event"
count=$(tenant <<SQL 2>&1 | grep -E '^[0-9]+$' | tail -1
BEGIN;
SET LOCAL app.tenant_id = '$ACME_ID';
SELECT count(*) FROM app.router_events;
COMMIT;
SQL
)
[[ "$count" == "1" ]] \
  && pass "tenant_reader sees 1 event for acme" \
  || fail "expected 1 event for acme; got: $count"

echo "==> Proof 5: tenant_reader scoped to globex (app.tenant_id = $GLOBEX_ID) sees the OTHER event"
count=$(tenant <<SQL 2>&1 | grep -E '^[0-9]+$' | tail -1
BEGIN;
SET LOCAL app.tenant_id = '$GLOBEX_ID';
SELECT count(*) FROM app.router_events;
COMMIT;
SQL
)
[[ "$count" == "1" ]] \
  && pass "tenant_reader sees 1 event for globex" \
  || fail "expected 1 event for globex; got: $count"

echo "==> Proof 6 (bonus): tenant_reader with NO app.tenant_id set sees 0 rows (RLS default-deny)"
count=$(tenant -c "SELECT count(*) FROM app.router_events;" 2>&1 | grep -E '^[0-9]+$' | tail -1)
[[ "$count" == "0" ]] \
  && pass "tenant_reader with no tenant_id set sees 0 events (RLS default-deny)" \
  || fail "expected 0 events without tenant_id; got: $count"

echo ""
echo "==> All 6 proofs passed. The privacy boundary is enforced by the database engine."
