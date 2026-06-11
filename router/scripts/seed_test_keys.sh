#!/usr/bin/env bash
# Seed test API keys for local /v1/scan testing.
#
# Creates one tenant ("acme") with three keys (developer, it, engineer).
# Tokens are printed to stdout — copy them for curl tests. The HMAC pepper
# must match what the router runs with (OPENSCOPE_AUTH_PEPPER).
#
# Local dev defaults: tenant=acme, pepper=DevPepperPlaceholder.
# Requires bin/openscope-mint (run `go build -o bin/ ./cmd/openscope-mint`
# first if absent).
#
# Resets keys if --reset is passed (DELETEs from app.api_keys first).
#
# Usage:
#   ./scripts/seed_test_keys.sh           # idempotent insert
#   ./scripts/seed_test_keys.sh --reset   # wipe + re-mint

set -euo pipefail

cd "$(dirname "$0")/.."

DB_CONTAINER="${DB_CONTAINER:-openscope-demo-postgres}"
DB_NAME="${DB_NAME:-openscope}"
TENANT_SLUG="${TENANT_SLUG:-acme}"
TENANT_NAME="${TENANT_NAME:-Acme Corp}"

# Match the dev default in pkg/serverconfig/config.go. For prod the seed
# script wouldn't be used; admin endpoint mints with the real pepper.
PEPPER="${OPENSCOPE_AUTH_PEPPER:-DEV-PEPPER-CHANGE-ME-32-BYTES-OF-DEV}"

# --- Build mint helper if missing ------------------------------------------
if [[ ! -x bin/openscope-mint ]]; then
  echo "==> building bin/openscope-mint"
  go build -o bin/openscope-mint ./cmd/openscope-mint
fi

# --- psql helper (uses docker if local psql missing) -----------------------
if command -v psql >/dev/null 2>&1; then
  PSQL_ADMIN=(psql --host "${DB_HOST:-127.0.0.1}" --port "${DB_PORT:-5432}" \
              --username openscope_admin --dbname "$DB_NAME" \
              -v ON_ERROR_STOP=1 --quiet --no-psqlrc -t -A)
  export PGPASSWORD="${DB_ADMIN_PASSWORD:-dev_admin_password}"
else
  PSQL_ADMIN=(docker exec -i -e PGPASSWORD="${DB_ADMIN_PASSWORD:-dev_admin_password}" \
              "$DB_CONTAINER" psql -U openscope_admin -d "$DB_NAME" \
              -v ON_ERROR_STOP=1 --quiet --no-psqlrc -t -A)
fi

# --- Reset if requested ----------------------------------------------------
if [[ "${1:-}" == "--reset" ]]; then
  # Cannot DELETE: api_keys may be referenced by router_events / usage_metrics
  # / receipts. Revoking preserves FK integrity while invalidating the
  # tokens. Fresh tokens minted below.
  echo "==> revoking active api_keys for tenant slug=$TENANT_SLUG (FK-safe)"
  "${PSQL_ADMIN[@]}" <<SQL >/dev/null
UPDATE app.api_keys
SET revoked_at = now()
WHERE tenant_id IN (SELECT id FROM app.tenants WHERE slug = '$TENANT_SLUG')
  AND revoked_at IS NULL;
SQL
fi

# --- Upsert tenant ---------------------------------------------------------
tenant_id=$("${PSQL_ADMIN[@]}" <<SQL
INSERT INTO app.tenants (slug, name) VALUES ('$TENANT_SLUG', '$TENANT_NAME')
  ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
RETURNING id;
SQL
)
tenant_id="${tenant_id##*$'\n'}"  # strip any noise
echo "==> tenant: $TENANT_SLUG = $tenant_id"

# --- Mint and insert one key per role --------------------------------------
echo "==> minting keys (pepper hidden; tokens shown ONCE):"
echo ""
for role in developer it engineer; do
  out=$(OPENSCOPE_AUTH_PEPPER="$PEPPER" ./bin/openscope-mint --role="$role")
  token=$(echo  "$out" | awk -F= '/^TOKEN=/    {print $2}')
  prefix=$(echo "$out" | awk -F= '/^PREFIX=/   {print $2}')
  hash=$(echo   "$out" | awk -F= '/^HASH_HEX=/ {print $2}')

  # FK-safe rotation: revoke the current active key for (tenant, role)
  # rather than deleting (which would violate router_events_api_key_id_fkey).
  "${PSQL_ADMIN[@]}" <<SQL >/dev/null
UPDATE app.api_keys SET revoked_at = now()
WHERE tenant_id = '$tenant_id' AND role = '$role' AND revoked_at IS NULL;
INSERT INTO app.api_keys (tenant_id, role, recipient_email, key_prefix, key_hash)
VALUES ('$tenant_id', '$role', 'test+$role@example.com', '$prefix', decode('$hash', 'hex'));
SQL
  printf "  %-10s %s\n" "$role:" "$token"
done

echo ""
echo "==> save these tokens. The router can only validate them; it cannot recover them."
echo "    Test with:"
echo "      curl -X POST http://localhost:8080/v1/scan \\"
echo "        -H 'Authorization: Bearer <token>' \\"
echo "        -F 'file=@testdata/clean.txt'"
