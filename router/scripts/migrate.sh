#!/usr/bin/env bash
# Apply Postgres migrations and set local-dev passwords for the DB roles.
# Production setup uses RDS IAM authentication and never runs this script.
#
# Works whether or not psql is installed on the host:
#   - if `psql` is in $PATH, uses that (connects to $DB_HOST:$DB_PORT)
#   - otherwise falls back to `docker exec openscope-demo-postgres psql ...`

set -euo pipefail

cd "$(dirname "$0")/.."

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-openscope}"
DB_ADMIN_USER="${DB_ADMIN_USER:-openscope_admin}"
DB_ADMIN_PASSWORD="${DB_ADMIN_PASSWORD:-dev_admin_password}"
DB_CONTAINER="${DB_CONTAINER:-openscope-demo-postgres}"

if command -v psql >/dev/null 2>&1; then
  export PGPASSWORD="$DB_ADMIN_PASSWORD"
  psql_file()  { psql --host "$DB_HOST" --port "$DB_PORT" --username "$DB_ADMIN_USER" --dbname "$DB_NAME" -v ON_ERROR_STOP=1 --quiet --no-psqlrc --file "$1"; }
  psql_stdin() { psql --host "$DB_HOST" --port "$DB_PORT" --username "$DB_ADMIN_USER" --dbname "$DB_NAME" -v ON_ERROR_STOP=1 --quiet --no-psqlrc; }
  echo "==> using local psql against $DB_HOST:$DB_PORT/$DB_NAME"
elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
  psql_file()  { docker exec -i -e PGPASSWORD="$DB_ADMIN_PASSWORD" "$DB_CONTAINER" psql -U "$DB_ADMIN_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 --quiet --no-psqlrc < "$1"; }
  psql_stdin() { docker exec -i -e PGPASSWORD="$DB_ADMIN_PASSWORD" "$DB_CONTAINER" psql -U "$DB_ADMIN_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 --quiet --no-psqlrc; }
  echo "==> using docker exec into $DB_CONTAINER"
else
  echo "ERROR: neither psql nor a running $DB_CONTAINER container found." >&2
  exit 1
fi

echo "==> applying migrations"
for f in db/migrations/*.sql; do
  echo "    $f"
  psql_file "$f"
done

echo "==> setting local-dev passwords for DB roles"
psql_stdin <<'SQL'
ALTER ROLE app_rw         WITH PASSWORD 'dev_app_rw_password';
ALTER ROLE tenant_reader  WITH PASSWORD 'dev_tenant_reader_password';
ALTER ROLE vendor_reader  WITH PASSWORD 'dev_vendor_reader_password';
SQL

echo "==> done."
