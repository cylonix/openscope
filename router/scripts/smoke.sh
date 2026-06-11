#!/usr/bin/env bash
# Offline smoke test for the OpenScope router stack.
#
# Brings up the full compose stack with OPENSCOPE_PROVIDER=mock (no AWS
# credentials needed), mints an API key via the console admin endpoint,
# then asserts:
#   1. /health (router), /api/v1/health (console), dashboard respond
#   2. /v1/chat allows clean text and returns a receipt
#   3. /v1/chat DLP-blocks testdata/confidential.txt content
#   4. unauthenticated /v1/chat is rejected
#
# Usage: scripts/smoke.sh [--keep]   (--keep leaves the stack running)
set -euo pipefail
cd "$(dirname "$0")/.."

KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

ENVFILE=deploy/.env.smoke
trap 'if [[ $KEEP -eq 0 ]]; then (cd deploy && docker compose --env-file .env.smoke down -v >/dev/null 2>&1 || true); fi' EXIT

echo "==> writing $ENVFILE (mock provider)"
./scripts/generate_secrets.sh | grep -v '^#' > "$ENVFILE"
echo "OPENSCOPE_PROVIDER=mock" >> "$ENVFILE"

echo "==> docker compose up --build"
(cd deploy && docker compose --env-file .env.smoke up --build -d)

ADMIN_TOKEN=$(grep '^OPENSCOPE_ADMIN_TOKEN=' "$ENVFILE" | cut -d= -f2)

echo "==> waiting for services"
for url in "http://127.0.0.1:8080/health" "http://127.0.0.1:8081/api/v1/health" "http://127.0.0.1:3000"; do
    for i in $(seq 1 60); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            echo "    up: $url"
            break
        fi
        [[ $i -eq 60 ]] && { echo "FAIL: $url never came up" >&2; exit 1; }
        sleep 2
    done
done

echo "==> minting a developer API key"
KEY_JSON=$(curl -fsS -X POST http://127.0.0.1:8081/api/v1/admin/keys \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"tenant_slug":"smoke","tenant_name":"Smoke Test","role":"developer"}')
TOKEN=$(echo "$KEY_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
[[ "$TOKEN" == osk_developer_* ]] || { echo "FAIL: unexpected token: $KEY_JSON" >&2; exit 1; }

echo "==> clean chat must be allowed with a receipt"
CLEAN=$(curl -fsS -X POST http://127.0.0.1:8080/v1/chat \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"messages":[{"role":"user","content":"summarize: the quick brown fox"}]}')
CLEAN="$CLEAN" python3 - <<'PY'
import json, os
r = json.loads(os.environ["CLEAN"])
assert r["decision"] == "allow", r
assert r["receipt"]["signature"], "missing receipt signature"
assert r["provider"] == "Mock Provider", r.get("provider")
print("    allow + signed receipt OK")
PY

echo "==> confidential content must be DLP-blocked"
python3 - "$TOKEN" <<'PY'
import json, subprocess, sys
token = sys.argv[1]
body = json.dumps({"messages": [{"role": "user", "content": open("testdata/confidential.txt").read()}]})
out = subprocess.run(
    ["curl", "-fsS", "-X", "POST", "http://127.0.0.1:8080/v1/chat",
     "-H", f"Authorization: Bearer {token}", "-H", "Content-Type: application/json", "-d", body],
    capture_output=True, text=True, check=True).stdout
r = json.loads(out)
assert r["decision"] == "deny", r
assert r["findings"], "expected findings"
assert r["receipt"]["signature"], "denials get receipts too"
print("    dlp_block + findings + receipt OK")
PY

echo "==> unauthenticated request must be rejected"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8080/v1/chat \
    -H "Content-Type: application/json" -d '{"messages":[{"role":"user","content":"hi"}]}')
[[ "$CODE" == "401" ]] || { echo "FAIL: expected 401, got $CODE" >&2; exit 1; }
echo "    401 OK"

echo "==> SMOKE PASSED"
if [[ $KEEP -eq 1 ]]; then
    echo "(stack left running: --keep)"
fi
