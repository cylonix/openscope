#!/usr/bin/env bash
# End-to-end SSO smoke test for the OpenScope broker (Phase 2a).
#
# Brings up: mock-oauth2-server (IdP stand-in) + oauth2-proxy + nginx token
# injector + openscoped + an sshd target, then asserts the full enterprise
# human-auth chain:
#
#   1. alice's IdP JWT -> oauth2-proxy -> nginx -> broker runs `ssh check_host`
#      on the target, and the audit row attributes user=alice@corp.example
#      with auth_method=proxy.
#   2. bob's IdP JWT is rejected by policy (no allow rule) -> 403.
#   3. a spoofed X-Forwarded-Email without the IdP JWT never reaches the broker
#      (oauth2-proxy rejects the unauthenticated request).
#
# Usage: scripts/smoke_broker_sso.sh [--keep]   (--keep leaves the stack up)
set -euo pipefail
cd "$(dirname "$0")/.."

SSO=deploy/broker/sso
SMOKE=$SSO/.smoke
COMPOSE="docker compose -f $SSO/docker-compose.yml"
NET=openscope-sso-smoke-net
CURL="docker run --rm --network $NET curlimages/curl:8.11.1"

KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1
trap 'if [[ $KEEP -eq 0 ]]; then $COMPOSE --profile proxy down -v >/dev/null 2>&1 || true; fi' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- provisioning ---------------------------------------------------------
echo "==> provisioning $SMOKE"
rm -rf "$SMOKE"
mkdir -p "$SMOKE/admin" "$SMOKE/state" "$SMOKE/seed"

# Broker SSH key (seed; copied root-owned into the broker at runtime).
ssh-keygen -t ed25519 -N "" -C broker -f "$SMOKE/seed/broker_key" >/dev/null

cat > "$SMOKE/admin/ssh_targets.yaml" <<'EOF'
version: 1
targets:
  - alias: target
    host: target
    user: broker
    port: 2222
    identity_file: /var/openscope/ssh/broker_key
EOF

# User-scoped policy: only alice may check_host; no agent selector.
cat > "$SMOKE/admin/policies.yaml" <<'EOF'
version: 1
rules:
  - effect: allow
    user: alice@corp.example
    app: ssh
    action: check_host
EOF

# The acting agent must be registered; the proxy agent is added at mint time.
cat > "$SMOKE/state/agents.yaml" <<'EOF'
version: 1
agents:
  - claude-code
EOF

# --- bring up the core tier (no proxy yet) --------------------------------
echo "==> building + starting broker, mock-oidc, target"
$COMPOSE up -d --build mock-oidc target broker

echo "==> waiting for broker /healthz and mock-oidc discovery"
for i in $(seq 1 60); do
  $CURL -fsS http://broker:8443/healthz >/dev/null 2>&1 && break
  [[ $i -eq 60 ]] && { $COMPOSE logs broker | tail -30; fail "broker never came up"; }
  sleep 2
done
for i in $(seq 1 60); do
  $CURL -fsS http://mock-oidc:8080/default/.well-known/openid-configuration >/dev/null 2>&1 && break
  [[ $i -eq 60 ]] && fail "mock-oidc never came up"
  sleep 2
done

# --- seed the broker key root-owned inside the broker ---------------------
# A bind-mounted key keeps the host uid; the SSH executor requires uid 0, so
# copy it into the container's own layer and chown root.
echo "==> installing the broker key root-owned"
$COMPOSE exec -T broker sh -c '
  mkdir -p /var/openscope/ssh &&
  cp /seed/broker_key /var/openscope/ssh/broker_key &&
  chown -R root:root /var/openscope/ssh &&
  chmod 700 /var/openscope/ssh &&
  chmod 600 /var/openscope/ssh/broker_key'

# --- mint the trusted-proxy token -----------------------------------------
echo "==> minting trusted-proxy token"
TOKJSON=$($COMPOSE exec -T broker openscope agent token mint --trusted-proxy sso-proxy)
TOKEN=$(echo "$TOKJSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
[[ "$TOKEN" == osk_agent_* ]] || fail "unexpected mint output: $TOKJSON"

echo "==> rendering nginx.conf with the proxy token"
sed "s#__PROXY_TOKEN__#${TOKEN}#" "$SSO/nginx.conf.tmpl" > "$SMOKE/nginx.conf"

# --- start the proxy tier -------------------------------------------------
echo "==> starting nginx + oauth2-proxy"
$COMPOSE --profile proxy up -d nginx oauth2-proxy
for i in $(seq 1 60); do
  curl -fsS http://localhost:4180/ping >/dev/null 2>&1 && break
  [[ $i -eq 60 ]] && { $COMPOSE logs oauth2-proxy | tail -30; fail "oauth2-proxy never came up"; }
  sleep 2
done

# --- helpers --------------------------------------------------------------
# Mint an IdP JWT for a subject, in-network so its issuer matches oauth2-proxy.
idp_jwt() {
  $CURL -fsS -X POST http://mock-oidc:8080/default/token \
    -d grant_type=password -d client_id=oauth2-proxy -d client_secret=secret \
    -d "username=$1" -d password=x --data-urlencode 'scope=openid email' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id_token"])'
}

check_host_req='{"app":"ssh","action":"check_host","agent":"claude-code","params":{"target":"target"}}'

# --- assertion 1: alice is allowed, SSH runs, audit names her -------------
echo "==> alice: check_host must succeed end to end"
ALICE_JWT=$(idp_jwt alice@corp.example)
ALICE_RESP=$(curl -sS -X POST http://localhost:4180/v1/actions \
  -H "Authorization: Bearer $ALICE_JWT" -H 'Content-Type: application/json' \
  -d "$check_host_req")
echo "    resp: $ALICE_RESP"
echo "$ALICE_RESP" | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert r.get("ok") is True, r
d=r.get("data") or {}
assert d.get("user")=="broker", d
print("    ssh check_host OK (user=%s host=%s)" % (d.get("user"), d.get("hostname")))'

# --- assertion 2: bob is denied by policy ---------------------------------
echo "==> bob: same action must be denied (403)"
BOB_JWT=$(idp_jwt bob@corp.example)
BOB_CODE=$(curl -s -o /tmp/bob.out -w '%{http_code}' -X POST http://localhost:4180/v1/actions \
  -H "Authorization: Bearer $BOB_JWT" -H 'Content-Type: application/json' \
  -d "$check_host_req")
[[ "$BOB_CODE" == "403" ]] || { cat /tmp/bob.out; fail "bob expected 403, got $BOB_CODE"; }
echo "    bob 403 OK"

# --- assertion 3: no IdP token => oauth2-proxy rejects (header can't leak) -
echo "==> spoofed header without a JWT must not reach the broker"
SPOOF_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:4180/v1/actions \
  -H 'X-Forwarded-Email: alice@corp.example' -H 'Content-Type: application/json' \
  -d "$check_host_req")
[[ "$SPOOF_CODE" != "200" ]] || fail "spoofed unauthenticated request was served ($SPOOF_CODE)"
echo "    spoof rejected ($SPOOF_CODE) OK"

# --- assertion 4: audit attributes the human -----------------------------
echo "==> audit log must attribute the human"
AUDIT=$($COMPOSE exec -T broker cat /var/lib/openscope/audit.jsonl)
echo "$AUDIT" | python3 -c '
import json,sys
rows=[json.loads(l) for l in sys.stdin if l.strip()]
ssh=[r for r in rows if r.get("app")=="ssh" and r.get("action")=="check_host"]
allow=[r for r in ssh if r.get("user")=="alice@corp.example" and r.get("decision")=="allow"]
deny=[r for r in ssh if r.get("user")=="bob@corp.example" and r.get("decision")=="deny"]
assert allow, "no allow row for alice: %s" % ssh
assert allow[0]["auth_method"]=="proxy", allow[0]
assert allow[0]["agent"]=="claude-code", allow[0]
assert deny, "no deny row for bob: %s" % ssh
print("    audit OK: alice allow (auth_method=proxy, agent=claude-code), bob deny")'

echo "==> SSO SMOKE PASSED"
[[ $KEEP -eq 1 ]] && echo "(stack left running: --keep)"
