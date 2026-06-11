# OpenScope Enterprise Broker — VPC Deployment

The OpenScope broker (`openscoped`) can run on a Linux host inside your VPC
instead of on each developer's device. In this topology the **broker holds
the privileged credentials** — SSH keys for production hosts, internal API
profiles, system-management permissions — and agents (on laptops, in CI, in
sandboxes) hold only a revocable OpenScope agent token. The agent never
sees an SSH key; it can only ask the broker to perform declared, policied,
audited actions.

```
agent (device/CI) --Bearer osk_agent_*--> openscoped (VPC) --ssh/http--> privileged resources
                                              |
                                       policies.yaml + audit.jsonl
```

On Linux the broker ships the `ssh`, `http`, and `system` executors. The
`applescript` executor is macOS-only; requests for it fail with a clear
"not available on this platform" error.

## Install

### Option A — systemd (recommended for a dedicated VM)

```bash
# on a build machine (or grab a release tarball)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/openscoped ./cmd/openscope
scp openscoped openscope deploy/broker/* vpc-host:/tmp/openscope-install/

# on the VPC host
cd /tmp/openscope-install && sudo ./install.sh
```

### Option B — Docker

```bash
docker build -f deploy/broker/Dockerfile -t openscope-broker .
docker run -d --name openscoped \
  -p 8443:8443 \
  -v openscope-admin:/etc/openscope \
  -v openscope-state:/var/lib/openscope \
  -e OPENSCOPE_HTTP_TLS_CERT=/etc/openscope/tls/cert.pem \
  -e OPENSCOPE_HTTP_TLS_KEY=/etc/openscope/tls/key.pem \
  openscope-broker
```

## TLS

The network listener refuses to start in plaintext on a non-loopback
address. Pick one:

1. **Broker-terminated TLS** — set `OPENSCOPE_HTTP_TLS_CERT` /
   `OPENSCOPE_HTTP_TLS_KEY`. Use a cert from your internal CA; clients set
   `OPENSCOPE_HTTP_CA=/path/to/ca.pem` if the CA isn't in the system trust
   store.
2. **Proxy-terminated TLS** — terminate at your ALB/NLB/nginx/traefik and
   set `OPENSCOPE_HTTP_PLAINTEXT_OK=1` on the broker. Keep the plaintext
   hop inside a private network segment.

Running over a Cylonix/WireGuard mesh? The mesh is transport security, not
authentication — agent tokens are still required (and you may set
`OPENSCOPE_HTTP_PLAINTEXT_OK=1` since the mesh encrypts the path).

## Agent tokens

Every request to the network listener must carry
`Authorization: Bearer osk_agent_…`. The broker derives the agent identity
from the token — a request body claiming a different agent is refused and
audited (`agent_token_mismatch`).

```bash
# mint (also registers the agent) — token is shown ONCE
sudo -u openscope OPENSCOPE_CONFIG_DIR=/var/lib/openscope \
  openscope agent token mint ci-runner-1

# list / revoke / rotate
... openscope agent token list
... openscope agent token revoke ci-runner-1
... openscope agent token mint --rotate ci-runner-1
```

Only HMAC-SHA256 hashes are stored (`agent_tokens.yaml`). The HMAC pepper
lives in `$OPENSCOPE_CONFIG_DIR/token_pepper` (or `OPENSCOPE_AUTH_PEPPER`)
— **back it up**; losing it invalidates every minted token.

The legacy unauthenticated bridge (`OPENSCOPE_HTTP_ALLOW_ANON=1`) still
exists for localhost Docker/NemoClaw bridging and is refused on
non-loopback listen addresses.

## Client (agent) side

```bash
export OPENSCOPE_HTTP_URL=https://broker.internal.example:8443
export OPENSCOPE_TOKEN=osk_agent_...          # from token mint
export OPENSCOPE_HTTP_CA=/etc/ssl/internal-ca.pem   # private CA only

openscope run ssh check_host --target prod-app-1
```

The `agent` is implied by the token — no `--agent` spoofing is possible
over the network.

## Audit

Every decision (allow, deny, invalid token, rate-limited, mismatch) is
appended to `/var/lib/openscope/audit.jsonl` with transport metadata:
`request_id`, `transport: http`, `remote_addr`, `token_prefix`. Ship it to
your SIEM, and install `deploy/broker/logrotate.openscope`. When the
OpenScope AI router runs alongside, point its
`OPENSCOPE_AUDIT_JSONL_PATH` at the same directory for one unified tail.

## Hardening defaults

- Bearer-token auth on `/v1/actions` (anon mode loopback-only)
- TLS ≥ 1.2; plaintext requires explicit proxy acknowledgement
- 1 MiB request-body cap; 5s/30s/60s read/write timeouts
- Per-token rate limit (10 rps, burst 30) → HTTP 429
- `X-Request-Id` on every response, recorded in the audit log
