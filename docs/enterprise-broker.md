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

On Linux the broker ships the `ssh`, `ssm`, `http`, and `system` executors. The
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

## Authenticating human users (SSO)

An agent token says *which tool* is acting; enterprises also want *which
human*. OpenScope models a `(user, agent)` principal: the **agent** is the
tool (Claude Code, Cursor, a CI runner), the **user** is the authenticated
person on whose behalf it acts. The user identity is recorded in the audit
log and can scope policy. There are two ways to establish it.

### Path A — SSO via a reverse proxy (customers with an IdP)

OpenScope is **IdP-agnostic**: it never speaks OIDC/SAML itself. You run a
standard OIDC reverse proxy that authenticates the human against your IdP
and forwards a verified identity header; the broker consumes it. This works
with any IdP — Okta, Microsoft Entra, Auth0, Ping, OneLogin — and with
**Google Workspace** (which is itself an OIDC provider): use `oauth2-proxy`
with the Google provider restricted to your domain, or Google IAP on GCP.
Cloud-native proxies (AWS ALB OIDC, Cloudflare Access) work the same way.

The broker does **not** validate IdP JWTs (it has no JWT/JWKS dependency).
Instead the proxy authenticates to the broker with its own
`trusted_proxy` token, and only then does the broker trust the forwarded
user header. The proxy token is the trust anchor; keep the broker reachable
**only** from the proxy (private segment / security group).

```bash
# 1. mint a token the proxy presents to the broker
sudo -u openscope OPENSCOPE_CONFIG_DIR=/var/lib/openscope \
  openscope agent token mint --trusted-proxy sso-proxy

# 2. turn on header trust and (optionally) name the headers
OPENSCOPE_HTTP_TRUST_PROXY=1
OPENSCOPE_HTTP_PROXY_USER_HEADER=X-Forwarded-Email     # default
OPENSCOPE_HTTP_PROXY_GROUPS_HEADER=X-Forwarded-Groups  # default
```

Header trust is gated on **both** the `trusted_proxy` token **and**
`OPENSCOPE_HTTP_TRUST_PROXY` — a forwarded user header on any normal token
is ignored, and the verified user always overwrites whatever the client put
in the request body. A full, runnable reference (oauth2-proxy + a mock IdP
+ an SSH target) lives in `deploy/broker/sso/` — see its README and
`scripts/smoke_broker_sso.sh`.

### Path B — per-user tokens (no IdP, or CI / service accounts)

With no IdP, give each developer or job a token that binds their subject:

```bash
openscope agent token mint --user alice@corp.example claude-code-alice
```

The bound user travels with the token (no proxy, no headers) and scopes
policy and audit exactly like the SSO path. Plain `mint <agent>` tokens
remain user-less and agent-only.

## Scoping authorization per user

Policy rules carry optional `user` and `groups` selectors alongside `agent`.
An empty selector is a wildcard; a set one must match. Deny still overrides
allow. So you can write:

```yaml
version: 1
rules:
  # any agent acting as alice may restart prod-api
  - effect: allow
    user: alice@corp.example
    app: ssh
    action: restart_service
    constraints: { target: prod-api }
  # the whole SRE group may tail logs anywhere
  - effect: allow
    groups: [sre]
    app: ssh
    action: tail_logs
  # …but never this contractor, even via an SRE group membership
  - effect: deny
    user: contractor@vendor.example
    app: ssh
    action: restart_service
```

`groups` matches when the principal belongs to **any** listed group (from
the proxy's `X-Forwarded-Groups`). A rule must name at least one of `agent`,
`user`, or `groups`. SSH adds a second layer on top of policy: the
per-target allow-lists in `ssh_targets.yaml` still bound which services,
paths, and upload sources are reachable.

## Governing AWS instances over SSM

The `ssm` executor reaches EC2 instances over AWS Systems Manager (Run Command) —
**no inbound SSH, no SSH key, no open port 22**. It shells out to the `aws` CLI
(no AWS SDK in the broker), runs each verb's fixed command template via
`AWS-RunShellScript`, and bounds path/service params with the same allow-lists as
the SSH executor. Targets live in `<AdminDir>/ssm_targets.yaml` (alias, instance
id, region, allow-lists).

It is governed exactly like SSH, with one extra control because the broker's
credential is an AWS identity, not a file:

- **Credential custody.** The broker uses its **EC2 instance role** (no static
  secret) or a root-owned credentials file (`AWS_SHARED_CREDENTIALS_FILE`); the
  executor refuses to run if its credentials file is agent-readable (the cred
  analog of an agent-readable SSH key).
- **The binding control — deny the agent SSM in IAM.** Custody alone is not
  enough: the *agent's own* AWS identity must be denied `ssm:SendCommand` /
  `StartSession`, or it could call `aws ssm` directly and bypass the broker.
  Apply the templates in `deploy/broker/iam/` (`agent-ssm-deny.policy.json` as a
  permission boundary on the agent; `broker-ssm-role.policy.json` as the broker's
  least-privilege allow). `plan` emits `SSM-DEPLOY-CONTRACT` to remind you, but
  cannot verify the IAM side. The guard hook denying raw `aws ssm` is
  defense-in-depth, not the boundary (it can't intercept boto3).

`plan` blocks an `ssm` verb whose command is a generic runner
(`SSM-RUNSHELL-ARBITRARY` — arbitrary root via RunShellScript) and warns on a
grant with no target constraint (`SSM-BROAD-SCOPE`).

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
`request_id`, `transport: http`, `remote_addr`, `token_prefix`. When a human
identity was established it also records `user`, `groups`, and `auth_method`
(`proxy` | `token` | `unix` | `anon`) — so every action answers "which
developer, via which agent." Ship it to your SIEM, and install
`deploy/broker/logrotate.openscope`. When the OpenScope AI router runs
alongside, point its `OPENSCOPE_AUDIT_JSONL_PATH` at the same directory for
one unified tail.

## Hardening defaults

- Bearer-token auth on `/v1/actions` (anon mode loopback-only)
- Proxy-forwarded user headers trusted only for a `trusted_proxy` token with
  `OPENSCOPE_HTTP_TRUST_PROXY=1`; the verified user overrides the request body
- TLS ≥ 1.2; plaintext requires explicit proxy acknowledgement
- 1 MiB request-body cap; 5s/30s/60s read/write timeouts
- Per-token rate limit (10 rps, burst 30) → HTTP 429
- `X-Request-Id` on every response, recorded in the audit log
- SSM: broker credential custody (instance role / root-owned creds) + the IAM
  agent-SSM deny (`deploy/broker/iam/`); `plan` blocks generic-runner SSM verbs
