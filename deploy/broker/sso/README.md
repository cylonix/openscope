# Broker SSO — reference stack + smoke test

This directory is the **reference deployment** for authenticating human users
to the OpenScope broker through an SSO reverse proxy, and a **runnable proof**
of the whole chain (`scripts/smoke_broker_sso.sh`).

## The chain

```
client  ── IdP JWT ──▶  oauth2-proxy ──▶  nginx ──▶  openscoped ──▶  sshd target
                        │                 │          │
        authenticates the human,   swaps Authorization   trusts X-Forwarded-Email
        forwards X-Forwarded-Email  for the broker's      ONLY for a trusted-proxy
                                    trusted-proxy token   token; scopes policy by
                                                          user; audits the human
```

Two things the broker needs are split across two hops on purpose:

1. **Who the human is** — `oauth2-proxy` does the OIDC/SAML dance with your
   IdP and forwards a verified `X-Forwarded-Email` (and `X-Forwarded-Groups`).
   OpenScope never parses IdP tokens itself, so it stays IdP-agnostic and has
   no JWT/JWKS dependency.
2. **That the proxy is allowed to assert it** — the hop to the broker carries
   a broker-minted `trusted_proxy` token (`Authorization: Bearer osk_agent_…`).
   The broker honors the forwarded user header *only* for such a token, and
   only when `OPENSCOPE_HTTP_TRUST_PROXY=1`. `oauth2-proxy` forwards the
   original IdP token, so the `nginx` hop replaces `Authorization` with the
   proxy token. In many estates that hop is your existing ingress/gateway.

Keep the broker reachable **only** from the proxy tier (private subnet /
security group). The trusted-proxy token is the trust anchor.

## Run the smoke test

```bash
scripts/smoke_broker_sso.sh          # builds, runs, asserts, tears down
scripts/smoke_broker_sso.sh --keep   # leave the stack up for poking
```

It uses [`mock-oauth2-server`](https://github.com/navikt/mock-oauth2-server)
as a headless IdP stand-in and asserts:

- **alice** (allowed by a user-scoped policy) drives a real `ssh check_host`
  on the target; the audit row shows `user=alice@corp.example`,
  `auth_method=proxy`, `agent=claude-code`.
- **bob** (no allow rule) is denied `403`.
- a spoofed `X-Forwarded-Email` with **no** IdP token is rejected by the proxy
  before it ever reaches the broker.

## Pointing at a real IdP

Swap the `oauth2-proxy` provider flags in `docker-compose.yml`; nothing
downstream changes.

| IdP | How |
|---|---|
| **Okta / Entra / Auth0 / Ping** | `--provider=oidc --oidc-issuer-url=<issuer>`, real `--client-id/--client-secret`; drop `--skip-jwt-bearer-tokens` for the interactive browser flow. |
| **Google Workspace** | `--provider=google` with an OAuth client, restricted to your domain (`--google-admin-email` / hosted-domain), or front the broker with **Google IAP** (GCP) which signs its own assertion. |
| **AWS ALB OIDC / Cloudflare Access** | terminate OIDC at the load balancer; it injects the identity header. Replace `oauth2-proxy` with the LB and keep the `nginx` token-injector hop. |

Production notes: terminate TLS at the proxy/LB and set
`OPENSCOPE_HTTP_PLAINTEXT_OK=1` on the broker (private hop); render
`nginx.conf` from your secrets store (never commit the token); and map IdP
groups to OpenScope `groups` policy rules so access follows your directory.
