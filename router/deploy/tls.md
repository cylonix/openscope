# TLS for the OpenScope Router Stack

Never expose the router (:8080) or console (:8081) without TLS **and** a
real `OPENSCOPE_AUTH_PEPPER` — tokens travel in the Authorization header.

## Option 1 — reverse proxy (recommended)

Terminate TLS at your ALB/NLB, nginx, traefik, or the bundled Caddy edge:

```bash
CADDY_DOMAIN=ai.internal.example docker compose --profile tls up -d
```

The Caddyfile routes `/v1/*` → router, `/api/*` → console, everything else
→ dashboard. Keep the plaintext hop on a private network segment (the
compose file pins service ports to 127.0.0.1 by default).

Behind TLS, set `OPENSCOPE_DEV_INSECURE_COOKIES=false` so console session
cookies are marked Secure.

## Option 2 — built-in TLS

Both `openscope-router` and `openscope-console` serve TLS directly when
`OPENSCOPE_TLS_CERT_FILE` / `OPENSCOPE_TLS_KEY_FILE` are set (min TLS 1.2).
Use certs from your internal CA; point agents' HTTP clients at the CA
bundle as usual.

## Receipts are an independent layer

Ed25519 receipt signatures verify end-to-end regardless of transport — TLS
protects tokens and content in flight; receipts prove what the router
decided.
