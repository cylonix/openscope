#!/usr/bin/env bash
# Generates production secrets for the OpenScope router stack (stdout).
# Pipe into your secrets store or deploy/.env — DO NOT commit.
#
# Generates:
#   OPENSCOPE_AUTH_PEPPER          — 32-byte HMAC key for token hashing
#   OPENSCOPE_SESSION_SECRET       — 32-byte HMAC key for cookie sessions
#   OPENSCOPE_ADMIN_TOKEN          — opaque bearer for /api/v1/admin/*
#   OPENSCOPE_RECEIPT_PRIVATE_KEY  — 32-byte Ed25519 seed (hex)
#   OPENSCOPE_RECEIPT_PUBLIC_KEY_ID — versioned id like prod-2026-05-21

set -euo pipefail

random_hex() { openssl rand -hex "$1"; }
random_b64() { openssl rand -base64 "$1" | tr -d '\n'; }
random_token() { openssl rand -hex 24; }

DATE_TAG=$(date -u +%Y-%m-%d)

cat <<EOF
# OpenScope router production secrets — generated $(date -u +%FT%TZ)
# Store in your secrets manager. Each value rotates independently.

OPENSCOPE_AUTH_PEPPER=$(random_hex 32)
OPENSCOPE_SESSION_SECRET=$(random_hex 32)
OPENSCOPE_ADMIN_TOKEN=$(random_token)
OPENSCOPE_RECEIPT_PRIVATE_KEY=$(random_hex 32)
OPENSCOPE_RECEIPT_PUBLIC_KEY_ID=prod-${DATE_TAG}
EOF

cat <<EOF

# Rotation cadence (suggested):
#   OPENSCOPE_AUTH_PEPPER         — never (rotating requires re-minting all tokens)
#   OPENSCOPE_SESSION_SECRET      — quarterly; existing cookies invalidate
#   OPENSCOPE_ADMIN_TOKEN         — monthly; mint a new one and update operator
#   OPENSCOPE_RECEIPT_PRIVATE_KEY — annually; bump RECEIPT_PUBLIC_KEY_ID and
#                                   ship the new public key to customer dashboards
EOF
