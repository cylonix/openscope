#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/openclaw_cylonix_plugin_test.sh [options]

Purpose:
  Perform an isolated real OpenClaw install, link the local Cylonix channel
  plugin from this repo, send one message through the installed Cylonix app,
  then tear the temporary OpenClaw install back down.

Options:
  --peer <fqdn-or-stableid>         Receiver peer reference.
                                    Default: m1.vital-skylark.cylonix.org
  --token <auth-token>              Cylonix peer-messaging auth token.
                                    Default: CYLONIX_AUTH_TOKEN or test-token.
  --message <text>                  Message body to send.
  --title <title>                   Conversation title for the send.
  --url <ws-url>                    Default: ws://127.0.0.1:50321/peer-messaging/v1
  --fresh-install                   Force a fresh temporary OpenClaw install.
  --keep-temp                       Keep the temporary install directory.
  --help                            Show this help.

Notes:
  - This script assumes the local Cylonix app is already running.
  - By default it reuses an existing openclaw binary if one is already installed.
  - It still uses a temporary HOME for isolated config, plugin state, and logs.
  - Use --fresh-install to force a brand new temporary OpenClaw install.
  - It links the plugin from plugins/cylonix-channel in this repo.
EOF
}

PEER="m1.vital-skylark.cylonix.org"
TOKEN="${CYLONIX_AUTH_TOKEN:-test-token}"
URL="ws://127.0.0.1:50321/peer-messaging/v1"
TITLE="OpenClaw via Cylonix"
MESSAGE=""
KEEP_TEMP=0
FRESH_INSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --peer) PEER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --message) MESSAGE="$2"; shift 2 ;;
    --title) TITLE="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --fresh-install) FRESH_INSTALL=1; shift ;;
    --keep-temp) KEEP_TEMP=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$MESSAGE" ]; then
  MESSAGE="openclaw plugin smoke test to ${PEER} at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_DIR="$REPO_ROOT/plugins/cylonix-channel"

if [ ! -f "$PLUGIN_DIR/openclaw.plugin.json" ]; then
  echo "error: plugin manifest not found at $PLUGIN_DIR/openclaw.plugin.json" >&2
  exit 1
fi

TMP_BASE_DEFAULT="${TMPDIR:-/tmp}"
TMP_BASE="${OPENCLAW_CYLONIX_TMP_BASE:-$TMP_BASE_DEFAULT}"
mkdir -p "$TMP_BASE"
TMP_ROOT="$(mktemp -d "$TMP_BASE/openclaw-cylonix-test.XXXXXX")"
TMP_HOME="$TMP_ROOT/home"
mkdir -p "$TMP_HOME"
GATEWAY_LOG="$TMP_ROOT/gateway.log"
INSTALL_LOG="$TMP_ROOT/install.log"
GATEWAY_PID=""
ORIGINAL_HOME="${HOME:-}"
EXISTING_OPENCLAW_BIN="$(command -v openclaw || true)"
OPENCLAW_BIN=""

cleanup() {
  local exit_code="$1"
  if [ -n "$GATEWAY_PID" ] && kill -0 "$GATEWAY_PID" >/dev/null 2>&1; then
    kill "$GATEWAY_PID" >/dev/null 2>&1 || true
    wait "$GATEWAY_PID" >/dev/null 2>&1 || true
  fi

  if [ "$KEEP_TEMP" -eq 1 ] || [ "$exit_code" -ne 0 ]; then
    echo "Temporary OpenClaw state kept at: $TMP_ROOT" >&2
  else
    rm -rf "$TMP_ROOT"
  fi
}

trap 'rc=$?; cleanup "$rc"; exit "$rc"' EXIT

echo "Preparing isolated OpenClaw install under: $TMP_ROOT"

export HOME="$TMP_HOME"
if [ -n "$ORIGINAL_HOME" ]; then
  export PATH="$PATH"
fi

if [ "$FRESH_INSTALL" -eq 0 ] && [ -n "$EXISTING_OPENCLAW_BIN" ]; then
  OPENCLAW_BIN="$EXISTING_OPENCLAW_BIN"
  export PATH="$(dirname "$OPENCLAW_BIN"):$PATH"
  echo "Reusing existing OpenClaw binary: $OPENCLAW_BIN"
else
  echo "Installing OpenClaw via install-cli.sh..."
  curl -fsSL --proto '=https' --tlsv1.2 https://openclaw.ai/install-cli.sh | bash >"$INSTALL_LOG" 2>&1
  OPENCLAW_BIN="$HOME/.openclaw/bin/openclaw"
  export PATH="$HOME/.openclaw/bin:$PATH"
fi

if [ -z "$OPENCLAW_BIN" ] || [ ! -x "$OPENCLAW_BIN" ]; then
  echo "error: openclaw was not found after install" >&2
  echo "install log: $INSTALL_LOG" >&2
  exit 1
fi

echo "Linking local plugin: $PLUGIN_DIR"
"$OPENCLAW_BIN" plugins install -l "$PLUGIN_DIR"
"$OPENCLAW_BIN" plugins enable cylonix

mkdir -p "$HOME/.openclaw"
python3 - "$HOME/.openclaw/openclaw.json" "$URL" "$TOKEN" "$TITLE" <<'PY'
import json
import os
import sys

path, url, token, title = sys.argv[1:5]
config = {}
if os.path.exists(path):
    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)

plugins = config.setdefault("plugins", {})
entries = plugins.setdefault("entries", {})
entry = entries.setdefault("cylonix", {})
entry["enabled"] = True

gateway = config.setdefault("gateway", {})
gateway["mode"] = "local"

channels = config.setdefault("channels", {})
cylonix = channels.setdefault("cylonix", {})
accounts = cylonix.setdefault("accounts", {})
default = accounts.setdefault("default", {})
default.update(
    {
        "enabled": True,
        "url": url,
        "token": token,
        "conversationTitle": title,
    }
)

config["channels"] = channels
config["plugins"] = plugins

with open(path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
PY

echo "Starting OpenClaw gateway..."
"$OPENCLAW_BIN" gateway >"$GATEWAY_LOG" 2>&1 &
GATEWAY_PID="$!"

for _ in $(seq 1 30); do
  if "$OPENCLAW_BIN" status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! "$OPENCLAW_BIN" status >/dev/null 2>&1; then
  echo "error: OpenClaw gateway did not become ready" >&2
  echo "gateway log: $GATEWAY_LOG" >&2
  exit 1
fi

echo "Sending test message through the real OpenClaw install..."
echo "  peer  : $PEER"
echo "  token : $TOKEN"
"$OPENCLAW_BIN" message send --channel cylonix --target "$PEER" --message "$MESSAGE"

echo
echo "PASS: OpenClaw sent a message through the Cylonix plugin"
echo "  peer : $PEER"
echo "  temp : $TMP_ROOT"
