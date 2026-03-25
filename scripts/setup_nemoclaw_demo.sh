#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

DEMO_ROOT="${1:-${NEMOCLAW_DEMO_ROOT:-$HOME/openscope-nemoclaw-demo}}"
SOURCE_PATH="${BASH_SOURCE[0]:-$0}"
while [ -L "$SOURCE_PATH" ]; do
  LINK_TARGET="$(readlink "$SOURCE_PATH")"
  if [[ "$LINK_TARGET" = /* ]]; then
    SOURCE_PATH="$LINK_TARGET"
  else
    SOURCE_DIR="$(cd "$(dirname "$SOURCE_PATH")" && pwd)"
    SOURCE_PATH="$SOURCE_DIR/$LINK_TARGET"
  fi
done
SCRIPT_DIR="$(cd "$(dirname "$SOURCE_PATH")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GOOS_TARGET="${GOOS_TARGET:-linux}"
HOST_UNAME="$(uname -m)"
case "${GOARCH_TARGET:-}" in
  "") case "$HOST_UNAME" in
        arm64|aarch64) GOARCH_TARGET="arm64" ;;
        x86_64|amd64) GOARCH_TARGET="amd64" ;;
        *) GOARCH_TARGET="arm64" ;;
      esac ;;
  *) ;;
esac

BIN_DIR="$DEMO_ROOT/bin"
SCRIPTS_DIR="$DEMO_ROOT/scripts"
WORK_DIR="$DEMO_ROOT/workspace"
HOST_RUN_DIR="$HOME/.openscope/run"
HOST_CFG_DIR="$HOME/.openscope"
HOST_ADMIN_DIR="/Library/Application Support/OpenScope"
PILOT_HOME="${OPENSCOPE_PILOT_HOME:-}"

if [ -z "$PILOT_HOME" ]; then
  if [ -f "$SCRIPT_DIR/nemoclaw_pilot_test.sh" ] && [ -d "$SCRIPT_DIR/client" ]; then
    PILOT_HOME="$SCRIPT_DIR"
  elif [ -d "/usr/local/lib/openscope/pilot" ]; then
    PILOT_HOME="/usr/local/lib/openscope/pilot"
  fi
fi

CLIENT_CANDIDATE=""
if [ -n "$PILOT_HOME" ]; then
  CLIENT_CANDIDATE="$PILOT_HOME/client/${GOOS_TARGET}-${GOARCH_TARGET}/openscope"
fi

mkdir -p "$BIN_DIR" "$SCRIPTS_DIR" "$WORK_DIR"

echo "Preparing NemoClaw demo bundle at: $DEMO_ROOT"
echo "Provisioning client-only openscope for ${GOOS_TARGET}/${GOARCH_TARGET}"

if [ -f "$CLIENT_CANDIDATE" ]; then
  cp "$CLIENT_CANDIDATE" "$BIN_DIR/openscope"
elif [ -d "$REPO_ROOT/cmd/openscope" ]; then
  GO_CACHE_ROOT="${ASCOPE_CACHE_ROOT:-$REPO_ROOT/.cache}"
  mkdir -p "$GO_CACHE_ROOT/go-build" "$GO_CACHE_ROOT/go-mod"
  (
    cd "$REPO_ROOT"
    env GOOS="$GOOS_TARGET" GOARCH="$GOARCH_TARGET" CGO_ENABLED=0 \
      GOCACHE="$GO_CACHE_ROOT/go-build" \
      GOMODCACHE="$GO_CACHE_ROOT/go-mod" \
      go build -o "$BIN_DIR/openscope" ./cmd/openscope
  )
else
  echo "error: no prebuilt client found for ${GOOS_TARGET}/${GOARCH_TARGET}" >&2
  echo "hint: install the packaged pilot assets or provide OPENSCOPE_PILOT_HOME" >&2
  exit 1
fi

chmod 755 "$BIN_DIR/openscope"
cp "${PILOT_HOME:-$SCRIPT_DIR}/nemoclaw_pilot_test.sh" "$SCRIPTS_DIR/nemoclaw_pilot_test.sh"
chmod 755 "$SCRIPTS_DIR/nemoclaw_pilot_test.sh"

cat > "$DEMO_ROOT/env.sh" <<EOF
export OPENSCOPE_SOCKET=/var/run/openscope/openscoped.sock
# For Docker Desktop style HTTP bridge mode, unset OPENSCOPE_SOCKET and set:
# export OPENSCOPE_HTTP_URL=http://host.docker.internal:42357
export OPENSCOPE_CONFIG_DIR=/host/openscope-config
export OPENSCOPE_ADMIN_DIR=/host/openscope-admin
export PATH=/demo/bin:\$PATH
EOF

cat > "$DEMO_ROOT/README.txt" <<EOF
OpenScope NemoClaw demo bundle

Host paths expected by the wrapper scripts:
  Host OpenScope run dir   : $HOST_RUN_DIR
  Host OpenScope config dir: $HOST_CFG_DIR
  Host OpenScope admin dir : $HOST_ADMIN_DIR

Sandbox mounts:
  $BIN_DIR        -> /demo/bin
  $SCRIPTS_DIR    -> /demo/scripts
  $HOST_RUN_DIR   -> /var/run/openscope
  $HOST_CFG_DIR   -> /host/openscope-config (ro)
  $HOST_ADMIN_DIR -> /host/openscope-admin (ro)

Primary validation command inside sandbox:
  bash /demo/scripts/nemoclaw_pilot_test.sh --folder Work --note "Sprint Plan"

Optional HTTP bridge:
  Host:    OPENSCOPE_HTTP_LISTEN=127.0.0.1:42357
  Sandbox: OPENSCOPE_HTTP_URL=http://host.docker.internal:42357
EOF

echo
echo "Demo bundle ready:"
echo "  client binary : $BIN_DIR/openscope"
echo "  test scripts  : $SCRIPTS_DIR"
echo "  env file      : $DEMO_ROOT/env.sh"
echo "  workspace     : $WORK_DIR"
echo
echo "No OpenScope app rebuild is required for this script itself."
echo "The demo bundle uses packaged pilot assets when available."
