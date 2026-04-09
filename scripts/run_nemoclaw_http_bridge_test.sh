#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_BIN="/Applications/OpenScope.app/Contents/Resources/bin/openscoped"

LOCAL_ROOT="${ASCOPE_LOCAL_ROOT:-$HOME}"
DEFAULT_DEMO_ROOT="$LOCAL_ROOT/openscope-nemoclaw-demo"

DEMO_ROOT="${NEMOCLAW_DEMO_ROOT:-$DEFAULT_DEMO_ROOT}"
HTTP_PORT="${OPENSCOPE_HTTP_PORT:-42357}"
HTTP_SOCKET="$(mktemp -u /tmp/openscope-http.XXXXXX.sock)"
HTTP_STDOUT="$(mktemp)"
HTTP_STDERR="$(mktemp)"
HTTP_PID=""
DOCKER_BIN="${DOCKER_BIN:-}"
PILOT_ARGS=("$@")

find_docker_bin() {
  if command -v docker >/dev/null 2>&1; then
    command -v docker
    return 0
  fi
  if [ -n "${DOCKER_APP_CANDIDATE:-}" ] && [ -x "${DOCKER_APP_CANDIDATE:-}" ]; then
    echo "${DOCKER_APP_CANDIDATE}"
    return 0
  fi
  if [ -x "/Applications/Docker.app/Contents/Resources/bin/docker" ]; then
    echo "/Applications/Docker.app/Contents/Resources/bin/docker"
    return 0
  fi
  find /private/var/folders -path '*/AppTranslocation/*/d/Docker.app/Contents/Resources/bin/docker' -print -quit 2>/dev/null || true
}

cleanup() {
  if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
    kill "$HTTP_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
  fi
  rm -f "$HTTP_SOCKET" "$HTTP_STDOUT" "$HTTP_STDERR" 2>/dev/null || true
}

trap cleanup EXIT

if [ ! -x "$APP_BIN" ]; then
  echo "error: openscoped not found at $APP_BIN" >&2
  exit 1
fi

if [ -z "$DOCKER_BIN" ]; then
  DOCKER_BIN="$(find_docker_bin)"
fi
if [ -z "$DOCKER_BIN" ] || [ ! -x "$DOCKER_BIN" ]; then
  echo "error: docker-compatible runtime not found" >&2
  echo "hint: start Docker Desktop or set DOCKER_BIN explicitly" >&2
  exit 1
fi

"$SCRIPT_DIR/setup_nemoclaw_demo.sh" "$DEMO_ROOT" >/dev/null

echo "Starting temporary HTTP bridge on 127.0.0.1:$HTTP_PORT"
OPENSCOPE_SOCKET="$HTTP_SOCKET" OPENSCOPE_HTTP_LISTEN="127.0.0.1:$HTTP_PORT" "$APP_BIN" >"$HTTP_STDOUT" 2>"$HTTP_STDERR" &
HTTP_PID=$!

for _ in $(seq 1 20); do
  if env OPENSCOPE_HTTP_URL="http://127.0.0.1:$HTTP_PORT" openscope status >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! env OPENSCOPE_HTTP_URL="http://127.0.0.1:$HTTP_PORT" openscope status >/dev/null 2>&1; then
  echo "error: temporary HTTP bridge did not become ready" >&2
  echo "stderr:" >&2
  cat "$HTTP_STDERR" >&2 || true
  exit 1
fi

echo "Running NemoClaw pilot through host.docker.internal:$HTTP_PORT"
CMD=( env DOCKER_BIN="$DOCKER_BIN" OPENSCOPE_HTTP_URL="http://host.docker.internal:$HTTP_PORT" \
  "$SCRIPT_DIR/run_nemoclaw_demo_container.sh" "$DEMO_ROOT" )
if [ ${#PILOT_ARGS[@]} -gt 0 ]; then
  CMD+=( "${PILOT_ARGS[@]}" )
fi
exec "${CMD[@]}"
