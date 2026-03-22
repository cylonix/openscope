#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

DEMO_ROOT="${1:-/Volumes/2TB-1/openscope-nemoclaw-demo}"
IMAGE="${NEMOCLAW_DEMO_IMAGE:-ubuntu:24.04}"
HOST_RUN_DIR="$HOME/.openscope/run"
HOST_CFG_DIR="$HOME/.openscope"
HOST_ADMIN_DIR="/Library/Application Support/OpenScope"
DEMO_SCRIPTS_DIR="$DEMO_ROOT/scripts"
DOCKER_BIN="${DOCKER_BIN:-}"
if [ -z "$DOCKER_BIN" ]; then
  if command -v docker >/dev/null 2>&1; then
    DOCKER_BIN="$(command -v docker)"
  elif [ -x "/Volumes/2TB-1/Applications/Docker.app/Contents/Resources/bin/docker" ]; then
    DOCKER_BIN="/Volumes/2TB-1/Applications/Docker.app/Contents/Resources/bin/docker"
  elif [ -x "/Applications/Docker.app/Contents/Resources/bin/docker" ]; then
    DOCKER_BIN="/Applications/Docker.app/Contents/Resources/bin/docker"
  else
    DOCKER_BIN=""
  fi
fi

if [ -z "$DOCKER_BIN" ]; then
  echo "error: docker-compatible runtime not found in PATH" >&2
  echo "hint: start Colima or Docker Desktop first" >&2
  exit 1
fi

DOCKER_DIR="$(cd "$(dirname "$DOCKER_BIN")" && pwd)"
export PATH="$DOCKER_DIR:$PATH"

EXTRA_MOUNTS=()
EXTRA_ENVS=()
if [ "${NEMOCLAW_MOUNT_ADMIN_DIR:-0}" = "1" ] && [ -d "$HOST_ADMIN_DIR" ]; then
  EXTRA_MOUNTS+=( -v "$HOST_ADMIN_DIR:/host/openscope-admin:ro" )
  EXTRA_ENVS+=( -e OPENSCOPE_ADMIN_DIR=/host/openscope-admin )
fi

if [ ! -x "$DEMO_ROOT/bin/openscope" ]; then
  echo "error: missing client-only openscope binary under $DEMO_ROOT/bin" >&2
  echo "hint: run scripts/setup_nemoclaw_demo.sh first" >&2
  exit 1
fi

if [ ! -f "$DEMO_SCRIPTS_DIR/nemoclaw_pilot_test.sh" ]; then
  echo "error: demo pilot script not found at $DEMO_SCRIPTS_DIR/nemoclaw_pilot_test.sh" >&2
  echo "hint: rerun setup_nemoclaw_demo.sh first" >&2
  exit 1
fi

DOCKER_FLAGS=(--rm -i)
if [ -t 0 ] && [ -t 1 ]; then
  DOCKER_FLAGS+=( -t )
fi

if [ -n "${OPENSCOPE_HTTP_URL:-}" ]; then
  CMD=( "$DOCKER_BIN" run "${DOCKER_FLAGS[@]}"
    -v "$DEMO_ROOT/bin:/demo/bin:ro"
    -v "$DEMO_SCRIPTS_DIR:/demo/scripts:ro"
    -v "$HOST_CFG_DIR:/host/openscope-config:ro"
    -w /demo/scripts
    -e OPENSCOPE_HTTP_URL="$OPENSCOPE_HTTP_URL"
    -e OPENSCOPE_CONFIG_DIR=/host/openscope-config
  )
  if [ ${#EXTRA_MOUNTS[@]} -gt 0 ]; then
    CMD+=( "${EXTRA_MOUNTS[@]}" )
  fi
  if [ ${#EXTRA_ENVS[@]} -gt 0 ]; then
    CMD+=( "${EXTRA_ENVS[@]}" )
  fi
  CMD+=( "$IMAGE" /bin/bash -lc 'export PATH=/demo/bin:$PATH; bash /demo/scripts/nemoclaw_pilot_test.sh' )
  exec "${CMD[@]}"
fi

if [ ! -S "$HOST_RUN_DIR/openscoped.sock" ]; then
  echo "error: host OpenScope socket not found at $HOST_RUN_DIR/openscoped.sock" >&2
  echo "hint: verify the installed host daemon with: openscope status" >&2
  exit 1
fi

CMD=( "$DOCKER_BIN" run "${DOCKER_FLAGS[@]}"
  -v "$DEMO_ROOT/bin:/demo/bin:ro"
  -v "$DEMO_SCRIPTS_DIR:/demo/scripts:ro"
  -v "$HOST_RUN_DIR:/var/run/openscope"
  -v "$HOST_CFG_DIR:/host/openscope-config:ro"
  -w /demo/scripts
  -e OPENSCOPE_SOCKET=/var/run/openscope/openscoped.sock
  -e OPENSCOPE_CONFIG_DIR=/host/openscope-config
)
if [ ${#EXTRA_MOUNTS[@]} -gt 0 ]; then
  CMD+=( "${EXTRA_MOUNTS[@]}" )
fi
if [ ${#EXTRA_ENVS[@]} -gt 0 ]; then
  CMD+=( "${EXTRA_ENVS[@]}" )
fi
CMD+=( "$IMAGE" /bin/bash -lc 'export PATH=/demo/bin:$PATH; bash /demo/scripts/nemoclaw_pilot_test.sh' )
exec "${CMD[@]}"
