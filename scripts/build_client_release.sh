#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

VERSION=""
GOOS_TARGET="${GOOS_TARGET:-linux}"
GOARCH_TARGET="${GOARCH_TARGET:-arm64}"
OUT_DIR="${OUT_DIR:-dist/client}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  scripts/build_client_release.sh --version <version> [--goos linux] [--goarch arm64] [--out-dir dist/client]

Purpose:
  Build a client-only openscope release tarball for sandboxed NemoClaw/OpenShell installs.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --goos) GOOS_TARGET="$2"; shift 2 ;;
    --goarch) GOARCH_TARGET="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$VERSION" ]; then
  echo "error: --version is required" >&2
  usage >&2
  exit 1
fi

ARTIFACT_DIR="$REPO_ROOT/$OUT_DIR/openscope-${GOOS_TARGET}-${GOARCH_TARGET}"
BIN_DIR="$ARTIFACT_DIR/bin"
ARCHIVE_PATH="$REPO_ROOT/$OUT_DIR/openscope-${VERSION}-${GOOS_TARGET}-${GOARCH_TARGET}.tar.gz"

rm -rf "$ARTIFACT_DIR"
mkdir -p "$BIN_DIR"

env GOOS="$GOOS_TARGET" GOARCH="$GOARCH_TARGET" CGO_ENABLED=0 \
  GOCACHE=/Volumes/2TB-1/src/ascope/.cache/go-build \
  GOMODCACHE=/Volumes/2TB-1/src/ascope/.cache/go-mod \
  go build -o "$BIN_DIR/openscope" ./cmd/openscope

chmod 755 "$BIN_DIR/openscope"
cp "$REPO_ROOT/LICENSE" "$ARTIFACT_DIR/LICENSE"

cat > "$ARTIFACT_DIR/README.txt" <<EOF
OpenScope client-only release

Contents:
  bin/openscope

Intended use:
  - install inside a sandboxed NemoClaw/OpenShell environment
  - do not run openscoped in the sandbox
  - point the client at a provisioned host broker

Environment:
  OPENSCOPE_SOCKET      Unix socket path to the host broker
  OPENSCOPE_HTTP_URL    Optional localhost bridge URL, for example http://host.docker.internal:42357
  OPENSCOPE_CONFIG_DIR  Optional read-only mounted host config path
  OPENSCOPE_ADMIN_DIR   Optional read-only mounted host admin config path
EOF

mkdir -p "$(dirname "$ARCHIVE_PATH")"
tar -C "$REPO_ROOT/$OUT_DIR" -czf "$ARCHIVE_PATH" "openscope-${GOOS_TARGET}-${GOARCH_TARGET}"

echo "Built client release:"
echo "  $ARCHIVE_PATH"
