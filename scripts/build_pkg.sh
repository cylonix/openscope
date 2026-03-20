#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

# build_pkg.sh — Build OpenScope.pkg from an exported, notarized app bundle.
#
# Step 1 (Xcode): Product → Archive → Distribute App → Developer ID
#                 Export the notarized OpenScope.app to dist/export/
#
# Step 2 (this script):
#   scripts/build_pkg.sh --version 0.1.0
#
# Options:
#   --version VER    Package version (required)
#   --app PATH       Path to OpenScope.app
#                    Default: dist/export/OpenScope.app
#   --output DIR     Output directory (default: dist/)
#   -h, --help       Show this message

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Load local developer config (.env.local is gitignored; copy from .env.local.example)
[ -f "$REPO_ROOT/.env.local" ] && set -a && . "$REPO_ROOT/.env.local" && set +a

BUNDLE_ID="com.ezblock.openscope"
# AGENTSCOPE_TEAM_ID filters signing identity lookup to your Apple Developer Team.
# Set it in .env.local or as an environment variable; leave unset to use the
# first available Developer ID Installer cert in the keychain.
TEAM_ID="${AGENTSCOPE_TEAM_ID:-}"

# ── Defaults ─────────────────────────────────────────────────────────────────
VERSION=""
OUTPUT_DIR="$REPO_ROOT/dist"

# Auto-detect the app: prefer dist/export/OpenScope.app, then find the most
# recently modified OpenScope.app inside any dist/export/ subdirectory
# (Xcode exports to a timestamped folder like "OpenScope 2026-03-19 00-54-50/").
_detect_app() {
  local direct="$REPO_ROOT/dist/export/OpenScope.app"
  if [ -d "$direct" ]; then echo "$direct"; return; fi
  # Use stat to sort by mtime; -print0 + xargs -0 handles spaces in paths
  find "$REPO_ROOT/dist/export" -maxdepth 2 -name "OpenScope.app" -type d -print0 2>/dev/null \
    | xargs -0 stat -f "%m %N" 2>/dev/null \
    | sort -rn | head -1 | cut -d' ' -f2-
}
APP_PATH="$(_detect_app)"

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --app)     APP_PATH="$2"; shift 2 ;;
    --output)  OUTPUT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \?//'
      exit 0 ;;
    *) echo "error: unknown option: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$VERSION" ]; then
  echo "error: --version is required (e.g. --version 0.1.0)" >&2
  exit 1
fi

FINAL_PKG="$OUTPUT_DIR/OpenScope-$VERSION.pkg"
COMPONENT_PKG="$OUTPUT_DIR/OpenScope-component.pkg"
WORK_DIR=$(mktemp -d /tmp/openscope-pkg.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> OpenScope PKG builder"
echo "    app:     $APP_PATH"
echo "    version: $VERSION"
echo "    output:  $FINAL_PKG"

# ── Validate app bundle ───────────────────────────────────────────────────────
if [ ! -d "$APP_PATH" ]; then
  echo "" >&2
  echo "error: OpenScope.app not found (checked dist/export/ and subdirectories)" >&2
  echo "" >&2
  echo "In Xcode: Product → Archive, then in the Organizer:" >&2
  echo "  Distribute App → Developer ID → Export → save to dist/export/" >&2
  echo "" >&2
  echo "Or pass a different path: --app /path/to/OpenScope.app" >&2
  exit 1
fi

for required in \
    "$APP_PATH/Contents/Resources/bin/openscope" \
    "$APP_PATH/Contents/Resources/bin/openscoped" \
    "$APP_PATH/Contents/Resources/bin/asapple" \
    "$APP_PATH/Contents/Resources/launchd/com.ezblock.openscope.openscoped.plist"
do
  if [ ! -f "$required" ]; then
    echo "error: missing from app bundle: $required" >&2
    echo "hint: check the Xcode Run Script build phase (Bundle Go Binaries)" >&2
    exit 1
  fi
done

# ── Verify Gatekeeper ─────────────────────────────────────────────────────────
echo ""
echo "==> Verifying Gatekeeper acceptance..."
if spctl --assess -v "$APP_PATH" 2>&1 | grep -q "accepted"; then
  echo "    ok: accepted (signed and notarized)"
else
  echo "    warning: not accepted by Gatekeeper" >&2
  echo "    Pilot users on other machines will be blocked unless the app is notarized." >&2
  printf "    Continue anyway? [y/N] "
  read -r confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 1
  fi
fi

# ── Auto-detect installer signing identity ────────────────────────────────────
_TEAM_FILTER="${TEAM_ID:+.*$TEAM_ID}"
SIGN_IDENTITY=$(security find-identity -v -p basic 2>/dev/null \
  | grep "Developer ID Installer${_TEAM_FILTER}" \
  | head -1 \
  | sed 's/.*"\(.*\)"/\1/' || true)

if [ -n "$SIGN_IDENTITY" ]; then
  echo "    signing PKG with: $SIGN_IDENTITY"
else
  echo "    warning: no 'Developer ID Installer' identity found — PKG will be unsigned"
fi

# ── Assemble payload ──────────────────────────────────────────────────────────
echo ""
echo "==> Assembling payload..."
PAYLOAD_DIR="$WORK_DIR/payload/Applications"
mkdir -p "$PAYLOAD_DIR"
cp -R "$APP_PATH" "$PAYLOAD_DIR/OpenScope.app"

# ── Copy installer scripts ────────────────────────────────────────────────────
SCRIPTS_DIR="$WORK_DIR/scripts"
mkdir -p "$SCRIPTS_DIR"
cp "$REPO_ROOT/scripts/pkg/preinstall"  "$SCRIPTS_DIR/preinstall"
cp "$REPO_ROOT/scripts/pkg/postinstall" "$SCRIPTS_DIR/postinstall"
chmod 755 "$SCRIPTS_DIR/preinstall" "$SCRIPTS_DIR/postinstall"

# ── Build component package ───────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
echo "==> Running pkgbuild..."
pkgbuild \
  --root "$WORK_DIR/payload" \
  --identifier "$BUNDLE_ID" \
  --version "$VERSION" \
  --install-location "/" \
  --scripts "$SCRIPTS_DIR" \
  "$COMPONENT_PKG"

# ── Write distribution XML ────────────────────────────────────────────────────
DIST_XML="$WORK_DIR/distribution.xml"
cat > "$DIST_XML" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>OpenScope</title>
    <background file="background.png" alignment="bottomleft" scaling="none"/>
    <welcome file="welcome.html"/>
    <license file="license.txt"/>
    <options customize="never" require-scripts="true" hostArchitectures="arm64,x86_64"/>
    <domains enable_localSystem="true"/>
    <pkg-ref id="$BUNDLE_ID"/>
    <choices-outline>
        <line choice="default">
            <line choice="$BUNDLE_ID"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$BUNDLE_ID" visible="false">
        <pkg-ref id="$BUNDLE_ID"/>
    </choice>
    <pkg-ref id="$BUNDLE_ID" version="$VERSION" onConclusion="none">OpenScope-component.pkg</pkg-ref>
</installer-gui-script>
XML

# ── Gather distribution assets ────────────────────────────────────────────────
DIST_RESOURCES="$WORK_DIR/dist-resources"
mkdir -p "$DIST_RESOURCES"
ASSETS_DIR="$REPO_ROOT/scripts/pkg/assets"
for asset in welcome.html license.txt background.png; do
  if [ -f "$ASSETS_DIR/$asset" ]; then
    cp "$ASSETS_DIR/$asset" "$DIST_RESOURCES/$asset"
  fi
done

# ── Build final product package ───────────────────────────────────────────────
echo "==> Running productbuild..."
PB_ARGS=(
  --distribution "$DIST_XML"
  --package-path "$OUTPUT_DIR"
  --resources "$DIST_RESOURCES"
)
if [ -n "$SIGN_IDENTITY" ]; then
  PB_ARGS+=(--sign "$SIGN_IDENTITY")
fi
productbuild "${PB_ARGS[@]}" "$FINAL_PKG"

rm -f "$COMPONENT_PKG"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  $FINAL_PKG"
echo ""
echo "  Test install:"
echo "    sudo installer -pkg '$FINAL_PKG' -target /"
echo "    openscope status && openscope doctor"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
