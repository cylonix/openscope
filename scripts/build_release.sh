#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

# build_release.sh — Build, sign, notarize, and package OpenScope in one step.
#
# Prerequisites (one-time):
#   1. Set up .env.local with your team ID and notarization profile name:
#        AGENTSCOPE_TEAM_ID=YOUR_TEAM_ID
#        NOTARIZE_PROFILE=YourProfileName
#
#   2. Store notarization credentials in your keychain:
#        xcrun notarytool store-credentials "YourProfileName" \
#          --apple-id your@email.com \
#          --team-id YOUR_TEAM_ID \
#          --password <app-specific-password>
#
# Usage:
#   scripts/build_release.sh --version 0.1.1
#   scripts/build_release.sh --version 0.1.1 --install
#
# Options:
#   --version VER    Package version (required)
#   --install        Install the PKG locally after building
#   --skip-archive   Reuse existing archive (skip xcodebuild archive)
#   --skip-notarize  Skip notarization (local testing only)
#   -h, --help       Show this message

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Load local developer config
if [ ! -f "$REPO_ROOT/.env.local" ]; then
  echo "error: .env.local not found — copy .env.local.example and fill in your values" >&2
  exit 1
fi
set -a && . "$REPO_ROOT/.env.local" && set +a

TEAM_ID="${AGENTSCOPE_TEAM_ID:-}"
NOTARIZE_PROFILE="${NOTARIZE_PROFILE:-}"
XCODEPROJ="$REPO_ROOT/macos/OpenScopeApp/OpenScope.xcodeproj"
SCHEME="OpenScope"
ARCHIVE_PATH="$REPO_ROOT/dist/OpenScope.xcarchive"
EXPORT_DIR="$REPO_ROOT/dist/export"

# ── Parse args ───────────────────────────────────────────────────────────────
VERSION=""
DO_INSTALL=false
SKIP_ARCHIVE=false
SKIP_NOTARIZE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)        VERSION="$2"; shift 2 ;;
    --install)        DO_INSTALL=true; shift ;;
    --skip-archive)   SKIP_ARCHIVE=true; shift ;;
    --skip-notarize)  SKIP_NOTARIZE=true; shift ;;
    -h|--help)
      sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \?//'
      exit 0 ;;
    *) echo "error: unknown option: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$VERSION" ]; then
  echo "error: --version is required (e.g. --version 0.1.1)" >&2
  exit 1
fi
if [ -z "$TEAM_ID" ]; then
  echo "error: AGENTSCOPE_TEAM_ID not set in .env.local" >&2
  exit 1
fi
if [ "$SKIP_NOTARIZE" = false ] && [ -z "$NOTARIZE_PROFILE" ]; then
  echo "error: NOTARIZE_PROFILE not set in .env.local (or pass --skip-notarize)" >&2
  exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  OpenScope release builder"
echo "  version:    $VERSION"
echo "  team:       $TEAM_ID"
echo "  notarize:   ${NOTARIZE_PROFILE:-disabled}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Step 1: Archive ──────────────────────────────────────────────────────────
if [ "$SKIP_ARCHIVE" = true ] && [ -d "$ARCHIVE_PATH" ]; then
  echo "==> Skipping archive (--skip-archive, using $ARCHIVE_PATH)"
else
  echo "==> Archiving..."
  # Pass the release version into the Run Script's go build (it stamps
  # buildinfo.Version via -ldflags). Command-line build settings are exported
  # into the script phase environment, where it falls back to `git describe`.
  OPENSCOPE_VERSION="$VERSION" xcodebuild archive \
    -project "$XCODEPROJ" \
    -scheme "$SCHEME" \
    -configuration Release \
    -archivePath "$ARCHIVE_PATH" \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    OPENSCOPE_VERSION="$VERSION" \
    | tail -5
  echo "    archive: $ARCHIVE_PATH"
fi

# ── Step 2: Export ───────────────────────────────────────────────────────────
echo ""
echo "==> Exporting signed app..."

# Generate ExportOptions.plist with the real team ID
WORK_DIR=$(mktemp -d /tmp/openscope-release.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

EXPORT_PLIST="$WORK_DIR/ExportOptions.plist"
sed "s/YOUR_TEAM_ID/$TEAM_ID/g" "$REPO_ROOT/macos/ExportOptions.plist" > "$EXPORT_PLIST"

rm -rf "$EXPORT_DIR"
mkdir -p "$EXPORT_DIR"

xcodebuild -exportArchive \
  -archivePath "$ARCHIVE_PATH" \
  -exportOptionsPlist "$EXPORT_PLIST" \
  -exportPath "$EXPORT_DIR" \
  | tail -5

APP_PATH="$EXPORT_DIR/OpenScope.app"
if [ ! -d "$APP_PATH" ]; then
  echo "error: export did not produce OpenScope.app at $APP_PATH" >&2
  exit 1
fi
echo "    exported: $APP_PATH"

# ── Step 3: Notarize app ────────────────────────────────────────────────────
if [ "$SKIP_NOTARIZE" = true ]; then
  echo ""
  echo "==> Skipping notarization (--skip-notarize)"
else
  echo ""
  echo "==> Notarizing app (this may take a few minutes)..."

  APP_ZIP="$WORK_DIR/OpenScope.zip"
  ditto -c -k --sequesterRsrc --keepParent "$APP_PATH" "$APP_ZIP"

  xcrun notarytool submit "$APP_ZIP" \
    --keychain-profile "$NOTARIZE_PROFILE" \
    --wait

  echo "==> Stapling notarization ticket to app..."
  xcrun stapler staple "$APP_PATH"
fi

# ── Step 4: Build PKG ───────────────────────────────────────────────────────
echo ""
echo "==> Building installer package..."
# --skip-notarize means the app won't be Gatekeeper-accepted; pass --force so
# build_pkg.sh doesn't stall on its "continue anyway?" prompt for a build the
# user already opted into as local-only.
PKG_ARGS=(--version "$VERSION" --app "$APP_PATH")
if [ "$SKIP_NOTARIZE" = true ]; then
  PKG_ARGS+=(--force)
fi
"$REPO_ROOT/scripts/build_pkg.sh" "${PKG_ARGS[@]}"

FINAL_PKG="$REPO_ROOT/dist/OpenScope-$VERSION.pkg"

# ── Step 5: Notarize PKG ────────────────────────────────────────────────────
if [ "$SKIP_NOTARIZE" = true ]; then
  echo "==> Skipping PKG notarization (--skip-notarize)"
else
  echo ""
  echo "==> Notarizing installer package..."
  xcrun notarytool submit "$FINAL_PKG" \
    --keychain-profile "$NOTARIZE_PROFILE" \
    --wait

  echo "==> Stapling notarization ticket to PKG..."
  xcrun stapler staple "$FINAL_PKG"
fi

# ── Step 6: Verify ──────────────────────────────────────────────────────────
echo ""
echo "==> Verifying..."
if spctl --assess -v "$APP_PATH" 2>&1 | grep -q "accepted"; then
  echo "    app: accepted by Gatekeeper"
else
  echo "    app: WARNING — not accepted by Gatekeeper" >&2
fi

if pkgutil --check-signature "$FINAL_PKG" 2>&1 | grep -q "signed"; then
  echo "    pkg: signed"
else
  echo "    pkg: WARNING — unsigned or invalid signature" >&2
fi

# ── Step 7: Install (optional) ──────────────────────────────────────────────
if [ "$DO_INSTALL" = true ]; then
  echo ""
  echo "==> Installing locally..."
  sudo installer -pkg "$FINAL_PKG" -target /
  echo ""
  echo "==> Running diagnostics..."
  # doctor now exits non-zero when a check fails (e.g. Notes Automation not yet
  # approved on a fresh install); don't let that abort the build under set -e.
  openscope --version
  openscope doctor || true
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  $FINAL_PKG"
echo ""
echo "  Install:   sudo installer -pkg '$FINAL_PKG' -target /"
echo "  Verify:    openscope doctor"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
