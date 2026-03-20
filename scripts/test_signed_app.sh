#!/bin/sh
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause


set -eu

usage() {
  cat <<'EOF'
Usage:
  scripts/test_signed_app.sh [/path/to/OpenScope.app] [folder] [note]

Examples:
  scripts/test_signed_app.sh
  scripts/test_signed_app.sh "/Applications/OpenScope.app"
  scripts/test_signed_app.sh "/Applications/OpenScope.app" Work "Sprint Plan"

What it does:
  1. Creates an isolated temporary HOME
  2. Seeds a test agent and policy under that HOME
  3. Launches the signed OpenScope app bundle
  4. Waits for openscoped to create its Unix socket
  5. Runs the bundled openscope client against the live daemon

Notes:
  - This is meant for manual signed-app verification.
  - If you pass folder/note, it will also try a real Notes read.
  - The first Apple Events permission prompt may still appear the first time.
  - If no app path is passed, the script uses:
      .xcodebuild/Build/Products/Debug/OpenScope.app
EOF
}

DEFAULT_APP_PATH="$(cd "$(dirname "$0")/.." && pwd)/.xcodebuild/Build/Products/Debug/OpenScope.app"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

APP_PATH=${1:-$DEFAULT_APP_PATH}
FOLDER=${2:-}
NOTE=${3:-}

APP_EXEC="$APP_PATH/Contents/MacOS/OpenScope"
BIN_DIR="$APP_PATH/Contents/Resources/bin"
OPENSCOPE_BIN="$BIN_DIR/openscope"
OPENSCOPED_BIN="$BIN_DIR/openscoped"
ASAPPLE_BIN="$BIN_DIR/asapple"

for path in "$APP_EXEC" "$OPENSCOPE_BIN" "$OPENSCOPED_BIN" "$ASAPPLE_BIN"; do
  if [ ! -x "$path" ]; then
    echo "error: required executable not found: $path" >&2
    exit 1
  fi
done

TEST_HOME=$(mktemp -d /tmp/openscope-signed-test.XXXXXX)
CONFIG_DIR="$TEST_HOME/.openscope"
RUN_DIR="$CONFIG_DIR/run"

cleanup() {
  if [ -n "${APP_PID:-}" ] && kill -0 "$APP_PID" 2>/dev/null; then
    kill "$APP_PID" 2>/dev/null || true
  fi
  if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$TEST_HOME"
}
trap cleanup EXIT INT TERM

mkdir -p "$CONFIG_DIR/apps.d" "$CONFIG_DIR/state" "$RUN_DIR"

cat > "$CONFIG_DIR/agents.yaml" <<'EOF'
version: 1
agents:
  - demo
  - research_assistant
  - admin
EOF

cat > "$CONFIG_DIR/policies.yaml" <<'EOF'
version: 1
rules:
  # demo: basic smoke-test access
  - effect: allow
    agent: demo
    app: notes
    action: list_folders
  - effect: allow
    agent: demo
    app: notes
    action: list_notes
    constraints:
      folder: Work
  - effect: allow
    agent: demo
    app: notes
    action: read_note
    constraints:
      folder: Work

  # research_assistant: general notes access, but blocked from protected folders
  - effect: allow
    agent: research_assistant
    app: notes
    action: list_folders
  - effect: allow
    agent: research_assistant
    app: notes
    action: list_notes
  - effect: allow
    agent: research_assistant
    app: notes
    action: read_note
  - effect: deny
    agent: research_assistant
    app: notes
    action: list_notes
    constraints:
      folder: Private
  - effect: deny
    agent: research_assistant
    app: notes
    action: read_note
    constraints:
      folder: Private
  - effect: deny
    agent: research_assistant
    app: notes
    action: list_notes
    constraints:
      folder: test-admin
  - effect: deny
    agent: research_assistant
    app: notes
    action: read_note
    constraints:
      folder: test-admin

  # admin: full notes access including protected folders
  - effect: allow
    agent: admin
    app: notes
    action: list_folders
  - effect: allow
    agent: admin
    app: notes
    action: list_notes
  - effect: allow
    agent: admin
    app: notes
    action: read_note
EOF

echo "Using isolated HOME: $TEST_HOME"
echo "Launching signed app: $APP_PATH"

HOME="$TEST_HOME" "$APP_EXEC" >/dev/null 2>&1 &
APP_PID=$!

SOCKET="$RUN_DIR/openscoped.sock"
ATTEMPTS=50
while [ $ATTEMPTS -gt 0 ]; do
  if [ -S "$SOCKET" ]; then
    break
  fi
  ATTEMPTS=$((ATTEMPTS - 1))
  sleep 0.2
done

if [ ! -S "$SOCKET" ]; then
  echo "error: openscoped socket was not created at $SOCKET" >&2
  echo "hint: check app signing/build output and launch behavior" >&2
  exit 1
fi

echo
echo "Socket is up:"
ls -l "$SOCKET"

echo
echo "Running list_folders smoke test"
HOME="$TEST_HOME" "$OPENSCOPE_BIN" notes list_folders --agent demo

if [ -n "$FOLDER" ]; then
  echo
  echo "Running list_notes smoke test for folder: $FOLDER"
  HOME="$TEST_HOME" "$OPENSCOPE_BIN" notes list_notes --agent demo --folder "$FOLDER"
fi

if [ -n "$FOLDER" ] && [ -n "$NOTE" ]; then
  echo
  echo "Running read_note smoke test for folder=$FOLDER note=$NOTE"
  HOME="$TEST_HOME" "$OPENSCOPE_BIN" notes read_note --agent demo --folder "$FOLDER" --note "$NOTE"

  echo
  echo "Running body-only smoke test"
  HOME="$TEST_HOME" "$OPENSCOPE_BIN" notes read_note --agent demo --folder "$FOLDER" --note "$NOTE" --body-only
  printf '\n'
fi


# ── Policy deny tests: research_assistant blocked from protected folders ───────

PASS=0
FAIL=0

expect_deny() {
  label="$1"; shift
  out=$(HOME="$TEST_HOME" "$OPENSCOPE_BIN" "$@" 2>&1 || true)
  if echo "$out" | grep -qE '"ok".*false|denied'; then
    echo "  PASS  $label"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label (expected denial but request succeeded)"
    echo "        output: $out"
    FAIL=$((FAIL + 1))
  fi
}

expect_allow() {
  label="$1"; shift
  out=$(HOME="$TEST_HOME" "$OPENSCOPE_BIN" "$@" 2>&1 || true)
  if echo "$out" | grep -q '"ok".*true'; then
    echo "  PASS  $label"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label (expected success but request was denied or errored)"
    echo "        output: $out"
    FAIL=$((FAIL + 1))
  fi
}

echo
echo "── Policy deny tests (research_assistant) ──────────────────────────────"
expect_deny "research_assistant blocked from list_notes in Private" \
  notes list_notes --agent research_assistant --folder Private
expect_deny "research_assistant blocked from read_note  in Private" \
  notes read_note  --agent research_assistant --folder Private --note dummy
expect_deny "research_assistant blocked from list_notes in test-admin" \
  notes list_notes --agent research_assistant --folder test-admin
expect_deny "research_assistant blocked from read_note  in test-admin" \
  notes read_note  --agent research_assistant --folder test-admin --note dummy

echo
echo "── Policy allow tests (research_assistant allowed elsewhere) ───────────"
expect_allow "research_assistant allowed list_folders" \
  notes list_folders --agent research_assistant

echo
printf "Result: %d passed, %d failed\n" "$PASS" "$FAIL"

# ── admin: enumerate and print notes in test-admin ────────────────────────────

echo
echo "── admin reads notes in test-admin ─────────────────────────────────────"
NOTES_JSON=$(HOME="$TEST_HOME" "$OPENSCOPE_BIN" notes list_notes --agent admin --folder test-admin 2>&1)
echo "list_notes response:"
echo "$NOTES_JSON"

NOTE_NAMES=$(echo "$NOTES_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if d.get('ok') and isinstance(d.get('data'), list):
    for n in d['data']:
        title = n['title'] if isinstance(n, dict) else n
        print(title)
" 2>/dev/null || true)

if [ -z "$NOTE_NAMES" ]; then
  echo "(no notes found in test-admin — create at least one note there first)"
else
  echo "$NOTE_NAMES" | while IFS= read -r note_name; do
    echo
    echo "  note: $note_name"
    HOME="$TEST_HOME" "$OPENSCOPE_BIN" notes read_note \
      --agent admin --folder test-admin --note "$note_name" --body-only || true
    printf '\n'
  done
fi

if [ "$FAIL" -gt 0 ]; then
  echo
  echo "warning: $FAIL policy test(s) failed — see above" >&2
fi

echo
if [ -f "$CONFIG_DIR/audit.jsonl" ]; then
  cat "$CONFIG_DIR/audit.jsonl"
else
  echo "(no audit log written yet)"
fi

echo
echo "Test completed."
echo "If this was the first Automation request, check whether macOS prompted for OpenScope access to Notes."
