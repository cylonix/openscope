#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

# scripts/pilot_test.sh — OpenScope pilot test suite
#
# Tests the live installed system end-to-end and prints a structured report.
# Requires OpenScope to be installed and the daemon running.
# Run with: bash scripts/pilot_test.sh [--folder <name>] [--note <title>]
#
# Options:
#   --folder <name>   Notes folder to use for list_notes / read_note tests
#   --note <title>    Note title to use for read_note test
#   --agent <name>    Agent name to use (default: openclaw)

set -euo pipefail

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

# ── colour helpers ─────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; CYAN=''; DIM=''; BOLD=''; RESET=''
fi

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
REPORT=()  # "STATUS|NAME|DETAIL"
HTTP_PID=""
HTTP_SOCKET=""
HTTP_STDOUT=""
HTTP_STDERR=""
ACTIVATION_APP="calendar"
ACTIVATION_READY=0

record() { REPORT+=("$1|$2|$3")
  case "$1" in PASS) PASS_COUNT=$((PASS_COUNT+1));; FAIL) FAIL_COUNT=$((FAIL_COUNT+1));; SKIP) SKIP_COUNT=$((SKIP_COUNT+1));; esac
}

# ── option parsing ─────────────────────────────────────────────────────────────
AGENT="openclaw"; TEST_FOLDER=""; TEST_NOTE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --folder) TEST_FOLDER="$2"; shift 2 ;;
    --note)   TEST_NOTE="$2";   shift 2 ;;
    --agent)  AGENT="$2";       shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── output helpers ─────────────────────────────────────────────────────────────
print_status() {  # status name detail
  local status="$1" name="$2" detail="${3:-}" colour="$RESET"
  case "$status" in PASS) colour="$GREEN";; FAIL) colour="$RED";; SKIP) colour="$YELLOW";; esac
  printf "  ${colour}%-4s${RESET}  %-46s  %s\n" "$status" "$name" "$detail"
}

# Print indented evidence lines below a test result.
# Each line is prefixed with a dim "│" to visually separate from test rows.
show_evidence() {  # text [max_lines]
  local text="$1" max="${2:-20}"
  local count=0
  while IFS= read -r line && [ "$count" -lt "$max" ]; do
    printf "  ${DIM}│${RESET}  %s\n" "$line"
    count=$((count + 1))
  done <<< "$text"
  [ "$count" -ge "$max" ] && printf "  ${DIM}│  … (truncated)${RESET}\n" || true
}

# Format key fields from a JSON blob for evidence display.
# json_extract <json> <python_expr_returning_string>
json_extract() { echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); $2" 2>/dev/null || echo "(parse error)"; }

TEST_OUTPUT=""
run_test() {  # name expect_exit cmd [args...]
  local name="$1" expect_exit="$2"; shift 2
  local ec=0; TEST_OUTPUT=$("$@" 2>&1) || ec=$?
  { [ "$expect_exit" -eq 0 ] && [ "$ec" -eq 0 ]; } || { [ "$expect_exit" -ne 0 ] && [ "$ec" -ne 0 ]; }
}

contains_deny_reason() {
  echo "$1" | grep -qiE "denied|no matching allow|unregistered|not registered|protected|blacklist"
}

contains_transport_failure() {
  echo "$1" | grep -qiE "daemon unavailable|not responding|connect to daemon|operation not permitted"
}

contains_automation_denied() {
  echo "$1" | grep -qiE "not authorized to send apple events|automation|not authorised to send apple events"
}

contains_app_unavailable() {
  echo "$1" | grep -qiE "application|calendar got an error" && echo "$1" | grep -qiE "running|can.?t get"
}

run_with_optional_sudo() {
  if sudo -n true >/dev/null 2>&1; then
    TEST_OUTPUT=""
    run_test "$1" "$2" sudo -n "${@:3}"
    return $?
  fi
  if [ -t 0 ] && [ -t 1 ]; then
    TEST_OUTPUT=""
    run_test "$1" "$2" sudo "${@:3}"
    return $?
  fi
  TEST_OUTPUT="sudo credentials unavailable"
  return 1
}

pick_free_port() {
  python3 <<'EOF' 2>/dev/null || true
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
}

find_docker_bin() {
  if command -v docker >/dev/null 2>&1; then
    command -v docker
    return 0
  fi
  if [ -x "/Volumes/2TB-1/Applications/Docker.app/Contents/Resources/bin/docker" ]; then
    echo "/Volumes/2TB-1/Applications/Docker.app/Contents/Resources/bin/docker"
    return 0
  fi
  if [ -x "/Applications/Docker.app/Contents/Resources/bin/docker" ]; then
    echo "/Applications/Docker.app/Contents/Resources/bin/docker"
    return 0
  fi
  return 1
}

cleanup() {
  if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
    kill "$HTTP_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
  fi
  [ -n "$HTTP_SOCKET" ] && rm -f "$HTTP_SOCKET" 2>/dev/null || true
  [ -n "$HTTP_STDOUT" ] && rm -f "$HTTP_STDOUT" 2>/dev/null || true
  [ -n "$HTTP_STDERR" ] && rm -f "$HTTP_STDERR" 2>/dev/null || true

}

trap cleanup EXIT

# ── header ─────────────────────────────────────────────────────────────────────
printf "\n${BOLD}OpenScope Pilot Test Suite${RESET}\n"
printf '%0.s─' {1..60}; printf '\n'
printf "  Agent : %s\n" "$AGENT"
[ -n "$TEST_FOLDER" ] && printf "  Folder: %s\n" "$TEST_FOLDER" || true
[ -n "$TEST_NOTE" ]   && printf "  Note  : %s\n" "$TEST_NOTE"   || true
printf '%0.s─' {1..60}; printf '\n\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}1. Installation${RESET}\n"

# 1.1 CLI in PATH
if command -v openscope >/dev/null 2>&1; then
  CLI_PATH=$(command -v openscope)
  record PASS "CLI in PATH" "$CLI_PATH"
  print_status PASS "CLI in PATH" "$CLI_PATH"
  show_evidence "$(ls -la "$CLI_PATH")"
else
  record FAIL "CLI in PATH" "openscope not found — is /usr/local/bin in PATH?"
  print_status FAIL "CLI in PATH" "openscope not found"
fi

# 1.2 App bundle installed
APP="/Applications/OpenScope.app"
if [ -d "$APP" ]; then
  APP_VER=$(defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "?")
  record PASS "App bundle installed" "v$APP_VER"
  print_status PASS "App bundle installed" "v$APP_VER"
  SIGN_INFO=$(codesign -dv "$APP" 2>&1 | grep -E '^(Identifier|TeamIdentifier|Timestamp)' || true)
  show_evidence "$SIGN_INFO"
else
  record FAIL "App bundle installed" "$APP not found"
  print_status FAIL "App bundle installed" "$APP not found"
fi

# 1.3 asapple signed with the app's bundle ID
ASAPPLE="$APP/Contents/Resources/bin/asapple"
if [ -x "$ASAPPLE" ]; then
  ASAPPLE_SIGN=$(codesign -dv "$ASAPPLE" 2>&1)
  ASAPPLE_ID=$(echo "$ASAPPLE_SIGN" | grep '^Identifier=' | cut -d= -f2 || echo "?")
  if [ "$ASAPPLE_ID" = "com.ezblock.openscope" ]; then
    record PASS "asapple bundle ID" "$ASAPPLE_ID"
    print_status PASS "asapple bundle ID" "$ASAPPLE_ID"
    show_evidence "$(echo "$ASAPPLE_SIGN" | grep -E '^(Identifier|TeamIdentifier|Format|flags)')"
  else
    record FAIL "asapple bundle ID" "got '$ASAPPLE_ID', want com.ezblock.openscope"
    print_status FAIL "asapple bundle ID" "got '$ASAPPLE_ID'"
    show_evidence "$ASAPPLE_SIGN"
  fi
else
  record FAIL "asapple present" "$ASAPPLE not found"
  print_status FAIL "asapple present" "not found"
fi

# 1.4 LaunchAgent plist installed and loaded
PLIST="$HOME/Library/LaunchAgents/com.ezblock.openscope.openscoped.plist"
if [ -f "$PLIST" ]; then
  LC_STATUS=$(launchctl list 2>/dev/null | grep "com.ezblock.openscope.openscoped" 2>/dev/null || echo "(not listed by launchctl)")
  record PASS "LaunchAgent plist" "installed"
  print_status PASS "LaunchAgent plist" "$PLIST"
  show_evidence "launchctl: $LC_STATUS"
else
  record FAIL "LaunchAgent plist" "$PLIST not found"
  print_status FAIL "LaunchAgent plist" "not found — reinstall?"
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}2. Daemon Health${RESET}\n"

# 2.1 openscope status
STATUS_JSON=$(openscope status 2>&1 || true)
DAEMON_RUNNING=$(json_extract "$STATUS_JSON" "print(d.get('daemon',{}).get('running','false'))")

if [ "$DAEMON_RUNNING" = "True" ] || [ "$DAEMON_RUNNING" = "true" ]; then
  SOCK=$(json_extract "$STATUS_JSON" "print(d.get('socket','?'))")
  record PASS "Daemon running" "$SOCK"
  print_status PASS "Daemon running" "$SOCK"
  show_evidence "$(json_extract "$STATUS_JSON" "
import json
print(json.dumps(d, indent=2))
")"
else
  record FAIL "Daemon running" "not reachable"
  print_status FAIL "Daemon running" "not reachable"
  show_evidence "$STATUS_JSON"
fi

# 2.2 openscope doctor
DOCTOR_OUT=$(openscope doctor 2>&1 || true)
DOCTOR_OK=$(json_extract "$DOCTOR_OUT" "print(str(d.get('ok',False)).lower())")
if [ "$DOCTOR_OK" = "true" ]; then
  record PASS "Doctor checks" "all OK"
  print_status PASS "Doctor checks" "all OK"
  CHECKS=$(json_extract "$DOCTOR_OUT" "
skip={'ok'}
for k,v in d.items():
    if k in skip: continue
    icon='✓' if v is True or (isinstance(v,dict) and v.get('ok')) else '·'
    val=v.get('ok','?') if isinstance(v,dict) else v
    print(f'{icon}  {k}: {val}')
")
  show_evidence "$CHECKS"
else
  record FAIL "Doctor checks" "one or more checks failed"
  print_status FAIL "Doctor checks" "one or more checks failed"
  show_evidence "$(json_extract "$DOCTOR_OUT" "
import json; print(json.dumps(d, indent=2))")"
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}3. Configuration${RESET}\n"

CONFIG="$HOME/.openscope"
PROTECTED_FOLDERS_FILE="/Library/Application Support/OpenScope/protected_folders.yaml"

# 3.1 openclaw agent registered
AGENTS_FILE="$CONFIG/agents.yaml"
if [ -f "$AGENTS_FILE" ] && grep -q "\bopenclaw\b" "$AGENTS_FILE"; then
  record PASS "openclaw agent registered" "found in agents.yaml"
  print_status PASS "openclaw agent registered" "found in agents.yaml"
  show_evidence "$(cat "$AGENTS_FILE")"
else
  record FAIL "openclaw agent registered" "openclaw not in $AGENTS_FILE"
  print_status FAIL "openclaw agent registered" "missing"
  [ -f "$AGENTS_FILE" ] && show_evidence "$(cat "$AGENTS_FILE")"
fi

# 3.2 Default user policies
POLICY_FILE="$CONFIG/policies.yaml"
if [ -f "$POLICY_FILE" ]; then
  OPENCLAW_ALLOW_COUNT=$(awk '
    BEGIN { count = 0; has_list_folders = "false"; has_mail_inbox = "false"; in_rule = 0; effect = ""; agent = ""; app = ""; action = ""; mailbox = "" }
    /^[[:space:]]*-[[:space:]]effect:/ {
      if (in_rule && agent == "openclaw" && effect == "allow") {
        count++
        if (action == "list_folders") {
          has_list_folders = "true"
        }
        if (app == "mail" && mailbox == "Inbox") {
          has_mail_inbox = "true"
        }
      }
      in_rule = 1
      effect = $NF
      agent = ""
      app = ""
      action = ""
      mailbox = ""
      next
    }
    in_rule && /^[[:space:]]*agent:/ { agent = $NF; next }
    in_rule && /^[[:space:]]*app:/ { app = $NF; next }
    in_rule && /^[[:space:]]*action:/ { action = $NF; next }
    in_rule && /^[[:space:]]*mailbox:/ { mailbox = $NF; next }
    END {
      if (in_rule && agent == "openclaw" && effect == "allow") {
        count++
        if (action == "list_folders") {
          has_list_folders = "true"
        }
        if (app == "mail" && mailbox == "Inbox") {
          has_mail_inbox = "true"
        }
      }
      printf "%d|%s|%s\n", count, has_list_folders, has_mail_inbox
    }
  ' "$POLICY_FILE" 2>/dev/null || echo "0|unknown")
  RULE_COUNT="${OPENCLAW_ALLOW_COUNT%%|*}"
  POLICY_TAIL="${OPENCLAW_ALLOW_COUNT#*|}"
  HAS_LIST_FOLDERS="${POLICY_TAIL%%|*}"
  HAS_MAIL_INBOX="${OPENCLAW_ALLOW_COUNT##*|}"
  if [ "$RULE_COUNT" -ge 4 ] && [ "$HAS_LIST_FOLDERS" = "false" ] && [ "$HAS_MAIL_INBOX" = "true" ]; then
    record PASS "Default policies" "$RULE_COUNT openclaw allow rules; notes + Inbox mail only"
    print_status PASS "Default policies" "$RULE_COUNT openclaw allow rules"
    # Show the allow rules in a compact format
    RULES_SUMMARY=$(python3 -c "
import re, sys
lines = open('$POLICY_FILE').read()
blocks = re.split(r'(?=\s*- effect:)', lines)
for b in blocks:
    b = b.strip()
    if 'effect: allow' in b:
        effect = re.search(r'effect:\s*(\S+)', b)
        agent  = re.search(r'agent:\s*(\S+)',  b)
        app    = re.search(r'app:\s*(\S+)',    b)
        action = re.search(r'action:\s*(\S+)', b)
        cons   = re.search(r'constraints:(.*)', b, re.DOTALL)
        parts = [f\"{effect.group(1)} {agent.group(1)} → {app.group(1)}.{action.group(1)}\"]
        if cons:
            con_str = cons.group(1).strip()
            if con_str and con_str != '{}':
                parts.append(f\"[{con_str.replace(chr(10),' ').strip()}]\")
        print('  '.join(parts))
" 2>/dev/null || grep "effect:\|action:\|agent:" "$POLICY_FILE")
    show_evidence "$RULES_SUMMARY"
  else
    record FAIL "Default policies" "want notes + Inbox mail only; got allow_count=$RULE_COUNT list_folders=$HAS_LIST_FOLDERS mail_inbox=$HAS_MAIL_INBOX"
    print_status FAIL "Default policies" "allow_count=$RULE_COUNT list_folders=$HAS_LIST_FOLDERS mail_inbox=$HAS_MAIL_INBOX"
    show_evidence "$(cat "$POLICY_FILE")"
  fi
else
  record FAIL "Default policies" "$POLICY_FILE not found"
  print_status FAIL "Default policies" "file missing"
fi

# 3.3 Admin protected folders file
if [ -f "$PROTECTED_FOLDERS_FILE" ]; then
  if grep -Eq 'private|hidden' "$PROTECTED_FOLDERS_FILE"; then
    record PASS "Protected folder blacklist" "$PROTECTED_FOLDERS_FILE"
    print_status PASS "Protected folder blacklist" "installed"
    show_evidence "$(cat "$PROTECTED_FOLDERS_FILE")"
  else
    record FAIL "Protected folder blacklist" "missing private/hidden defaults"
    print_status FAIL "Protected folder blacklist" "missing private/hidden defaults"
    show_evidence "$(cat "$PROTECTED_FOLDERS_FILE")"
  fi
else
  record FAIL "Protected folder blacklist" "$PROTECTED_FOLDERS_FILE not found"
  print_status FAIL "Protected folder blacklist" "file missing"
fi

MAIL_FILTERS_FILE="/Library/Application Support/OpenScope/mail_filters.yaml"
if [ -f "$MAIL_FILTERS_FILE" ]; then
  record PASS "Mail filters config" "$MAIL_FILTERS_FILE"
  print_status PASS "Mail filters config" "installed"
  show_evidence "$(cat "$MAIL_FILTERS_FILE")"
else
  record FAIL "Mail filters config" "$MAIL_FILTERS_FILE not found"
  print_status FAIL "Mail filters config" "file missing"
fi

# 3.5 Notes Automation permission (TCC)
AE_RAW=$(osascript -e 'tell application "Notes" to return' 2>&1; echo "EXIT:$?")
AE_EXIT=$(echo "$AE_RAW" | grep "EXIT:" | cut -d: -f2)
if [ "$AE_EXIT" = "0" ]; then
  TCC_ENTRY=$(sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
    "SELECT client,auth_value FROM access WHERE service='kTCCServiceAppleEvents' AND indirect_object_identifier='com.apple.Notes';" \
    2>/dev/null | sed 's/|/ → auth_value=/' || echo "(TCC db not readable)")
  record PASS "Notes Automation permission" "granted"
  print_status PASS "Notes Automation permission" "granted"
  show_evidence "osascript: OK (exit 0)
TCC entries for Notes: ${TCC_ENTRY:-none found}"
else
  record FAIL "Notes Automation permission" "denied"
  print_status FAIL "Notes Automation permission" "denied — open /Applications/OpenScope.app"
  show_evidence "$(echo "$AE_RAW" | grep -v "EXIT:")"
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}4. Passthrough App Mode${RESET}\n"

APP_LIST_JSON=$(openscope app list 2>&1 || true)
BUNDLED_PASSTHROUGH_COUNT=$(json_extract "$APP_LIST_JSON" "
apps=d.get('apps', [])
names=sorted(a.get('name') for a in apps if a.get('bundled') and a.get('name') in {'calendar','reminders','contacts','safari','messages'})
print(len(names))
for name in names:
    print(name)
")
COUNT_LINE="$(echo "$BUNDLED_PASSTHROUGH_COUNT" | head -1)"
if [ "$COUNT_LINE" = "5" ]; then
  record PASS "Bundled passthrough apps" "calendar reminders contacts safari messages"
  print_status PASS "Bundled passthrough apps" "5 bundled apps present"
  show_evidence "$(echo "$BUNDLED_PASSTHROUGH_COUNT" | tail -n +2)"
else
  record FAIL "Bundled passthrough apps" "expected 5 common apps"
  print_status FAIL "Bundled passthrough apps" "expected 5 common apps"
  show_evidence "$APP_LIST_JSON"
fi

CALENDAR_POLICY_ACTIVE=0
if [ -f "$POLICY_FILE" ] && grep -Eq "agent:[[:space:]]*$AGENT" "$POLICY_FILE" && grep -Eq "app:[[:space:]]*calendar" "$POLICY_FILE"; then
  CALENDAR_POLICY_ACTIVE=1
fi

if [ "$CALENDAR_POLICY_ACTIVE" -eq 1 ]; then
  ACTIVATION_READY=1
  if run_test "calendar already active" 0 openscope calendar list_calendars --agent "$AGENT"; then
    CAL_COUNT=$(json_extract "$TEST_OUTPUT" "print(len(d.get('data', [])))")
    record PASS "Calendar already activated" "$CAL_COUNT calendar(s) available for $AGENT"
    print_status PASS "Calendar already activated" "$CAL_COUNT calendar(s)"
    show_evidence "$TEST_OUTPUT"
  elif contains_automation_denied "$TEST_OUTPUT"; then
    record SKIP "Calendar permission" "Calendar brokered access is activated but macOS Automation for Calendar is not yet granted"
    print_status SKIP "Calendar permission" "grant OpenScope Automation access to Calendar to validate live passthrough execution"
    show_evidence "$TEST_OUTPUT"
  elif contains_app_unavailable "$TEST_OUTPUT"; then
    record SKIP "Calendar runtime" "Calendar app is not running; passthrough policy is already activated"
    print_status SKIP "Calendar runtime" "launch Calendar to validate live passthrough execution"
    show_evidence "$TEST_OUTPUT"
  else
    record FAIL "Calendar already activated" "$(echo "$TEST_OUTPUT" | head -1)"
    print_status FAIL "Calendar already activated" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
  fi
  record SKIP "Calendar activation" "already activated in current policy"
  print_status SKIP "Calendar activation" "already activated in current policy"
elif run_test "calendar before activation" 0 openscope calendar list_calendars --agent "$AGENT"; then
  ACTIVATION_READY=1
  CAL_COUNT=$(json_extract "$TEST_OUTPUT" "print(len(d.get('data', [])))")
  record PASS "Calendar already activated" "$CAL_COUNT calendar(s) available for $AGENT"
  print_status PASS "Calendar already activated" "$CAL_COUNT calendar(s)"
  show_evidence "$TEST_OUTPUT"
  record SKIP "Calendar activation" "already activated in current policy"
  print_status SKIP "Calendar activation" "already activated in current policy"
else
  if contains_deny_reason "$TEST_OUTPUT"; then
    record PASS "Calendar denied before activation" "passthrough apps are opt-in"
    print_status PASS "Calendar denied before activation" "expected deny"
    show_evidence "$TEST_OUTPUT"
  elif contains_automation_denied "$TEST_OUTPUT"; then
    ACTIVATION_READY=1
    record SKIP "Calendar permission" "Calendar brokered access is activated but macOS Automation for Calendar is not yet granted"
    print_status SKIP "Calendar permission" "grant OpenScope Automation access to Calendar to validate live passthrough execution"
    show_evidence "$TEST_OUTPUT"
    record SKIP "Calendar activation" "already activated in current policy"
    print_status SKIP "Calendar activation" "already activated in current policy"
  elif contains_app_unavailable "$TEST_OUTPUT"; then
    ACTIVATION_READY=1
    record SKIP "Calendar runtime" "Calendar app is unavailable or not running; passthrough policy appears active"
    print_status SKIP "Calendar runtime" "launch Calendar to validate live passthrough execution"
    show_evidence "$TEST_OUTPUT"
    record SKIP "Calendar activation" "already activated in current policy"
    print_status SKIP "Calendar activation" "already activated in current policy"
  else
    record FAIL "Calendar denied before activation" "failed for the wrong reason"
    print_status FAIL "Calendar denied before activation" "failed for the wrong reason"
    show_evidence "$TEST_OUTPUT"
    if run_with_optional_sudo "calendar activate" 0 openscope app activate --agent "$AGENT" "$ACTIVATION_APP"; then
      if run_test "calendar success" 0 openscope calendar list_calendars --agent "$AGENT"; then
        ACTIVATION_READY=1
        CAL_COUNT=$(json_extract "$TEST_OUTPUT" "print(len(d.get('data', [])))")
        record PASS "Calendar activation" "$CAL_COUNT calendar(s) via bundled passthrough app"
        print_status PASS "Calendar activation" "$CAL_COUNT calendar(s)"
        show_evidence "$TEST_OUTPUT"
      elif contains_automation_denied "$TEST_OUTPUT"; then
        ACTIVATION_READY=1
        record SKIP "Calendar permission" "Calendar app activated, but macOS Automation for Calendar is not yet granted"
        print_status SKIP "Calendar permission" "grant OpenScope Automation access to Calendar to validate live passthrough execution"
        show_evidence "$TEST_OUTPUT"
      else
        record FAIL "Calendar activation" "$(echo "$TEST_OUTPUT" | head -1)"
        print_status FAIL "Calendar activation" "$(echo "$TEST_OUTPUT" | head -1)"
        show_evidence "$TEST_OUTPUT"
      fi
    elif echo "$TEST_OUTPUT" | grep -qi "sudo credentials unavailable"; then
      record SKIP "Calendar activation" "sudo credentials unavailable"
      print_status SKIP "Calendar activation" "sudo credentials unavailable"
    else
      record FAIL "Calendar activation" "$(echo "$TEST_OUTPUT" | head -1)"
      print_status FAIL "Calendar activation" "$(echo "$TEST_OUTPUT" | head -1)"
      show_evidence "$TEST_OUTPUT"
    fi
  fi
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}5. Local HTTP Client Access${RESET}\n"

HTTP_PORT="$(pick_free_port)"
if [ -z "$HTTP_PORT" ]; then
  HTTP_PORT="42357"
fi
HTTP_BIN="$APP/Contents/Resources/bin/openscoped"
HTTP_READY=0

if [ -z "$HTTP_PORT" ] || [ ! -x "$HTTP_BIN" ]; then
  record SKIP "Local HTTP client access" "temporary HTTP broker prerequisites missing"
  print_status SKIP "Local HTTP client access" "temporary HTTP broker prerequisites missing"
else
  HTTP_SOCKET=$(mktemp -u /tmp/openscope-http.XXXXXX.sock)
  HTTP_STDOUT=$(mktemp)
  HTTP_STDERR=$(mktemp)
  OPENSCOPE_SOCKET="$HTTP_SOCKET" OPENSCOPE_HTTP_LISTEN="127.0.0.1:$HTTP_PORT" "$HTTP_BIN" >"$HTTP_STDOUT" 2>"$HTTP_STDERR" &
  HTTP_PID=$!

  for _ in $(seq 1 20); do
    HTTP_STATUS=$(env OPENSCOPE_HTTP_URL="http://127.0.0.1:$HTTP_PORT" openscope status 2>&1 || true)
    HTTP_RUNNING=$(json_extract "$HTTP_STATUS" "print(str(d.get('daemon',{}).get('running',False)).lower())")
    if [ "$HTTP_RUNNING" = "true" ]; then
      HTTP_READY=1
      break
    fi
    sleep 0.5
  done

  if [ "$HTTP_READY" -eq 1 ] && run_test "http policy deny" 1 env OPENSCOPE_HTTP_URL="http://127.0.0.1:$HTTP_PORT" openscope notes list_folders --agent "$AGENT"; then
    if contains_deny_reason "$TEST_OUTPUT"; then
      record PASS "Local HTTP client access" "http://127.0.0.1:$HTTP_PORT"
      print_status PASS "Local HTTP client access" "http://127.0.0.1:$HTTP_PORT"
      show_evidence "$HTTP_STATUS
$TEST_OUTPUT"
    else
      record FAIL "Local HTTP client access" "HTTP broker reachable but returned wrong result"
      print_status FAIL "Local HTTP client access" "HTTP broker reachable but returned wrong result"
      show_evidence "$HTTP_STATUS
$TEST_OUTPUT"
    fi
  elif [ "$HTTP_READY" -eq 1 ] && [ "$ACTIVATION_READY" -ne 1 ]; then
    record PASS "Local HTTP client access" "http://127.0.0.1:$HTTP_PORT"
    print_status PASS "Local HTTP client access" "http://127.0.0.1:$HTTP_PORT"
    show_evidence "$HTTP_STATUS"
  elif [ "$HTTP_READY" -eq 1 ] && [ "$ACTIVATION_READY" -eq 1 ] && run_test "http calendar" 0 env OPENSCOPE_HTTP_URL="http://127.0.0.1:$HTTP_PORT" openscope calendar list_calendars --agent "$AGENT"; then
    record PASS "Local HTTP client access" "http://127.0.0.1:$HTTP_PORT"
    print_status PASS "Local HTTP client access" "http://127.0.0.1:$HTTP_PORT"
    show_evidence "$HTTP_STATUS
$TEST_OUTPUT"
  else
    record FAIL "Local HTTP client access" "temporary HTTP broker did not respond"
    print_status FAIL "Local HTTP client access" "temporary HTTP broker did not respond"
    show_evidence "$(cat "$HTTP_STDERR" 2>/dev/null || true)"
  fi
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}6. NemoClaw Bridge${RESET}\n"

DEMO_ROOT="/Volumes/2TB-1/openscope-nemoclaw-demo"
DOCKER_BIN="$(find_docker_bin || true)"
if [ -z "$DOCKER_BIN" ]; then
  record SKIP "NemoClaw sandbox test" "docker not installed"
  print_status SKIP "NemoClaw sandbox test" "docker not installed"
elif [ "$HTTP_READY" -ne 1 ]; then
  record SKIP "NemoClaw sandbox test" "local HTTP bridge unavailable"
  print_status SKIP "NemoClaw sandbox test" "local HTTP bridge unavailable"
else
  if "$SCRIPT_DIR/setup_nemoclaw_demo.sh" "$DEMO_ROOT" >/dev/null 2>&1; then
    record PASS "NemoClaw client bundle" "$DEMO_ROOT"
    print_status PASS "NemoClaw client bundle" "refreshed"
  elif [ -x "$DEMO_ROOT/bin/openscope" ] && [ -f "$DEMO_ROOT/scripts/nemoclaw_pilot_test.sh" ]; then
    record SKIP "NemoClaw client bundle" "refresh failed; using existing bundle"
    print_status SKIP "NemoClaw client bundle" "refresh failed; using existing bundle"
  else
    record FAIL "NemoClaw client bundle" "setup failed"
    print_status FAIL "NemoClaw client bundle" "setup failed"
  fi

  if [ -x "$DEMO_ROOT/bin/openscope" ] && run_test "nemoclaw http bridge" 0 env DOCKER_BIN="$DOCKER_BIN" OPENSCOPE_HTTP_URL="http://host.docker.internal:$HTTP_PORT" "$SCRIPT_DIR/run_nemoclaw_demo_container.sh" "$DEMO_ROOT"; then
    record PASS "NemoClaw sandbox test" "HTTP bridge to host broker succeeded"
    print_status PASS "NemoClaw sandbox test" "HTTP bridge to host broker succeeded"
    NEMO_SUMMARY=$(printf "%s\n" "$TEST_OUTPUT" | awk '
      /Passthrough Apps Through Broker/ { keep=1 }
      keep { print }
    ')
    if [ -n "$NEMO_SUMMARY" ]; then
      show_evidence "$NEMO_SUMMARY" 40
    else
      show_evidence "$(echo "$TEST_OUTPUT" | tail -30)" 30
    fi
  elif [ -x "$DEMO_ROOT/bin/openscope" ]; then
    record FAIL "NemoClaw sandbox test" "$(echo "$TEST_OUTPUT" | head -1)"
    print_status FAIL "NemoClaw sandbox test" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
  else
    record SKIP "NemoClaw sandbox test" "client bundle unavailable"
    print_status SKIP "NemoClaw sandbox test" "client bundle unavailable"
  fi
fi

if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
  kill "$HTTP_PID" 2>/dev/null || true
  wait "$HTTP_PID" 2>/dev/null || true
  HTTP_PID=""
fi
[ -n "$HTTP_SOCKET" ] && rm -f "$HTTP_SOCKET" 2>/dev/null || true
[ -n "$HTTP_STDOUT" ] && rm -f "$HTTP_STDOUT" 2>/dev/null || true
[ -n "$HTTP_STDERR" ] && rm -f "$HTTP_STDERR" 2>/dev/null || true

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}7. Notes Actions  (agent: $AGENT)${RESET}\n"

# 4.1 list_folders is intentionally denied for openclaw
if run_test "list_folders denied" 1 openscope notes list_folders --agent "$AGENT"; then
  if contains_deny_reason "$TEST_OUTPUT" && ! contains_transport_failure "$TEST_OUTPUT"; then
    record PASS "notes list_folders denied" "default agent cannot enumerate folders"
    print_status PASS "notes list_folders denied" "expected deny"
    show_evidence "$TEST_OUTPUT"
  else
    record FAIL "notes list_folders denied" "failed for the wrong reason"
    print_status FAIL "notes list_folders denied" "failed for the wrong reason"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record FAIL "notes list_folders denied" "request unexpectedly succeeded"
  print_status FAIL "notes list_folders denied" "request unexpectedly succeeded"
  show_evidence "$TEST_OUTPUT"
fi

if [ -z "$TEST_FOLDER" ]; then
  TEST_FOLDER=$(osascript <<'EOF' 2>/dev/null || true
tell application "Notes"
	set folderNames to {}
	repeat with acc in every account
		repeat with f in every folder of acc
			set end of folderNames to (name of f as text)
		end repeat
	end repeat
end tell
repeat with folderName in folderNames
	set lowerName to do shell script "printf %s " & quoted form of (folderName as text) & " | tr '[:upper:]' '[:lower:]'"
	if lowerName does not contain "private" and lowerName does not contain "hidden" then
		return folderName as text
	end if
end repeat
EOF
)
fi

# 4.2 list_notes
if [ -n "$TEST_FOLDER" ]; then
  if run_test "list_notes" 0 openscope notes list_notes --agent "$AGENT" --folder "$TEST_FOLDER"; then
    NOTE_TITLES=$(json_extract "$TEST_OUTPUT" "
notes=d.get('data',[])
for n in notes[:8]:
    print(n['title'] if isinstance(n,dict) else n)
if len(notes)>8: print(f'… and {len(notes)-8} more')
")
    NOTE_COUNT=$(json_extract "$TEST_OUTPUT" "print(len(d.get('data',[])))")
    record PASS "notes list_notes" "folder=$TEST_FOLDER  $NOTE_COUNT note(s)"
    print_status PASS "notes list_notes" "folder=$TEST_FOLDER  $NOTE_COUNT note(s)"
    show_evidence "$NOTE_TITLES"
    if [ -z "$TEST_NOTE" ]; then
      TEST_NOTE=$(json_extract "$TEST_OUTPUT" "
n=d.get('data',[]); t=n[0] if n else None
print(t['title'] if isinstance(t,dict) else t) if t else print('')")
    fi
  else
    record FAIL "notes list_notes" "$(echo "$TEST_OUTPUT" | head -1)"
    print_status FAIL "notes list_notes" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
    TEST_NOTE=""
  fi
else
  record SKIP "notes list_notes" "no folder available"
  print_status SKIP "notes list_notes" "skipped (no folder)"
fi

# 4.3 read_note
if [ -n "$TEST_FOLDER" ] && [ -n "$TEST_NOTE" ]; then
  if run_test "read_note" 0 openscope notes read_note --agent "$AGENT" \
      --folder "$TEST_FOLDER" --note "$TEST_NOTE"; then
    NOTE_META=$(json_extract "$TEST_OUTPUT" "
data=d.get('data',{})
body=data.get('body','')
preview=(body[:200]+'…') if len(body)>200 else body
print(f\"title  : {data.get('title','?')}\")
print(f\"folder : $TEST_FOLDER\")
print(f\"chars  : {len(body)}\")
print(f\"body   : {preview}\")
")
    BODY_LEN=$(json_extract "$TEST_OUTPUT" "print(len(d.get('data',{}).get('body','')))")
    record PASS "notes read_note" "note=$TEST_NOTE  body=${BODY_LEN} chars"
    print_status PASS "notes read_note" "note=$TEST_NOTE  body=${BODY_LEN} chars"
    show_evidence "$NOTE_META"
  else
    record FAIL "notes read_note" "$(echo "$TEST_OUTPUT" | head -1)"
    print_status FAIL "notes read_note" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record SKIP "notes read_note" "no folder/note available"
  print_status SKIP "notes read_note" "skipped (no folder/note)"
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}8. Mail Actions  (agent: $AGENT)${RESET}\n"

MAILBOX="Inbox"
MAIL_MESSAGE_ID=""
MAILBOX_MISSING=0

if run_test "mail list_messages" 0 openscope mail list_messages --agent "$AGENT" --mailbox "$MAILBOX" --limit 20 --unread true; then
  MAIL_COUNT=$(json_extract "$TEST_OUTPUT" "print(len(d.get('data',[])))")
  record PASS "mail list_messages" "mailbox=$MAILBOX  $MAIL_COUNT message(s)"
  print_status PASS "mail list_messages" "mailbox=$MAILBOX  $MAIL_COUNT message(s)"
  MAIL_SUMMARY=$(json_extract "$TEST_OUTPUT" "
messages=d.get('data',[])
for m in messages[:8]:
    print(f\"{m.get('id','?')}  {m.get('sender','?')}  {m.get('subject','?')}\")
if len(messages)>8: print(f'… and {len(messages)-8} more')
")
  show_evidence "$MAIL_SUMMARY"
  MAIL_MESSAGE_ID=$(json_extract "$TEST_OUTPUT" "
messages=d.get('data',[])
if messages:
    print(messages[0].get('id',''))
")
else
  if echo "$TEST_OUTPUT" | grep -qiE "can't get mailbox|can’t get mailbox|unknown mailbox|mailbox .* not found"; then
    MAILBOX_MISSING=1
    record PASS "mail list_messages" "Inbox mailbox not configured on this machine"
    print_status PASS "mail list_messages" "Inbox mailbox not configured"
    show_evidence "$TEST_OUTPUT"
  else
    record FAIL "mail list_messages" "$(echo "$TEST_OUTPUT" | head -1)"
    print_status FAIL "mail list_messages" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
  fi
fi

if [ -n "$MAIL_MESSAGE_ID" ]; then
  if run_test "mail read_message" 0 openscope mail read_message --agent "$AGENT" --mailbox "$MAILBOX" --id "$MAIL_MESSAGE_ID" --body-only; then
    BODY_LEN=$(printf "%s" "$TEST_OUTPUT" | wc -c | tr -d ' ')
    record PASS "mail read_message" "id=$MAIL_MESSAGE_ID  body=${BODY_LEN} chars"
    print_status PASS "mail read_message" "id=$MAIL_MESSAGE_ID  body=${BODY_LEN} chars"
    show_evidence "$TEST_OUTPUT"
  else
    record FAIL "mail read_message" "$(echo "$TEST_OUTPUT" | head -1)"
    print_status FAIL "mail read_message" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
  fi
elif [ "$MAILBOX_MISSING" -eq 1 ]; then
  record SKIP "mail read_message" "Inbox mailbox not configured on this machine"
  print_status SKIP "mail read_message" "skipped (Inbox mailbox unavailable)"
else
  record SKIP "mail read_message" "no unread Inbox messages available"
  print_status SKIP "mail read_message" "skipped (no unread Inbox messages)"
fi

if [ "$MAILBOX_MISSING" -eq 1 ]; then
  record SKIP "mail non-Inbox denied" "Inbox mailbox unavailable; skipping mailbox policy check"
  print_status SKIP "mail non-Inbox denied" "skipped (Inbox mailbox unavailable)"
elif run_test "mail non-Inbox denied" 1 openscope mail list_messages --agent "$AGENT" --mailbox "Sent" --limit 5; then
  if contains_deny_reason "$TEST_OUTPUT" && ! contains_transport_failure "$TEST_OUTPUT"; then
    record PASS "mail non-Inbox denied" "default agent is Inbox-only"
    print_status PASS "mail non-Inbox denied" "expected deny"
    show_evidence "$TEST_OUTPUT"
  else
    record FAIL "mail non-Inbox denied" "failed for the wrong reason"
    print_status FAIL "mail non-Inbox denied" "failed for the wrong reason"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record FAIL "mail non-Inbox denied" "request unexpectedly succeeded"
  print_status FAIL "mail non-Inbox denied" "request unexpectedly succeeded"
  show_evidence "$TEST_OUTPUT"
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}9. Policy Enforcement${RESET}\n"

# 6.1 Unregistered agent rejected
RANDOM_AGENT="pilot_test_agent_$$"
if run_test "Unregistered agent rejected" 1 openscope notes list_folders --agent "$RANDOM_AGENT"; then
  ERR_MSG=$(echo "$TEST_OUTPUT" | head -1)
  if echo "$TEST_OUTPUT" | grep -qiE "unregistered|not registered"; then
    record PASS "Unregistered agent rejected" "$ERR_MSG"
    print_status PASS "Unregistered agent rejected" "$ERR_MSG"
    show_evidence "exit non-zero; output: $TEST_OUTPUT"
  else
    record FAIL "Unregistered agent rejected" "failed for the wrong reason"
    print_status FAIL "Unregistered agent rejected" "failed for the wrong reason"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record FAIL "Unregistered agent rejected" "was not rejected"
  print_status FAIL "Unregistered agent rejected" "was not rejected"
  show_evidence "$TEST_OUTPUT"
fi

# 6.2 Unknown app rejected
if run_test "Unknown app rejected" 1 openscope nonexistentapp someaction --agent "$AGENT"; then
  ERR_MSG=$(echo "$TEST_OUTPUT" | head -1)
  if echo "$TEST_OUTPUT" | grep -qiE "not found|unknown action|unknown app"; then
    record PASS "Unknown app rejected" "$ERR_MSG"
    print_status PASS "Unknown app rejected" "$ERR_MSG"
    show_evidence "exit non-zero; output: $TEST_OUTPUT"
  else
    record FAIL "Unknown app rejected" "failed for the wrong reason"
    print_status FAIL "Unknown app rejected" "failed for the wrong reason"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record FAIL "Unknown app rejected" "was not rejected"
  print_status FAIL "Unknown app rejected" "was not rejected"
  show_evidence "$TEST_OUTPUT"
fi

# 6.3 Admin blacklist overrides broader user policy
BLACKLIST_TEST_FOLDER=$(osascript <<'EOF' 2>/dev/null || true
tell application "Notes"
	set folderNames to {}
	repeat with acc in every account
		repeat with f in every folder of acc
			set end of folderNames to (name of f as text)
		end repeat
	end repeat
end tell
repeat with folderName in folderNames
	set lowerName to do shell script "printf %s " & quoted form of (folderName as text) & " | tr '[:upper:]' '[:lower:]'"
	if lowerName contains "private" or lowerName contains "hidden" then
		return folderName as text
	end if
end repeat
EOF
)
if [ -n "$BLACKLIST_TEST_FOLDER" ]; then
  POLICY_BACKUP=$(mktemp)
  cp "$HOME/.openscope/policies.yaml" "$POLICY_BACKUP"
  cat >> "$HOME/.openscope/policies.yaml" <<EOF
  - effect: allow
    agent: $AGENT
    app: notes
    action: list_notes
    constraints:
      folder: $BLACKLIST_TEST_FOLDER
  - effect: allow
    agent: $AGENT
    app: notes
    action: read_note
    constraints:
      folder: $BLACKLIST_TEST_FOLDER
EOF

  DENY_OUTPUT=""
  DENY_EC=0
  DENY_OUTPUT=$(openscope notes list_notes --agent "$AGENT" --folder "$BLACKLIST_TEST_FOLDER" 2>&1) || DENY_EC=$?

  mv "$POLICY_BACKUP" "$HOME/.openscope/policies.yaml"

  if [ "$DENY_EC" -ne 0 ] && echo "$DENY_OUTPUT" | grep -qi "protected\|blacklist\|deny"; then
    record PASS "Admin blacklist overrides user allow" "protected folder still denied"
    print_status PASS "Admin blacklist overrides user allow" "$BLACKLIST_TEST_FOLDER"
    show_evidence "user policy temporarily allowed:
  $AGENT -> notes.list_notes [folder=$BLACKLIST_TEST_FOLDER]
response:
$DENY_OUTPUT"
  else
    record FAIL "Admin blacklist overrides user allow" "protected folder was not denied"
    print_status FAIL "Admin blacklist overrides user allow" "$BLACKLIST_TEST_FOLDER"
    show_evidence "$DENY_OUTPUT"
  fi
else
  record SKIP "Admin blacklist overrides user allow" "no Notes folder with private/hidden in its name"
  print_status SKIP "Admin blacklist overrides user allow" "no protected folder found"
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}10. Audit Log${RESET}\n"

AUDIT_FILE="$HOME/.openscope/audit.jsonl"
if [ -f "$AUDIT_FILE" ] && [ -s "$AUDIT_FILE" ]; then
  ENTRY_COUNT=$(wc -l < "$AUDIT_FILE" | tr -d ' ')
  record PASS "Audit log written" "$ENTRY_COUNT entries"
  print_status PASS "Audit log written" "$ENTRY_COUNT entries"
  # Show last 4 entries formatted as: ts  agent → app.action  decision
  AUDIT_SUMMARY=$(tail -4 "$AUDIT_FILE" | python3 -c "
import sys,json
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try:
        d=json.loads(line)
        ts=d.get('ts','?')[:19].replace('T',' ')
        who=f\"{d.get('agent','?')} → {d.get('app','?')}.{d.get('action','?')}\"
        params=d.get('params',{})
        param_str=', '.join(f'{k}={v}' for k,v in params.items()) if params else ''
        dec=d.get('decision','?')
        print(f'{ts}  {who}({param_str})  [{dec}]')
    except: print(line)
" 2>/dev/null || tail -4 "$AUDIT_FILE")
  show_evidence "$AUDIT_SUMMARY"
else
  record FAIL "Audit log written" "no entries found"
  print_status FAIL "Audit log written" "$AUDIT_FILE missing or empty"
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
TOTAL=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
printf '%0.s─' {1..60}; printf '\n'
printf "${BOLD}Summary  (${TOTAL} tests)${RESET}\n"
printf '%0.s─' {1..60}; printf '\n'
for entry in "${REPORT[@]}"; do
  IFS='|' read -r status name detail <<< "$entry"
  print_status "$status" "$name" "$detail"
done
printf '\n'
printf "  ${GREEN}%d passed${RESET}" "$PASS_COUNT"
[ "$FAIL_COUNT" -gt 0 ] && printf "   ${RED}%d failed${RESET}" "$FAIL_COUNT"
[ "$SKIP_COUNT" -gt 0 ] && printf "   ${YELLOW}%d skipped${RESET}" "$SKIP_COUNT"
printf '\n\n'

[ "$FAIL_COUNT" -eq 0 ]
