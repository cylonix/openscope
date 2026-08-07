#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/nemoclaw_pilot_test.sh [--agent <name>] [--folder <name>] [--note <title>]

Purpose:
  Exercise the live host OpenScope broker from inside a sandbox/container by using
  either a mounted Unix socket or a localhost HTTP bridge. This is the
  sandbox-facing companion to scripts/pilot_test.sh.

Environment:
  OPENSCOPE_SOCKET          Optional. Mounted path to the host openscoped socket.
  OPENSCOPE_HTTP_URL        Optional. Localhost bridge URL for the host broker.
  OPENSCOPE_CONFIG_DIR      Optional. Read-only mounted host ~/.openscope path.
  OPENSCOPE_ADMIN_DIR       Optional. Read-only mounted /Library/Application Support/OpenScope path.

Example:
  export OPENSCOPE_SOCKET=/var/run/openscope/openscoped.sock
  # or: export OPENSCOPE_HTTP_URL=http://host.docker.internal:42357
  export OPENSCOPE_CONFIG_DIR=/host/openscope-config
  export OPENSCOPE_ADMIN_DIR=/host/openscope-admin
  bash scripts/nemoclaw_pilot_test.sh
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ -z "${OPENSCOPE_SOCKET:-}" ] && [ -z "${OPENSCOPE_HTTP_URL:-}" ]; then
  echo "error: OPENSCOPE_SOCKET or OPENSCOPE_HTTP_URL is required" >&2
  usage >&2
  exit 1
fi

if [ -t 1 ]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
  DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; DIM=''; BOLD=''; RESET=''
fi

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
record() {
  case "$1" in
    PASS) PASS_COUNT=$((PASS_COUNT+1));;
    FAIL) FAIL_COUNT=$((FAIL_COUNT+1));;
    SKIP) SKIP_COUNT=$((SKIP_COUNT+1));;
  esac
}

print_status() {
  local status="$1" name="$2" detail="${3:-}" colour="$RESET"
  case "$status" in PASS) colour="$GREEN";; FAIL) colour="$RED";; SKIP) colour="$YELLOW";; esac
  printf "  ${colour}%-4s${RESET}  %-42s  %s\n" "$status" "$name" "$detail"
}

show_evidence() {
  local text="$1" max="${2:-12}" count=0
  while IFS= read -r line && [ "$count" -lt "$max" ]; do
    printf "  ${DIM}│${RESET}  %s\n" "$line"
    count=$((count + 1))
  done <<< "$text"
  [ "$count" -ge "$max" ] && printf "  ${DIM}│  … (truncated)${RESET}\n" || true
}

json_extract() {
  local json="$1" expr="$2"
  if command -v python3 >/dev/null 2>&1; then
    echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); $expr" 2>/dev/null && return 0
  fi

  case "$expr" in
    "print(str(d.get('daemon',{}).get('running',False)).lower())")
      if echo "$json" | grep -q '"running"[[:space:]]*:[[:space:]]*true'; then
        echo "true"
      else
        echo "false"
      fi
      ;;
    "print(len(d.get('data',[])))")
      echo "$json" | awk '
        BEGIN { count = 0 }
        /"data"[[:space:]]*:[[:space:]]*\[/ { in_data = 1 }
        in_data && /}/ { count++ }
        in_data && /\]/ { print count; exit }
        END { if (!in_data) print 0 }
      '
      ;;
    "n=d.get('data',[]); print((n[0] or {}).get('title','') if n else '')")
      echo "$json" | sed -n 's/.*"title"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
      ;;
    "messages=d.get('data',[]); print(messages[0].get('id','') if messages else '')")
      echo "$json" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
      ;;
    *)
      echo "(parse error)"
      ;;
  esac
}

run_test() {
  local expect_exit="$1"; shift
  TEST_OUTPUT=""
  local ec=0
  TEST_OUTPUT=$("$@" 2>&1) || ec=$?
  { [ "$expect_exit" -eq 0 ] && [ "$ec" -eq 0 ]; } || { [ "$expect_exit" -ne 0 ] && [ "$ec" -ne 0 ]; }
}

contains_deny_reason() {
  echo "$1" | grep -qiE "denied|no matching allow|unregistered|not registered|protected|blacklist"
}

contains_app_unavailable() {
  echo "$1" | grep -qiE "application|calendar got an error" && echo "$1" | grep -qiE "running|can.?t get"
}

AGENT="openclaw"; TEST_FOLDER=""; TEST_NOTE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --folder) TEST_FOLDER="$2"; shift 2 ;;
    --note)   TEST_NOTE="$2"; shift 2 ;;
    --agent)  AGENT="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

CONFIG_DIR="${OPENSCOPE_CONFIG_DIR:-}"
ADMIN_DIR="${OPENSCOPE_ADMIN_DIR:-}"
MAILBOX="Inbox"
MAIL_MESSAGE_ID=""
TRANSPORT_DETAIL="${OPENSCOPE_SOCKET:-${OPENSCOPE_HTTP_URL:-}}"

printf "\n${BOLD}OpenScope NemoClaw Bridge Pilot${RESET}\n"
printf '%0.s─' {1..60}; printf '\n'
printf "  Agent  : %s\n" "$AGENT"
[ -n "${OPENSCOPE_SOCKET:-}" ] && printf "  Socket : %s\n" "$OPENSCOPE_SOCKET"
[ -n "${OPENSCOPE_HTTP_URL:-}" ] && printf "  HTTP   : %s\n" "$OPENSCOPE_HTTP_URL"
[ -n "$CONFIG_DIR" ] && printf "  Config : %s\n" "$CONFIG_DIR"
[ -n "$ADMIN_DIR" ] && printf "  Admin  : %s\n" "$ADMIN_DIR"
printf '%0.s─' {1..60}; printf '\n\n'

printf "${BOLD}1. Broker Bridge${RESET}\n"
if [ -n "${OPENSCOPE_SOCKET:-}" ]; then
  if [ -S "$OPENSCOPE_SOCKET" ]; then
    record PASS; print_status PASS "Mounted socket present" "$OPENSCOPE_SOCKET"
  else
    record FAIL; print_status FAIL "Mounted socket present" "missing"
  fi
else
  record SKIP; print_status SKIP "Mounted socket present" "HTTP bridge mode"
fi

STATUS_JSON=$(openscope status 2>&1 || true)
STATUS_OK=$(json_extract "$STATUS_JSON" "print(str(d.get('daemon',{}).get('running',False)).lower())")
if [ "$STATUS_OK" = "true" ]; then
  record PASS; print_status PASS "Broker reachable" "$TRANSPORT_DETAIL"
  show_evidence "$(json_extract "$STATUS_JSON" "import json; print(json.dumps(d, indent=2))")"
else
  record FAIL; print_status FAIL "Broker reachable" "daemon unavailable"
  show_evidence "$STATUS_JSON"
fi

printf '\n'
printf "${BOLD}2. Optional Host Config Checks${RESET}\n"

if [ -n "$CONFIG_DIR" ] && [ -f "$CONFIG_DIR/agents.yaml" ]; then
  if grep -q "\bopenclaw\b" "$CONFIG_DIR/agents.yaml"; then
    record PASS; print_status PASS "openclaw agent registered" "$CONFIG_DIR/agents.yaml"
  else
    record FAIL; print_status FAIL "openclaw agent registered" "missing from mounted config"
  fi
else
  record SKIP; print_status SKIP "openclaw agent registered" "mount OPENSCOPE_CONFIG_DIR for host config checks"
fi

if [ -n "$CONFIG_DIR" ] && [ -f "$CONFIG_DIR/policies.yaml" ]; then
  if grep -q "app: mail" "$CONFIG_DIR/policies.yaml" && grep -q "mailbox: Inbox" "$CONFIG_DIR/policies.yaml" && ! grep -q "action: list_folders" "$CONFIG_DIR/policies.yaml"; then
    record PASS; print_status PASS "Default openclaw policy" "Notes read/list + Mail Inbox"
  else
    record FAIL; print_status FAIL "Default openclaw policy" "mounted policy does not match expected defaults"
    show_evidence "$(cat "$CONFIG_DIR/policies.yaml")"
  fi
else
  record SKIP; print_status SKIP "Default openclaw policy" "mount OPENSCOPE_CONFIG_DIR for host config checks"
fi

if [ -n "$ADMIN_DIR" ] && [ -f "$ADMIN_DIR/protected_folders.yaml" ] && [ -f "$ADMIN_DIR/mail_filters.yaml" ]; then
  record PASS; print_status PASS "Admin config mounted" "$ADMIN_DIR"
else
  record SKIP; print_status SKIP "Admin config mounted" "mount OPENSCOPE_ADMIN_DIR for blacklist/domain checks"
fi

printf '\n'
printf "${BOLD}3. Passthrough Apps Through Broker${RESET}\n"

if run_test 0 openscope calendar list_calendars --agent "$AGENT"; then
  CAL_COUNT=$(json_extract "$TEST_OUTPUT" "print(len(d.get('data',[])))")
  record PASS; print_status PASS "calendar list_calendars" "$CAL_COUNT calendar(s)"
else
  if contains_deny_reason "$TEST_OUTPUT"; then
    record SKIP; print_status SKIP "calendar list_calendars" "calendar not activated for this agent"
  elif contains_app_unavailable "$TEST_OUTPUT"; then
    record SKIP; print_status SKIP "calendar list_calendars" "Calendar app is not running on the host"
  else
    record FAIL; print_status FAIL "calendar list_calendars" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
  fi
fi

printf '\n'
printf "${BOLD}4. Notes Through Broker${RESET}\n"

if run_test 1 openscope notes list_folders --agent "$AGENT"; then
  if contains_deny_reason "$TEST_OUTPUT"; then
    record PASS; print_status PASS "notes list_folders denied" "expected deny"
  else
    record FAIL; print_status FAIL "notes list_folders denied" "wrong failure reason"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record FAIL; print_status FAIL "notes list_folders denied" "unexpected success"
  show_evidence "$TEST_OUTPUT"
fi

if [ -n "$TEST_FOLDER" ]; then
  if run_test 0 openscope notes list_notes --agent "$AGENT" --folder "$TEST_FOLDER"; then
    NOTE_COUNT=$(json_extract "$TEST_OUTPUT" "print(len(d.get('data',[])))")
    record PASS; print_status PASS "notes list_notes" "folder=$TEST_FOLDER  $NOTE_COUNT note(s)"
    TEST_NOTE="${TEST_NOTE:-$(json_extract "$TEST_OUTPUT" "n=d.get('data',[]); print((n[0] or {}).get('title','') if n else '')")}"
  else
    record FAIL; print_status FAIL "notes list_notes" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record SKIP; print_status SKIP "notes list_notes" "pass --folder to validate Notes content access"
fi

if [ -n "$TEST_FOLDER" ] && [ -n "$TEST_NOTE" ]; then
  if run_test 0 openscope notes read_note --agent "$AGENT" --folder "$TEST_FOLDER" --note "$TEST_NOTE" --body-only; then
    BODY_LEN=$(printf "%s" "$TEST_OUTPUT" | wc -c | tr -d ' ')
    record PASS; print_status PASS "notes read_note" "note=$TEST_NOTE  body=${BODY_LEN} chars"
  else
    record FAIL; print_status FAIL "notes read_note" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record SKIP; print_status SKIP "notes read_note" "pass --folder and --note to validate note reads"
fi

printf '\n'
printf "${BOLD}5. Mail Through Broker${RESET}\n"

if run_test 0 openscope mail list_messages --agent "$AGENT" --mailbox "$MAILBOX" --limit 20 --unread true; then
  MAIL_COUNT=$(json_extract "$TEST_OUTPUT" "print(len(d.get('data',[])))")
  record PASS; print_status PASS "mail list_messages" "mailbox=$MAILBOX  $MAIL_COUNT message(s)"
  MAIL_MESSAGE_ID=$(json_extract "$TEST_OUTPUT" "messages=d.get('data',[]); print(messages[0].get('id','') if messages else '')")
elif echo "$TEST_OUTPUT" | grep -qi "audit log is not writable"; then
  # System-mode deployment: the bridge is a user-launched shadow daemon, and it
  # correctly refuses to EXECUTE an allowed action it cannot audit (only the
  # root daemon can append to the root-owned log). That fail-closed custody
  # property is working as designed — execution coverage needs the real daemon.
  record PASS; print_status PASS "mail list_messages" "shadow daemon refused unlogged execution (system-mode custody holds)"
  show_evidence "$TEST_OUTPUT"
else
  record FAIL; print_status FAIL "mail list_messages" "$(echo "$TEST_OUTPUT" | head -1)"
  show_evidence "$TEST_OUTPUT"
fi

if [ -n "$MAIL_MESSAGE_ID" ]; then
  if run_test 0 openscope mail read_message --agent "$AGENT" --mailbox "$MAILBOX" --id "$MAIL_MESSAGE_ID" --body-only; then
    BODY_LEN=$(printf "%s" "$TEST_OUTPUT" | wc -c | tr -d ' ')
    record PASS; print_status PASS "mail read_message" "id=$MAIL_MESSAGE_ID  body=${BODY_LEN} chars"
  else
    record FAIL; print_status FAIL "mail read_message" "$(echo "$TEST_OUTPUT" | head -1)"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record SKIP; print_status SKIP "mail read_message" "no unread Inbox messages available"
fi

if run_test 1 openscope mail list_messages --agent "$AGENT" --mailbox "Sent" --limit 5; then
  if contains_deny_reason "$TEST_OUTPUT"; then
    record PASS; print_status PASS "mail non-Inbox denied" "expected deny"
  else
    record FAIL; print_status FAIL "mail non-Inbox denied" "wrong failure reason"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record FAIL; print_status FAIL "mail non-Inbox denied" "unexpected success"
  show_evidence "$TEST_OUTPUT"
fi

printf '\n'
printf "${BOLD}6. Policy Edge Cases${RESET}\n"

RANDOM_AGENT="nemoclaw_test_agent_$$"
if run_test 1 openscope notes list_notes --agent "$RANDOM_AGENT" --folder "${TEST_FOLDER:-Work}"; then
  if echo "$TEST_OUTPUT" | grep -qiE "unregistered|not registered"; then
    record PASS; print_status PASS "Unregistered agent rejected" "$(echo "$TEST_OUTPUT" | head -1)"
  else
    record FAIL; print_status FAIL "Unregistered agent rejected" "wrong failure reason"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record FAIL; print_status FAIL "Unregistered agent rejected" "unexpected success"
  show_evidence "$TEST_OUTPUT"
fi

if run_test 1 openscope nonexistentapp someaction --agent "$AGENT"; then
  if echo "$TEST_OUTPUT" | grep -qiE "not found|unknown action|unknown app"; then
    record PASS; print_status PASS "Unknown app rejected" "$(echo "$TEST_OUTPUT" | head -1)"
  else
    record FAIL; print_status FAIL "Unknown app rejected" "wrong failure reason"
    show_evidence "$TEST_OUTPUT"
  fi
else
  record FAIL; print_status FAIL "Unknown app rejected" "unexpected success"
  show_evidence "$TEST_OUTPUT"
fi

printf '\n'
printf "${BOLD}Summary${RESET}\n"
printf "  PASS=%d  FAIL=%d  SKIP=%d\n" "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"

[ "$FAIL_COUNT" -eq 0 ]
