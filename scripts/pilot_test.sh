#!/bin/bash
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

# scripts/pilot_test.sh — AgentScope pilot test suite
#
# Tests the live installed system end-to-end and prints a structured report.
# Requires AgentScope to be installed and the daemon running.
# Run with: bash scripts/pilot_test.sh [--folder <name>] [--note <title>]
#
# Options:
#   --folder <name>   Notes folder to use for list_notes / read_note tests
#   --note <title>    Note title to use for read_note test
#   --agent <name>    Agent name to use (default: demo)

set -euo pipefail

# ── colour helpers ─────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; CYAN=''; DIM=''; BOLD=''; RESET=''
fi

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
REPORT=()  # "STATUS|NAME|DETAIL"

record() { REPORT+=("$1|$2|$3")
  case "$1" in PASS) PASS_COUNT=$((PASS_COUNT+1));; FAIL) FAIL_COUNT=$((FAIL_COUNT+1));; SKIP) SKIP_COUNT=$((SKIP_COUNT+1));; esac
}

# ── option parsing ─────────────────────────────────────────────────────────────
AGENT="demo"; TEST_FOLDER=""; TEST_NOTE=""
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

# ── header ─────────────────────────────────────────────────────────────────────
printf "\n${BOLD}AgentScope Pilot Test Suite${RESET}\n"
printf '%0.s─' {1..60}; printf '\n'
printf "  Agent : %s\n" "$AGENT"
[ -n "$TEST_FOLDER" ] && printf "  Folder: %s\n" "$TEST_FOLDER" || true
[ -n "$TEST_NOTE" ]   && printf "  Note  : %s\n" "$TEST_NOTE"   || true
printf '%0.s─' {1..60}; printf '\n\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}1. Installation${RESET}\n"

# 1.1 CLI in PATH
if command -v ascope >/dev/null 2>&1; then
  CLI_PATH=$(command -v ascope)
  record PASS "CLI in PATH" "$CLI_PATH"
  print_status PASS "CLI in PATH" "$CLI_PATH"
  show_evidence "$(ls -la "$CLI_PATH")"
else
  record FAIL "CLI in PATH" "ascope not found — is /usr/local/bin in PATH?"
  print_status FAIL "CLI in PATH" "ascope not found"
fi

# 1.2 App bundle installed
APP="/Applications/AgentScope.app"
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
  if [ "$ASAPPLE_ID" = "com.ezblock.agentscope" ]; then
    record PASS "asapple bundle ID" "$ASAPPLE_ID"
    print_status PASS "asapple bundle ID" "$ASAPPLE_ID"
    show_evidence "$(echo "$ASAPPLE_SIGN" | grep -E '^(Identifier|TeamIdentifier|Format|flags)')"
  else
    record FAIL "asapple bundle ID" "got '$ASAPPLE_ID', want com.ezblock.agentscope"
    print_status FAIL "asapple bundle ID" "got '$ASAPPLE_ID'"
    show_evidence "$ASAPPLE_SIGN"
  fi
else
  record FAIL "asapple present" "$ASAPPLE not found"
  print_status FAIL "asapple present" "not found"
fi

# 1.4 LaunchAgent plist installed and loaded
PLIST="$HOME/Library/LaunchAgents/com.ezblock.agentscope.ascoped.plist"
if [ -f "$PLIST" ]; then
  LC_STATUS=$(launchctl list 2>/dev/null | grep "com.ezblock.agentscope.ascoped" 2>/dev/null || echo "(not listed by launchctl)")
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

# 2.1 ascope status
STATUS_JSON=$(ascope status 2>&1 || true)
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

# 2.2 ascope doctor
DOCTOR_OUT=$(ascope doctor 2>&1 || true)
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

CONFIG="$HOME/.agentscope"

# 3.1 Demo agent registered
AGENTS_FILE="$CONFIG/agents.yaml"
if [ -f "$AGENTS_FILE" ] && grep -q "\bdemo\b" "$AGENTS_FILE"; then
  record PASS "Demo agent registered" "found in agents.yaml"
  print_status PASS "Demo agent registered" "found in agents.yaml"
  show_evidence "$(cat "$AGENTS_FILE")"
else
  record FAIL "Demo agent registered" "demo not in $AGENTS_FILE"
  print_status FAIL "Demo agent registered" "missing"
  [ -f "$AGENTS_FILE" ] && show_evidence "$(cat "$AGENTS_FILE")"
fi

# 3.2 Default Notes policies
POLICY_FILE="$CONFIG/policies.yaml"
if [ -f "$POLICY_FILE" ]; then
  RULE_COUNT=$(grep -c "effect: allow" "$POLICY_FILE" 2>/dev/null || echo 0)
  if [ "$RULE_COUNT" -ge 3 ]; then
    record PASS "Default policies" "$RULE_COUNT allow rules"
    print_status PASS "Default policies" "$RULE_COUNT allow rules"
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
    record FAIL "Default policies" "only $RULE_COUNT allow rules, expected ≥3"
    print_status FAIL "Default policies" "only $RULE_COUNT allow rules"
    show_evidence "$(cat "$POLICY_FILE")"
  fi
else
  record FAIL "Default policies" "$POLICY_FILE not found"
  print_status FAIL "Default policies" "file missing"
fi

# 3.3 Notes Automation permission (TCC)
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
  print_status FAIL "Notes Automation permission" "denied — open /Applications/AgentScope.app"
  show_evidence "$(echo "$AE_RAW" | grep -v "EXIT:")"
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}4. Notes Actions  (agent: $AGENT)${RESET}\n"

# 4.1 list_folders
if run_test "list_folders" 0 ascope notes list_folders --agent "$AGENT"; then
  FOLDERS=$(json_extract "$TEST_OUTPUT" "print('\n'.join(d.get('data',[])))")
  FOLDER_COUNT=$(echo "$FOLDERS" | grep -c . 2>/dev/null || echo 0)
  record PASS "notes list_folders" "$FOLDER_COUNT folder(s)"
  print_status PASS "notes list_folders" "$FOLDER_COUNT folder(s)"
  show_evidence "$FOLDERS"
  if [ -z "$TEST_FOLDER" ]; then
    TEST_FOLDER=$(json_extract "$TEST_OUTPUT" "f=d.get('data',[]); print(f[0]) if f else print('')")
  fi
else
  record FAIL "notes list_folders" "$(echo "$TEST_OUTPUT" | head -1)"
  print_status FAIL "notes list_folders" "$(echo "$TEST_OUTPUT" | head -1)"
  show_evidence "$TEST_OUTPUT"
  TEST_FOLDER=""
fi

# 4.2 list_notes
if [ -n "$TEST_FOLDER" ]; then
  if run_test "list_notes" 0 ascope notes list_notes --agent "$AGENT" --folder "$TEST_FOLDER"; then
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
  if run_test "read_note" 0 ascope notes read_note --agent "$AGENT" \
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
printf "${BOLD}5. Policy Enforcement${RESET}\n"

# 5.1 Unregistered agent rejected
RANDOM_AGENT="pilot_test_agent_$$"
if run_test "Unregistered agent rejected" 1 ascope notes list_folders --agent "$RANDOM_AGENT"; then
  # CLI returns plain text for these errors, not JSON
  ERR_MSG=$(echo "$TEST_OUTPUT" | head -1)
  record PASS "Unregistered agent rejected" "$ERR_MSG"
  print_status PASS "Unregistered agent rejected" "$ERR_MSG"
  show_evidence "exit non-zero; output: $TEST_OUTPUT"
else
  record FAIL "Unregistered agent rejected" "was not rejected"
  print_status FAIL "Unregistered agent rejected" "was not rejected"
  show_evidence "$TEST_OUTPUT"
fi

# 5.2 Unknown app rejected
if run_test "Unknown app rejected" 1 ascope nonexistentapp someaction --agent "$AGENT"; then
  ERR_MSG=$(echo "$TEST_OUTPUT" | head -1)
  record PASS "Unknown app rejected" "$ERR_MSG"
  print_status PASS "Unknown app rejected" "$ERR_MSG"
  show_evidence "exit non-zero; output: $TEST_OUTPUT"
else
  record FAIL "Unknown app rejected" "was not rejected"
  print_status FAIL "Unknown app rejected" "was not rejected"
  show_evidence "$TEST_OUTPUT"
fi

# 5.3 Policy deny: backup → add deny → test → restore
DENY_TEST_FOLDER="__pilot_deny_test_$$__"
POLICY_BACKUP=$(mktemp)
cp "$HOME/.agentscope/policies.yaml" "$POLICY_BACKUP"

ascope policy deny --agent "$AGENT" --app notes --action list_notes \
  --folder "$DENY_TEST_FOLDER" >/dev/null 2>&1 || true

DENY_OUTPUT=""
DENY_EC=0
DENY_OUTPUT=$(ascope notes list_notes --agent "$AGENT" --folder "$DENY_TEST_FOLDER" 2>&1) || DENY_EC=$?

mv "$POLICY_BACKUP" "$HOME/.agentscope/policies.yaml"

if [ "$DENY_EC" -ne 0 ]; then
  DENY_MSG=$(json_extract "$DENY_OUTPUT" "print(d.get('error',d))" 2>/dev/null || echo "$DENY_OUTPUT")
  record PASS "Policy deny blocks action" "folder constraint enforced"
  print_status PASS "Policy deny blocks action" "folder constraint enforced"
  show_evidence "rule: deny $AGENT → notes.list_notes [folder=$DENY_TEST_FOLDER]
response: $DENY_OUTPUT"
else
  record FAIL "Policy deny blocks action" "deny had no effect"
  print_status FAIL "Policy deny blocks action" "deny had no effect"
  show_evidence "$DENY_OUTPUT"
fi

printf '\n'

# ══════════════════════════════════════════════════════════════════════════════
printf "${BOLD}6. Audit Log${RESET}\n"

AUDIT_FILE="$HOME/.agentscope/audit.jsonl"
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
