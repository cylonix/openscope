#!/bin/bash
# OpenScope guard — Claude Code PreToolUse hook for Bash and file-edit tools.
#
# Routes governed operations through the OpenScope action broker instead of
# letting the agent run them raw:
#   1. ssh/scp/rsync/sftp to a governed (production) host  -> deny, use `openscope ssh ...`
#   2. sudo anything                                       -> deny, use `openscope system ...`
#   3. Write/Edit of broker config (~/.openscope, admin dir) -> deny
# Everything else passes through untouched (exit 0, no output).
#
# Governed hosts are substrings listed one per line in
# ~/.openscope/governed_hosts.txt (comments with #, blank lines ignored).

set -u

AGENT_ID="${OPENSCOPE_AGENT_ID:-claude-code}"

INPUT=$(cat)

deny() {
  jq -n --arg reason "$1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
}

# --- Rule 3: protect broker config from direct file edits ---------------------
file_path=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
if [ -n "$file_path" ]; then
  case "$file_path" in
    "$HOME/.openscope/audit.jsonl"|"$HOME/.openscope/reports"*) ;; # reports/audit reads are handled elsewhere; never edited via this rule's exemption
    "$HOME/.openscope/"*|"/Library/Application Support/OpenScope/"*|/etc/openscope/*)
      deny "OpenScope broker config is admin-owned. Do not edit files under ~/.openscope or the OpenScope admin dir directly — ask the user to run the appropriate 'sudo openscope ...' command (policy allow/deny, ssh targets, system commands)." ;;
  esac
  exit 0
fi

command=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
[ -z "$command" ] && exit 0

# A single, unchained openscope invocation is the sanctioned path — skip checks.
# Chained commands (;, &&, ||, |) fall through so nothing rides along.
if printf '%s' "$command" | grep -qE '^[[:space:]]*openscope[[:space:]][^;&|]*$'; then
  exit 0
fi

GOVERNED_FILE="$HOME/.openscope/governed_hosts.txt"

# --- Rule 1: remote access to governed hosts ---------------------------------
# Word-boundary match for the remote-access binaries (not ssh-keygen/ssh-add).
if printf '%s' "$command" | grep -qE '(^|[;&|[:space:]])(ssh|scp|sftp|rsync)([[:space:]]|$)'; then
  if [ -f "$GOVERNED_FILE" ]; then
    while IFS= read -r host; do
      host="${host%%#*}"
      host=$(printf '%s' "$host" | tr -d '[:space:]')
      [ -z "$host" ] && continue
      if printf '%s' "$command" | grep -qF "$host"; then
        deny "Raw SSH to governed host '$host' is brokered by OpenScope. Use the scoped actions instead (agent id: $AGENT_ID), e.g.:
  openscope ssh check_host --agent $AGENT_ID --target <alias>
  openscope ssh service_status --agent $AGENT_ID --target <alias> --service <svc>
  openscope ssh restart_service --agent $AGENT_ID --target <alias> --service <svc>
  openscope ssh tail_logs --agent $AGENT_ID --target <alias> --service <svc> --lines 200
  openscope ssh read_file --agent $AGENT_ID --target <alias> --path <abs-path>
  openscope ssh list_dir --agent $AGENT_ID --target <alias> --path <abs-path>
  openscope ssh host_metrics --agent $AGENT_ID --target <alias>
List configured targets with: openscope ssh targets list
Exit code 3 means denied by policy — report it to the user, do not work around it."
      fi
    done < "$GOVERNED_FILE"
  fi
fi

# --- Rule 2: sudo -------------------------------------------------------------
if printf '%s' "$command" | grep -qE '(^|[;&|[:space:]])sudo([[:space:]]|$)'; then
  deny "Raw sudo is brokered by OpenScope. Use the scoped system actions instead (agent id: $AGENT_ID), e.g.:
  openscope system manage_packages --agent $AGENT_ID --op install --manager brew --package <pkg>
  openscope system manage_services --agent $AGENT_ID --op restart --service <svc>
  openscope system manage_apps --agent $AGENT_ID --op install --name <App> --source <path>
  openscope system manage_processes --agent $AGENT_ID --op kill --name <proc>
  openscope system check_port --agent $AGENT_ID --port <port>
  openscope system release_port --agent $AGENT_ID --port <port>
  openscope system manage_files --agent $AGENT_ID --op chmod --path <abs-path> --mode <mode>
If no scoped action covers this, ask the user to run the command themselves.
Exit code 3 means denied by policy — report it to the user, do not work around it."
fi

# --- Rule 4: raw AWS SSM execution -------------------------------------------
# send-command / start-session are the agentic execution surface — broker them.
# SSM Parameter Store reads (aws ssm get-parameter) are not execution and pass.
# Defense-in-depth only: the real boundary is the IAM deny on the agent identity
# (see deploy/broker/iam), since this can't intercept the AWS SDK / boto3.
if printf '%s' "$command" | grep -qE '(^|[;&|[:space:]])aws([[:space:]]|$)' \
   && printf '%s' "$command" | grep -qE '[[:space:]]ssm([[:space:]]|$)' \
   && printf '%s' "$command" | grep -qE '(send-command|start-session)'; then
  deny "Raw AWS SSM execution is brokered by OpenScope. Use the scoped actions instead (agent id: $AGENT_ID), e.g.:
  openscope ssm check_host --agent $AGENT_ID --target <alias>
  openscope ssm tail_logs --agent $AGENT_ID --target <alias> --service <svc>
  openscope ssm read_file --agent $AGENT_ID --target <alias> --path <abs-path>
The broker runs SSM with its own least-privilege AWS identity; the agent's identity must be denied ssm:SendCommand/StartSession in IAM.
Exit code 3 means denied by policy — report it to the user, do not work around it."
fi

# ssh/scp/sftp/rsync tunneled to an EC2 instance id over SSM (ProxyCommand) — also brokered.
if printf '%s' "$command" | grep -qE '(^|[;&|[:space:]])(ssh|scp|sftp|rsync)([[:space:]]|$)' \
   && printf '%s' "$command" | grep -qE '(^|[@[:space:]])(i|mi)-[0-9a-f]{8,}'; then
  deny "Raw SSH/SCP to an EC2 instance id (SSM tunnel) is brokered by OpenScope. Use 'openscope ssm ...' (agent id: $AGENT_ID), e.g. openscope ssm check_host --agent $AGENT_ID --target <alias>."
fi

exit 0
