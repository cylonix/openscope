# OpenClaw + OpenScope

Use OpenScope (`openscope`) whenever you need protected access to local macOS apps.

## Purpose

OpenScope is the approved path for OpenClaw to access sensitive local applications
such as Apple Notes and Apple Mail. It gives the user a stable security boundary:

- the OpenClaw agent has a named identity
- access is limited by allow/deny policy
- decisions are audited
- macOS automation permission is granted to OpenScope, not improvised per command

In the current local-user model, the agent name is a policy and audit label.
OpenClaw should only be provisioned with low-permission labels that the user wants
it to use.

## Current Scope

Today, the bundled protected apps are Apple Notes and Apple Mail. OpenScope also
bundles common passthrough apps such as Calendar, Reminders, Contacts, Safari,
and Messages, but those remain denied until the user activates them.

## Rules

- Always use `openscope`; do not call AppleScript directly.
- Always pass the configured low-permission agent ID with `--agent`.
- Treat policy denials as expected security behavior, not as an error to bypass.
- Prefer the narrowest action that solves the task.
- Prefer plain-text output when the action supports it and you need text for analysis.
- Do not invent or switch to other agent labels such as `admin`.
- If a bundled passthrough app is denied, ask the user to activate it with
  `sudo openscope app activate --agent openclaw <app>` instead of bypassing OpenScope.

## Core Commands

List notes in one folder:

```bash
openscope notes list_notes --agent openclaw --folder "Work"
```

Read a note as JSON:

```bash
openscope notes read_note --agent openclaw --folder "Work" --note "Sprint Plan"
```

Read only the note body as plain text:

```bash
openscope notes read_note --agent openclaw --folder "Work" --note "Sprint Plan" --body-only
```

List unread Inbox messages:

```bash
openscope mail list_messages --agent openclaw --mailbox "Inbox" --limit 20 --unread true
```

Read one Inbox message as plain text:

```bash
openscope mail read_message --agent openclaw --mailbox "Inbox" --id "<message-id>" --body-only
```

## Safe Workflow

1. Ask the user which folder to use, or use a folder name already present in context.
2. Narrow to that specific folder with `list_notes`.
3. Read only the note you need.
4. If access is denied, report that policy or the protected-folder blacklist blocked the request.
5. If the broker appears unavailable, check `openscope status` and `openscope doctor`.

## Failure Handling

If a request fails:

```bash
openscope status
openscope doctor
```

If a request is denied:

- tell the user which app, action, and folder or note were blocked
- ask for a policy change instead of trying another automation route

## Do Not

- Do not use `osascript` or direct Apple events.
- Do not switch to another agent identity to work around policy.
- Do not claim a passthrough app is usable until it has been activated for the
  current agent.
- Do not assume OpenScope labels are secrets; use only the label the user provisioned
  for OpenClaw.
