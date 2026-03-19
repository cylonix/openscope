# AgentScope Revised Implementation Spec

## Summary

AgentScope is a local application access broker for AI agents.

The correct macOS runtime shape for AgentScope is:

- `ascope`: CLI wrapper invoked by an AI agent or the user
- `ascoped`: signed local broker daemon with stable app identity
- local IPC between `ascope` and `ascoped`
- policy enforcement and audit logging in `ascoped`
- Apple app automation performed by `ascoped`

The first protected app is Apple Notes.

The first automation backend should preserve the YAML-driven action model while executing AppleScript in-process from the signed broker, not by spawning `/usr/bin/osascript`.

## Product Shape

The user mental model remains:

```text
original app action
-> protected by adding "ascope <app>" in front
-> AgentScope authorizes, audits, executes, and returns output
```

Example:

```bash
ascope notes read_note --agent summarizer --folder Work --note "Weekly Notes"
```

Actual execution flow:

1. AI agent invokes `ascope`
2. `ascope` sends request to local `ascoped` over Unix socket IPC
3. `ascoped` loads enabled app definition and policy
4. `ascoped` validates action and parameters from YAML
5. `ascoped` evaluates policy
6. `ascoped` executes AppleScript in-process if authorized
7. `ascoped` writes audit event
8. `ascoped` returns normalized response to `ascope`
9. `ascope` prints stdout/stderr for AI agent

## Why `ascoped` Is Core

`ascoped` is not only an architectural convenience.

It is the stable signed app identity that should hold macOS Automation approval for controlling Apple Notes.

That is how AgentScope can support the intended experience:

- AI agent approves use of `ascope`
- macOS approves `ascoped` automating Notes
- policy is enforced without repeated per-invocation user prompts

## Goals

- Persistent semantic permissions for protected app access
- No repetitive per-invocation app-automation prompts after approval is granted
- User-extensible app/action definitions via YAML
- Stable CLI contract for AI agent
- Clear audit trail of allow/deny decisions

## Non-Goals For Initial Implementation

- No shell executor
- No dynamic Go plugins
- No remote policy service
- No GUI-first workflow
- No assumption that Homebrew is installed

## CLI And Daemon Design

### Binaries

- `ascope`: CLI client
- `ascoped`: local broker daemon

### Top-level Commands

```bash
ascope agent ...
ascope app ...
ascope policy ...
ascope doctor
ascope status
ascope <app> <action> [flags]
```

Protected actions are always invoked through:

```bash
ascope <app> <action> --agent <agent_id> [action flags]
```

### Administrative Commands

```bash
ascope agent register <agent_id>
ascope agent list

ascope app list
ascope app show <app>
ascope app enable <app>
ascope app disable <app>
ascope app validate [--file <path>]

ascope policy show --agent <agent_id>
ascope policy list
ascope policy validate

ascope status
ascope doctor
```

## IPC Design

### Transport

Use a Unix domain socket for local IPC between `ascope` and `ascoped`.

Example path:

```text
~/.agentscope/run/ascoped.sock
```

### IPC Responsibilities

`ascope`:

- parse CLI command
- package request
- send request to daemon
- print response

`ascoped`:

- authenticate or identify caller as needed in future phases
- validate request
- load app definitions and enabled state
- load agents and policies
- evaluate authorization
- execute app action
- emit audit event
- return normalized response

### Request Shape

Initial IPC payload can be JSON:

```json
{
  "app": "notes",
  "action": "read_note",
  "agent": "summarizer",
  "params": {
    "folder": "Work",
    "note": "Weekly Notes"
  },
  "mode": "json"
}
```

### Response Shape

```json
{
  "ok": true,
  "app": "notes",
  "action": "read_note",
  "agent": "summarizer",
  "data": {
    "folder": "Work",
    "title": "Weekly Notes",
    "body": "..."
  }
}
```

## Output Contract

### Transport Semantics

AgentScope behaves like a process-oriented broker:

- `stdout`: machine-readable response data
- `stderr`: diagnostics and error text
- exit code: result class

### Default Output Format

Default output is JSON.

### Optional Raw/Text Mode

Some actions may expose a text-only mode for agent workflows that want direct text for summarization.

Example:

```bash
ascope notes read_note --agent research_assistant --folder Work --note "Sprint Plan" --body-only
```

Response:

- `stdout`: note body text only
- `stderr`: error text only

### Exit Codes

```text
0 success
2 invalid command or invalid parameters
3 denied by policy
4 target not found
5 executor or automation failure
6 configuration or manifest error
7 daemon unavailable or IPC failure
```

## App Definition Model

### Design Principles

- App behavior is defined by YAML, not hardcoded command logic
- Each app exposes named actions
- Each action declares parameters, output mode, and execution details
- Policy evaluation uses app and action metadata from YAML
- YAML should remain user-extensible even though execution happens in the signed daemon

### App Definition Locations

Bundled app definitions:

- embedded in the signed product

User app definitions:

- `~/.agentscope/apps.d/*.yaml`

Enabled state:

- explicit enable step required for user-defined apps

### App Definition Example

```yaml
version: 1
app:
  name: notes
  display_name: Apple Notes
  executor: applescript
  description: Protected access to Apple Notes

actions:
  list_folders:
    description: List all note folders
    parameters: []
    output:
      mode: json
      schema: folders
    script: notes/list_folders.applescript

  list_notes:
    description: List notes in a folder
    parameters:
      - name: folder
        type: string
        required: true
        policy_key: folder
    output:
      mode: json
      schema: notes
    script: notes/list_notes.applescript

  read_note:
    description: Read a note by title
    parameters:
      - name: folder
        type: string
        required: true
        policy_key: folder
      - name: note
        type: string
        required: true
        policy_key: note
    output:
      mode: json
      schema: note
      raw_modes:
        - body-only
    script: notes/read_note.applescript
```

## Automation Execution Model

### Initial Execution Backend

The initial backend remains `applescript`, but the execution path changes:

- do not spawn `/usr/bin/osascript` as the core production path
- execute AppleScript in-process from the signed daemon
- let macOS Automation approval attach to `ascoped`

### Why Keep AppleScript

AppleScript keeps the system user-extensible:

- YAML can still point to script content or script resources
- new protected apps can be added without shipping a new Go binary
- Notes is just the first bundled integration

### Why Avoid `/usr/bin/osascript`

The goal is not only to run scripts.

The goal is for the sender of Apple Events to have a stable signed app identity so that macOS approval can be granted to AgentScope once and then reused.

### Future Backend Option

Some built-in apps may later use lower-level Apple Event APIs directly.

That can be added as another executor type in YAML, for example:

```yaml
executor: appleevents
```

But the first implementation should preserve the AppleScript-driven extensibility model.

## Parameter Passing

Because execution happens inside the daemon, parameters should not be passed as arbitrary script fragments.

Rules:

- parameters must be declared in YAML
- only declared parameters may be passed
- parameter binding must be escaped safely
- scripts should follow a stable wrapper convention for inputs and outputs

Possible implementation approaches:

- script template rendering with strict escaping
- named handler convention
- serialized input payload convention

The exact mechanism can be finalized during implementation, but it must not allow arbitrary code injection through CLI flags.

## Policy Model

### Policy Design Principles

- Policies authorize `agent + app + action`
- Additional constraints are data-driven from action parameter metadata
- Policy matching depends on YAML-declared parameter mappings, not hardcoded app-specific code

### Policy Storage

Initial storage:

- `~/.agentscope/policies.yaml`

Audit log:

- `~/.agentscope/audit.jsonl`

Agent registry:

- `~/.agentscope/agents.yaml`

Enabled apps state:

- `~/.agentscope/state/enabled_apps.yaml`

### Policy Example

```yaml
version: 1
rules:
  - effect: allow
    agent: summarizer
    app: notes
    action: list_notes
    constraints:
      folder: Work

  - effect: allow
    agent: summarizer
    app: notes
    action: read_note
    constraints:
      folder: Work

  - effect: deny
    agent: summarizer
    app: notes
    action: read_note
    constraints:
      folder: Work
      tag: private
```

### Matching Semantics

1. request must target a known enabled app and action
2. agent must be registered
3. matching deny rules override allow rules
4. missing allow results in deny by default

## Audit Model

### Audit Storage

- `~/.agentscope/audit.jsonl`

### Audit Event Fields

- timestamp
- agent
- app
- action
- parameters used for evaluation
- decision
- reason
- execution result class

## Config Layout

```text
~/.agentscope/
  agents.yaml
  policies.yaml
  audit.jsonl
  apps.d/
  state/
    enabled_apps.yaml
  run/
    ascoped.sock
```

Bundled manifests and AppleScript resources are embedded in the signed product.

## Security Rules

- user-defined apps are not active until explicitly enabled
- only declared actions may be invoked
- only declared parameters may be passed
- deny by default
- audit every allow and deny decision
- macOS automation permission should attach to the signed daemon identity

## Suggested Go Structure

```text
cmd/ascope
cmd/ascoped
cli
daemon
ipc
agent
appdef
policy
executor
executor/applescript
audit
output
config
status
doctor
resources
```

## Milestones

### Milestone 1: Core Bootstrap

- initialize Go module
- add both binaries: `ascope` and `ascoped`
- add config path discovery
- add embedded resources support

### Milestone 2: Manifests And State

- define YAML schema for apps
- load bundled and user manifests
- implement enabled app state
- implement agent registry

### Milestone 3: Policy Engine

- define YAML schema for policies
- implement validation
- implement deny-overrides-allow evaluation
- implement audit logging

### Milestone 4: IPC

- create Unix socket server in `ascoped`
- implement request and response types
- implement CLI client in `ascope`
- return daemon-unavailable errors cleanly

### Milestone 5: In-Process AppleScript Execution

- load script resources in daemon
- bind parameters safely
- execute AppleScript in-process
- normalize results to JSON or text

### Milestone 6: Protected Notes Flow

- bundle Apple Notes app definition
- bundle Notes scripts
- support `list_folders`, `list_notes`, `read_note`
- verify policy-enforced end-to-end flow

### Milestone 7: Diagnostics And Packaging

- implement `status`
- implement `doctor`
- prepare signed macOS packaging for daemon + CLI
- document Automation approval and recovery steps

## Enterprise / Later Phase

Possible future areas:

- managed policy distribution
- centralized audit collection
- fleet deployment
- richer observability
- optional direct Apple Events executor for built-in integrations
