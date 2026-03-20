# OpenClaw User Guide

This guide is for a typical OpenClaw user who wants to let the agent access
important local macOS apps in a controlled way.

The short version:

- OpenClaw should not automate Notes, Calendar, or similar apps directly
- OpenClaw should call `openscope`
- OpenScope decides whether the request is allowed
- every decision is logged
- OpenClaw should only be configured with low-permission agent labels

That gives you a safer setup than letting the agent talk to local apps however it wants.

## What OpenScope Does

OpenScope is a local broker between OpenClaw and sensitive apps.

Instead of:

```text
OpenClaw -> Apple Notes directly
```

you use:

```text
OpenClaw -> openscope -> openscoped -> protected local app
```

This adds four protections:

1. OpenClaw uses a named agent identity such as `openclaw`
2. You choose exactly which actions that agent may perform
3. Requests are audited in `~/.openscope/audit.jsonl`
4. macOS Automation approval is attached to OpenScope's signed broker

For local setups, the agent name is best understood as a policy label, not as a
secret API key.

## What Works Today

Today, the bundled protected app in this repository is Apple Notes.

That means a novice user can use OpenScope right now to secure OpenClaw's access
to Notes.

For apps such as Calendar and other critical local applications, the same security
model applies, but they need to exist as bundled or user-defined OpenScope apps
before OpenClaw can use them through `openscope`.

## Install And Provision OpenScope

Before OpenClaw can use OpenScope, OpenScope must be installed on the Mac.

### Where To Get It

Download the latest installer package from the project's latest GitHub release:

[cylonix/openscope latest release](https://github.com/cylonix/openscope/releases/latest)

Open the release page and download the packaged `.pkg` asset for your version.

You can also browse all releases here:

[cylonix/openscope releases](https://github.com/cylonix/openscope/releases)

### Install It

Open `OpenScope.pkg` and complete the installer.

The installer is expected to:

- copy `OpenScope.app` into `/Applications`
- install the `openscope` CLI
- register and start the `openscoped` background service
- create the initial `~/.openscope/` configuration directory

### Verify The Install

After installation, open Terminal and run:

```bash
openscope status
openscope doctor
```

You want `openscope status` to show that the daemon is running.

### Provision OpenClaw

Once OpenScope is installed, register a dedicated low-permission label for OpenClaw:

Use one dedicated agent identity for OpenClaw:

```bash
openscope agent register openclaw
```

Then grant only the permissions OpenClaw actually needs.

The important practical rule is:

- only register and configure labels that you want OpenClaw to use
- do not create a broader-permission OpenClaw label unless you truly need it
- do not reuse a manual or admin label for OpenClaw

For example, if OpenClaw only needs your `Work` notes:

```bash
openscope policy allow --agent openclaw --app notes --action list_folders
openscope policy allow --agent openclaw --app notes --action list_notes --folder Work
openscope policy allow --agent openclaw --app notes --action read_note --folder Work
openscope policy deny --agent openclaw --app notes --action list_notes --folder Private
openscope policy deny --agent openclaw --app notes --action read_note --folder Private
```

This is much better than giving the agent broad unrestricted access.

For most users, the safest pattern is to have one OpenClaw label with narrow
permissions and no separate high-permission OpenClaw label at all.

### What OpenClaw May Do During Setup

OpenClaw may help the user walk through installation and provisioning, but it should
not silently install packages or widen local app permissions without explicit user
approval.

Good setup behavior:

- tell the user where to download OpenScope
- ask before running install or policy commands
- verify setup with `openscope status` and `openscope doctor`

Risky setup behavior:

- downloading and installing OpenScope without clear user consent
- registering broader-permission labels than the user asked for
- configuring Notes or future apps with wider policy than necessary

## First-Time Automation Approval

The first time OpenScope accesses Notes, macOS should show an Automation prompt.
Approve it for OpenScope.

## How OpenClaw Should Use OpenScope

OpenClaw should use commands like these:

```bash
openscope notes list_folders --agent openclaw
openscope notes list_notes --agent openclaw --folder "Work"
openscope notes read_note --agent openclaw --folder "Work" --note "Sprint Plan" --body-only
```

The best novice pattern is:

1. Let OpenClaw discover folders
2. Let it list notes only inside approved folders
3. Let it read only the note it needs
4. Prefer `--body-only` when OpenClaw only needs text

## How To Think About Notes, Calendar, And Similar Apps

Use this rule of thumb:

- if the app holds sensitive personal or business data, put it behind OpenScope
- if OpenClaw needs access, give it a dedicated agent ID
- start with read-only, narrow permissions
- widen policy only when you have a real use case

For Notes, this is already available.

For Calendar and similar apps, the next step is to add or enable an OpenScope app
definition for that target, then give `openclaw` a scoped policy for that app.

## Common Safe Policy Shapes

### Safer

- allow `list_folders`
- allow `list_notes` only for `Work`
- allow `read_note` only for `Work`
- explicitly deny `Private`
- provision OpenClaw with only one low-permission label such as `openclaw`

### Riskier

- allow all folders
- reuse the `demo` agent for a production OpenClaw deployment
- let OpenClaw use raw AppleScript outside OpenScope
- create an `admin`-style label and also give OpenClaw access to it

## Operational Tips

- Use one agent ID per tool or product integration
- Keep personal and business folders separated if possible
- Review `~/.openscope/audit.jsonl` occasionally
- Use `openscope policy show --agent openclaw` to inspect active rules

## Troubleshooting

If OpenClaw says it cannot access a protected app:

```bash
openscope status
openscope doctor
openscope policy show --agent openclaw
```

If access is denied, that usually means the security policy is working as intended.
Add a new allow rule only if you want that behavior.

## Recommended OpenClaw Prompting Contract

If you are configuring OpenClaw, tell it:

- use `openscope` for protected local app access
- always pass `--agent openclaw`
- never bypass OpenScope with direct automation
- if policy denies a request, ask for permission instead of working around it
- never use any agent label other than the one explicitly provisioned for OpenClaw

## Enterprise Security Model

For enterprise deployments, treat local self-registration as a convenience for
development and small self-managed setups, not as the long-term control plane.

The recommended enterprise model is:

- agent registration is centrally administered
- policy is centrally approved
- managed identities and policy are pushed to devices
- local applications such as OpenClaw do not create or register their own labels

In other words, enterprise customers should not rely on ad hoc local registration
for important access control decisions. The local device should enforce identities
and policies that were authorized elsewhere.
