# AgentScope macOS Packaging Setup

This directory contains the macOS-side assets and configuration templates for packaging AgentScope as:

- a background-only signed macOS app bundle
- a bundled broker helper executable: `ascoped`
- a CLI wrapper binary: `ascope`
- a per-user LaunchAgent that starts `ascoped`

## Recommended Bundle IDs

- App bundle: `com.ezblock.agentscope`
- Helper executable identity: `com.ezblock.agentscope.ascoped`

If Xcode requires a helper-specific bundle identifier inside the app bundle, keep it under the same prefix.

## Runtime Shape

```text
AI agent
  -> /usr/local/bin/ascope
  -> ~/.agentscope/run/ascoped.sock
  -> ascoped (bundled helper, signed)
  -> Apple Notes automation
```

## Xcode Targets

Recommended target layout:

1. `AgentScope`
- macOS App target
- background-only
- minimal no-UI lifecycle
- owns product bundle identity

2. `ascoped`
- bundled helper executable
- launched by `launchd` via a LaunchAgent plist
- owns local socket and broker runtime

The `ascope` CLI does not need to be an Xcode app target. It can remain a Go-built CLI binary installed by packaging scripts or the installer.

## Files In This Directory

- `AgentScope-Info.plist`
  - app bundle info
- `Ascoped-Info.plist`
  - helper metadata template
- `LaunchAgent/com.ezblock.agentscope.ascoped.plist`
  - per-user launch agent template
- `XcodeSetup.md`
  - concrete setup steps in Xcode

## Important Signing Note

The point of the Xcode app/helper packaging is to give the broker a stable signed macOS identity so that macOS Automation approval can be granted to AgentScope and reused.

You will still need to attach the real EZBLOCK signing team, signing certificate, and final bundle settings in Xcode.
