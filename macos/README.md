# OpenScope macOS Packaging Setup

This directory contains the macOS-side assets and configuration templates for packaging OpenScope as:

- a background-only signed macOS app bundle
- a bundled broker helper executable: `openscoped`
- a CLI wrapper binary: `openscope`
- a per-user LaunchAgent that starts `openscoped`

## Recommended Bundle IDs

- App bundle: `com.ezblock.openscope`
- Helper executable identity: `com.ezblock.openscope.openscoped`

If Xcode requires a helper-specific bundle identifier inside the app bundle, keep it under the same prefix.

## Runtime Shape

```text
AI agent
  -> /usr/local/bin/openscope
  -> ~/.openscope/run/openscoped.sock
  -> openscoped (bundled helper, signed)
  -> Apple Notes automation
```

## Xcode Targets

Recommended target layout:

1. `OpenScope`
- macOS App target
- background-only
- minimal no-UI lifecycle
- owns product bundle identity

2. `openscoped`
- bundled helper executable
- launched by `launchd` via a LaunchAgent plist
- owns local socket and broker runtime

The `openscope` CLI does not need to be an Xcode app target. It can remain a Go-built CLI binary installed by packaging scripts or the installer.

## Files In This Directory

- `OpenScope-Info.plist`
  - app bundle info
- `Ascoped-Info.plist`
  - helper metadata template
- `LaunchAgent/com.ezblock.openscope.openscoped.plist`
  - per-user launch agent template
- `XcodeSetup.md`
  - concrete setup steps in Xcode

## Important Signing Note

The point of the Xcode app/helper packaging is to give the broker a stable signed macOS identity so that macOS Automation approval can be granted to OpenScope and reused.

You will still need to attach the real EZBLOCK signing team, signing certificate, and final bundle settings in Xcode.
