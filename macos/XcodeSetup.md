# Xcode Setup

## Goal

Package OpenScope so that:

- `OpenScope.app` is signed by EZBLOCK
- `openscoped` is shipped inside the app bundle
- `openscope` remains a CLI wrapper installed onto `PATH`
- macOS Automation approval can attach to the signed OpenScope runtime

## Recommended App Bundle Layout

```text
OpenScope.app
  Contents/
    Info.plist
    MacOS/
      OpenScope
    Resources/
      bin/
        openscoped
        openscope
      launchd/
        com.ezblock.openscope.openscoped.plist
      bundled/
        apps/
        scripts/
```

## Xcode Project Setup

Create a macOS App project with:

- Product Name: `OpenScope`
- Bundle Identifier: `com.ezblock.openscope`
- Interface: no special UI required
- Lifecycle: app lifecycle can stay minimal
- Background-only behavior via `LSBackgroundOnly=true`

Use [OpenScope-Info.plist](OpenScope-Info.plist) as the starting point.

For a minimal app entrypoint, use the files in:

- [macos/AppStub/OpenScopeApp.swift](AppStub/OpenScopeApp.swift)
- [macos/AppStub/AppDelegate.swift](AppStub/AppDelegate.swift)

These provide a no-UI background app shell suitable for the first signed packaging pass.

## Binary Inputs

Build the Go binaries outside Xcode and copy them into the bundle during a build phase:

- `openscope`
- `openscoped`

Recommended destination:

```text
$(TARGET_BUILD_DIR)/$(UNLOCALIZED_RESOURCES_FOLDER_PATH)/bin/
```

## Recommended Xcode Build Phase

Add a Run Script phase after the app target is built that:

1. builds the Go binaries
2. copies `openscope` and `openscoped` into `Contents/Resources/bin`
3. copies the launch agent plist into `Contents/Resources/launchd`
4. copies bundled YAML/script resources if you decide not to rely only on Go embed

Example shape:

```bash
set -euo pipefail

ROOT="$SRCROOT/.."
BIN_DIR="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/bin"
LAUNCHD_DIR="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/launchd"

mkdir -p "$BIN_DIR" "$LAUNCHD_DIR"

cd "$ROOT"
go build -o "$BIN_DIR/openscope" ./cmd/openscope
go build -o "$BIN_DIR/openscoped" ./cmd/openscoped

cp "$ROOT/macos/LaunchAgent/com.ezblock.openscope.openscoped.plist" "$LAUNCHD_DIR/"
```

If you prefer, `openscope` can instead be installed by the `.pkg` outside the app bundle. That is likely the better long-term install story for CLI usability.

## Signing Guidance

In Xcode, attach:

- the EZBLOCK team
- automatic signing or explicit signing configuration
- hardened runtime if you plan to notarize

The specific signing identity is the part you will fill in from Xcode.

## LaunchAgent Installation

The app bundle should include the LaunchAgent plist, but installation should copy it to:

```text
~/Library/LaunchAgents/com.ezblock.openscope.openscoped.plist
```

Then load it:

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.ezblock.openscope.openscoped.plist
launchctl kickstart -k gui/$(id -u)/com.ezblock.openscope.openscoped
```

That install step is usually better handled by the installer package rather than by first app launch.

## Open Questions For Final Packaging

1. Whether `openscoped` should live in `Contents/Resources/bin` or `Contents/Library/LoginItems`
2. Whether the app target should own the broker process directly or only package and manage it
3. Whether `openscope` should be copied to `/usr/local/bin` or `/opt/homebrew/bin` by installer logic
4. Whether we want a minimal settings/troubleshooting UI later

## Recommended First Xcode Pass

For the first Xcode setup:

1. create the background-only app target
2. use the provided app plist
3. add the Go build/copy phase
4. include `openscoped` in app resources
5. attach EZBLOCK signing
6. do not worry about UI yet

That is enough to give us the signed app identity needed for the next phase.
