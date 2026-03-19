# AgentScope Packaging Guide

## Step 1 — Archive, sign, and notarize in Xcode

> **Note:** Skip the "Validate App" button in the Organizer — that's only for App Store
> submissions. Go straight to "Distribute App" as described below.

1. **Product → Archive** — builds a release archive and opens the Organizer
2. In the Organizer, click **Distribute App**
3. Select **Direct Distribution** → click **Distribute**
   - This is the Xcode 15+ name for Developer ID signing + automatic notarization
   - ("Custom" also works but requires manually selecting the certificate type)
4. Xcode signs, uploads to Apple for notarization, then prompts to export
5. When asked where to save, choose the `dist/export/` folder in this repo:
   ```
   /path/to/ascope/dist/export/
   ```
   Xcode creates `dist/export/AgentScope.app`, already notarized and Gatekeeper-ready.

## Step 2 — Build the PKG

```bash
scripts/build_pkg.sh --version 0.1.0
```

The script finds `dist/export/AgentScope.app`, auto-detects the `Developer ID Installer`
signing identity from your keychain, and produces `dist/AgentScope-0.1.0.pkg`.

If the app is at a different path:

```bash
scripts/build_pkg.sh --version 0.1.0 --app /path/to/AgentScope.app
```

The script will warn and prompt if the app hasn't been accepted by Gatekeeper (not
notarized), giving you a chance to abort before producing a PKG pilots can't open.

## What the installer does

The PKG runs `scripts/pkg/preinstall` and `scripts/pkg/postinstall` as root:

1. Stops any running `ascoped` daemon (upgrade safe)
2. Copies `AgentScope.app` to `/Applications`
3. Installs `~/Library/LaunchAgents/com.ezblock.agentscope.ascoped.plist`
4. Starts `ascoped` via `launchctl bootstrap` + `kickstart`
5. Creates `/usr/local/bin/ascope` symlink
6. Seeds `~/.agentscope/agents.yaml` with a `demo` agent and `policies.yaml` with
   default Notes access (first install only; upgrade preserves existing config)

## Pilot distribution checklist

- [ ] Xcode archive + export to `dist/export/` succeeds
- [ ] `spctl --assess -v dist/export/AgentScope.app` → `accepted`
- [ ] `scripts/build_pkg.sh --version X.Y.Z` exits cleanly
- [ ] `sudo installer -pkg dist/AgentScope-X.Y.Z.pkg -target /` succeeds
- [ ] `ascope status && ascope doctor` pass
- [ ] `ascope notes list_folders --agent demo` returns folders from Apple Notes

## Xcode project setup

See `macos/XcodeSetup.md` for initial Xcode configuration. The Xcode Run Script build
phase (`Bundle Go Binaries`) builds `ascope`, `ascoped`, and `asapple` from source
during archive. No manual Go build step is needed before archiving.
