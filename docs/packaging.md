# OpenScope Packaging Guide

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
   /path/to/openscope/dist/export/
   ```
   Xcode creates `dist/export/OpenScope.app`, already notarized and Gatekeeper-ready.

## Step 2 — Build the PKG

```bash
scripts/build_pkg.sh --version 0.1.0
```

The script finds `dist/export/OpenScope.app`, auto-detects the `Developer ID Installer`
signing identity from your keychain, and produces `dist/OpenScope-0.1.0.pkg`.

If the app is at a different path:

```bash
scripts/build_pkg.sh --version 0.1.0 --app /path/to/OpenScope.app
```

The script will warn and prompt if the app hasn't been accepted by Gatekeeper (not
notarized), giving you a chance to abort before producing a PKG pilots can't open.

## Client-Only Linux Release For NemoClaw / OpenShell

To build a sandbox-side client-only release, use:

```bash
scripts/build_client_release.sh --version 0.1.0 --goos linux --goarch arm64
```

This produces a tarball such as:

```text
dist/client/openscope-0.1.0-linux-arm64.tar.gz
```

The client archive contains only `openscope`. It is meant for sandboxed
NemoClaw/OpenShell environments that connect to a host or endpoint-local
`openscoped` broker over either:

- `OPENSCOPE_SOCKET`
- `OPENSCOPE_HTTP_URL`

## What the installer does

The PKG runs `scripts/pkg/preinstall` and `scripts/pkg/postinstall` as root:

1. Stops any running `openscoped` daemon (upgrade safe)
2. Copies `OpenScope.app` to `/Applications`
3. Installs `~/Library/LaunchAgents/com.ezblock.openscope.openscoped.plist`
4. Starts `openscoped` via `launchctl bootstrap` + `kickstart`
5. Creates `/usr/local/bin/openscope` symlink
6. Creates `/usr/local/bin/openscope-diag` symlink to the bundled pilot test
   script under `/usr/local/lib/openscope/pilot/`
7. Installs bundled pilot assets for installation validation, including:
   - `pilot_test.sh`
   - `nemoclaw_pilot_test.sh`
   - `run_nemoclaw_demo_container.sh`
   - `setup_nemoclaw_demo.sh`
   - prebuilt Linux `openscope` client binaries for `arm64` and `amd64`
8. Seeds `~/.openscope/agents.yaml` with an `openclaw` agent and `policies.yaml`
   with default Notes access plus Mail `Inbox`-only read access when those files
   do not already exist;
   existing user config is left untouched and can be reset intentionally with
   `openscope init --force`
9. Seeds `/Library/Application Support/OpenScope/protected_folders.yaml` with
   `private` and `hidden`
10. Seeds `/Library/Application Support/OpenScope/mail_filters.yaml` with an
   empty sender-domain allowlist

## Pilot distribution checklist

- [ ] Xcode archive + export to `dist/export/` succeeds
- [ ] `spctl --assess -v dist/export/OpenScope.app` → `accepted`
- [ ] `scripts/build_pkg.sh --version X.Y.Z` exits cleanly
- [ ] `sudo installer -pkg dist/OpenScope-X.Y.Z.pkg -target /` succeeds
- [ ] `openscope status && openscope doctor` pass
- [ ] `openscope-diag` passes on an installed system
- [ ] `openscope notes list_notes --agent openclaw --folder Work` returns notes from Apple Notes

## Xcode project setup

See `macos/XcodeSetup.md` for initial Xcode configuration. The Xcode Run Script build
phase (`Bundle Go Binaries`) builds `openscope`, `openscoped`, and `asapple` from source
during archive. No manual Go build step is needed before archiving.
