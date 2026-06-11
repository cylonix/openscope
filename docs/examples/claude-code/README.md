# Claude Code + OpenScope

Working files for governing Claude Code with a locally installed OpenScope
broker. The full guide lives at
[/docs/coding-agents](https://open-scope.org/docs/coding-agents) (source:
`web/public/docs/coding-agents.md`).

| File | Purpose |
|---|---|
| `openscope-guard.sh` | `PreToolUse` hook — denies raw `ssh`/`scp`/`rsync` to governed hosts, raw `sudo`, and direct edits of broker config, telling the agent which `openscope` action to use instead |
| `settings-fragment.json` | The `hooks` + `permissions` entries to merge into `~/.claude/settings.json` |
| `CLAUDE.md-snippet.md` | Instructions block to append to `~/.claude/CLAUDE.md` so the agent reaches for the broker first |
| `setup.proposal.yaml` | A typed privilege **proposal** — what an agent drafts instead of a `sudo bash` script |
| `setup.plan.txt` | The real `openscope plan` output (emoji-coded findings + bounds verdict) |
| `setup.plan.html` | The same review as a styled HTML report (`openscope plan --html`) |
| `bounds.yaml` | The root-owned envelope `apply` can never exceed — install to the admin dir, edit as root to widen |

## Reviewing an agent-drafted setup

Instead of running a `sudo bash setup.sh` the agent wrote, have it draft a
proposal and let the broker review it:

```bash
openscope plan  --file setup.proposal.yaml                 # read-only, no sudo
openscope plan  --file setup.proposal.yaml --html          # HTML report, opens in browser
sudo openscope apply --file setup.proposal.yaml --expect-hash <sha>
```

`plan` exits 3 when a bounds rule blocks (good for CI gating); `--html [path]`
writes a styled report and launches the browser (`--no-open` to skip, `--json`
for machine output); `apply` refuses on any block and requires you to type each
high-risk resource to confirm. See `setup.plan.txt` / `setup.plan.html` for what
the review looks like on the example proposal.

Quick install:

```bash
# 1. Register the agent identity (no sudo)
openscope agent register claude-code

# 2. Install the hook
install -m 0755 openscope-guard.sh ~/.claude/hooks/openscope-guard.sh

# 3. List the hosts the hook should govern (substring match)
printf '%s\n' prod.example.com 203.0.113.7 > ~/.openscope/governed_hosts.txt

# 4. Merge settings-fragment.json into ~/.claude/settings.json
#    (hooks.PreToolUse entry + "Bash(openscope:*)" allow rule)

# 5. Append the CLAUDE.md snippet
cat CLAUDE.md-snippet.md >> ~/.claude/CLAUDE.md
```

Then, as admin, define what the agent may reach (see the guide):
`sudo openscope ssh targets add ...`, `sudo openscope system commands ...`,
`sudo openscope policy allow --agent claude-code ...`.
