# OpenScope plugin for Claude Code

Govern Claude Code with the [OpenScope](https://open-scope.org) action broker in
one install. The plugin bundles the two pieces that *teach and enforce*:

| Component | What it does |
|---|---|
| **`openscope` skill** (`skills/openscope/SKILL.md`) | Teaches the agent one rule: for privileged or production access, route through `openscope --agent <id>`, and run `openscope capabilities` to discover the live, policy-driven action surface before calling. It does **not** hardcode the action list (that drifts when policy changes). |
| **Guard hook** (`hooks/hooks.json` → `scripts/openscope-guard.sh`) | A `PreToolUse` net. Denies raw `ssh`/`scp`/`sftp`/`rsync` to governed hosts, raw `sudo`, and direct `Write`/`Edit` of broker config under `~/.openscope` or the admin dir, telling the agent which `openscope` action to use instead. |

The skill teaches, the broker is the authority, the hook is the net.

## Install

```
/plugin marketplace add cylonix/openscope
/plugin install openscope@openscope
```

(The marketplace and the plugin are both named `openscope` — the first token is
the plugin, the second is the marketplace.) The skill auto-loads and the guard
hook registers itself; **no manual hook wiring or `CLAUDE.md` snippet is needed.**

## One manual step the plugin cannot do for you

Claude Code **plugins cannot grant permissions** — only the user's own settings
can. So that the agent isn't prompted to approve every brokered call, add this
allow rule to `~/.claude/settings.json` (user level) or `.claude/settings.json`
(project level):

```json
{
  "permissions": {
    "allow": ["Bash(openscope:*)"]
  }
}
```

## Runtime prerequisites (the broker itself)

The plugin is the *agent-side* integration. It assumes the OpenScope broker is
installed and configured on the machine:

1. **Install OpenScope** (the signed `OpenScope.app` / PKG providing the
   `openscope` CLI + `openscoped` daemon).
2. **Register the agent identity** (no sudo):
   ```bash
   openscope agent register claude-code
   ```
   The default agent id is `claude-code`; override with the `OPENSCOPE_AGENT_ID`
   environment variable (the guard hook reads it too).
3. **List the governed hosts** the hook should protect — one substring per line
   (raw `ssh` to anything matching is denied and redirected to the broker):
   ```bash
   printf '%s\n' prod.example.com 203.0.113.7 > ~/.openscope/governed_hosts.txt
   ```
   Raw `ssh` to *ungoverned* lab hosts (e.g. `10.0.0.x`, adb devices) is left
   untouched.
4. **As admin, define what the agent may reach** — see the full guide at
   [/docs/coding-agents](https://open-scope.org/docs/coding-agents):
   `sudo openscope ssh targets add ...`, `sudo openscope system commands ...`,
   `sudo openscope policy allow --agent claude-code ...`.

## Verifying

After install, in a fresh session:

- Ask the agent to read a file on a governed host. It should reach for
  `openscope ssh read_file --agent claude-code --target <alias> --path <abs>`
  rather than raw `ssh` — and a raw `ssh prod.example.com ...` attempt should be
  denied by the hook with a redirect message.
- `openscope capabilities --agent claude-code` prints the current allowed
  actions with ready-to-run command forms.

## Relationship to `docs/examples/claude-code/`

The loose example files in `docs/examples/claude-code/` (guard hook, settings
fragment, `CLAUDE.md` snippet, proposal templates) remain the reference for a
**manual** setup and for non-Claude agents. This plugin packages the skill +
hook so the Claude Code integration is a single `/plugin install`; only the
permission allow rule above stays manual (a plugin limitation, not a choice).
