# Snippet for ~/.claude/CLAUDE.md

Append the short section below to your user-level `~/.claude/CLAUDE.md` (or a
project `CLAUDE.md`). Keep it minimal: it only has to point the agent at the
broker. The exact actions and their command forms are **not** listed here on
purpose, that list drifts when policy changes; the `openscope` skill teaches the
agent to discover the live surface with `openscope capabilities` instead.

> Note: if you installed the OpenScope Claude Code **plugin** (skill + guard hook
> + permission as one unit), you don't need this snippet at all, the skill it
> ships already carries this instruction.

---

## OpenScope Action Broker (all projects)

This machine routes privileged operations (SSH to governed/production hosts,
`sudo` / local system changes, brokered macOS apps) through the OpenScope action
broker. Never run those raw. Use the `openscope` CLI with `--agent claude-code`,
and run `openscope capabilities --agent claude-code` first to discover the
currently allowed actions and their exact command form. Exit code 3 means denied
by policy: report it and stop, never work around it or switch agent labels.
