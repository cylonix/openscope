# Snippet for ~/.claude/CLAUDE.md

Append the section below to your user-level `~/.claude/CLAUDE.md` (or a
project `CLAUDE.md`) so Claude Code knows the broker exists and how to call
it. Adjust the host names to whatever you govern.

---

## OpenScope Action Broker (all projects)

This machine routes privileged operations through the OpenScope action broker.
Your agent ID is `claude-code`.

- **Production servers**: never raw `ssh`/`scp`/`rsync`. Use the scoped actions:
  - `openscope ssh check_host --agent claude-code --target <alias>`
  - `openscope ssh service_status|restart_service|tail_logs --agent claude-code --target <alias> --service <svc>` (`tail_logs` takes `--lines`, 1–500)
  - `openscope ssh read_file|list_dir --agent claude-code --target <alias> --path <abs-path>`
  - `openscope ssh host_metrics --agent claude-code --target <alias>`
  - Discover targets: `openscope ssh targets list`
- **Local privileged ops**: never raw `sudo`. Use `openscope system <action> --agent claude-code ...`:
  `manage_packages` (`--op install|uninstall|upgrade|list --manager <m> --package <p>`),
  `manage_services` (`--op start|stop|restart|status --service <s>`),
  `manage_apps` (`--op install|launch|quit|symlink|uninstall --name <App> --source <path>`),
  `manage_processes` (`--op list|kill --name <proc> --signal TERM`),
  `check_port`/`release_port` (`--port <n>`),
  `manage_files` (`--op chmod|chown --path <abs> --mode/--owner ...`),
  `build` (`--op xcodebuild --project <abs> ...`).
- Output is JSON on stdout. Exit codes: 0 ok, 2 invalid, 3 **denied by policy**,
  4 not found, 5 executor error, 6 config error, 7 daemon unreachable, 8 rate limited.
- Treat exit 3 as expected security behavior: report the denial to the user and
  ask; never work around it, never switch agent labels.
