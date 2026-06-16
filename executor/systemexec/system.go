// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package systemexec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
)

var (
	packagePattern = regexp.MustCompile(`^[A-Za-z0-9@_.+/-]+$`)
	servicePattern = regexp.MustCompile(`^[A-Za-z0-9@_.:-]+$`)
	processPattern = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
	modePattern    = regexp.MustCompile(`^[0-7]{3,4}$`)
	ownerPattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]+(:[A-Za-z0-9_.-]+)?$`)
	appNamePattern = regexp.MustCompile(`^[A-Za-z0-9_. -]+$`)
	buildConfigPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	validSignals = map[string]bool{
		"TERM": true, "HUP": true, "INT": true, "KILL": true,
		"USR1": true, "USR2": true, "QUIT": true,
	}

	// npm uses different subcommands than brew/pip.
	npmOps = map[string][]string{
		"install":   {"install", "-g"},
		"uninstall": {"uninstall", "-g"},
		"upgrade":   {"update", "-g"},
		"list":      {"list", "-g", "--json"},
	}
)

type CommandRunner interface {
	Run(name string, args []string) (executor.Result, error)
}

type Executor struct {
	Paths  config.Paths
	Runner CommandRunner
}

func (e Executor) Run(def appdef.Definition, actionName string, params map[string]string) (executor.Result, error) {
	cmds, err := admin.LoadSystemCommandsOrDefault(e.Paths)
	if err != nil {
		return executor.Result{}, err
	}

	payload, err := e.runAction(def, cmds, actionName, params)
	if err != nil {
		return executor.Result{}, err
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return executor.Result{}, fmt.Errorf("marshal system action output: %w", err)
	}
	return executor.Result{Stdout: string(data), ExitCode: 0}, nil
}

func (e Executor) runAction(def appdef.Definition, cmds admin.SystemCommands, actionName string, params map[string]string) (map[string]any, error) {
	switch actionName {
	case "manage_packages":
		return e.managePackages(cmds, params)
	case "manage_services":
		return e.manageServices(cmds, params)
	case "manage_processes":
		return e.manageProcesses(cmds, params)
	case "check_port":
		return e.checkPort(params)
	case "release_port":
		return e.releasePort(cmds, params)
	case "manage_files":
		return e.manageFiles(cmds, params)
	case "manage_apps":
		return e.manageApps(cmds, params)
	case "install_pkg":
		return e.installPkg(cmds, params)
	case "build":
		return e.build(cmds, params)
	default:
		// Not a bundled Go verb — a custom verb runs from its root-applied command
		// template (see runSystemCommand). Bundled verbs are matched above and never
		// reach here, so an override of a bundled name is fail-safe: the trusted Go
		// handler runs, not the template.
		return e.runSystemCommand(def, actionName, params)
	}
}

// placeholderRE matches {name} substitution points in a custom verb's command
// template (the same shape the ssh executor uses).
var placeholderRE = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

// runSystemCommand executes a custom (non-bundled) system verb from its
// app-definition `command:` template. Unlike the ssh executor it NEVER goes
// through a shell: the template is tokenized into a fixed argv and each {param}
// substitutes into exactly one argv element, so a parameter value can never add
// an argument or break out into another command. Two guardrails fence it off:
//   - Provenance: when the verb would run privileged (root daemon or sudo
//     escalation) its command template MUST be root-applied — a same-uid agent
//     cannot rewrite it. Personal installs with no privilege boundary keep
//     apps.d custom verbs, matching the ssh executor.
//   - argv[0] is a fixed absolute path with no placeholder (renderSystemArgv
//     re-checks the lint guarantee); e.run's RequireSudoSafe then rejects a
//     user-writable program for a privileged verb.
func (e Executor) runSystemCommand(def appdef.Definition, actionName string, params map[string]string) (map[string]any, error) {
	action, ok := def.Action(actionName)
	if !ok || strings.TrimSpace(action.Command) == "" {
		return nil, fmt.Errorf("unsupported system action %q", actionName)
	}

	priv := geteuid() == 0 || allowSudoEscalation()
	if priv && !action.RootApplied {
		return nil, fmt.Errorf(
			"custom system verb %q must come from the root-owned applied registry "+
				"(via `sudo openscope apply`): a privileged command template may not "+
				"come from an agent-writable source", actionName)
	}

	argv, err := renderSystemArgv(action.Command, action.Parameters, params)
	if err != nil {
		return nil, fmt.Errorf("system verb %q: %w", actionName, err)
	}

	stdout, err := e.run(priv, argv[0], argv[1:]...)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"action": actionName,
		"output": strings.TrimRight(stdout, "\n"),
	}, nil
}

// renderSystemArgv turns a command template into a fixed argv with NO shell:
// it tokenizes on whitespace and substitutes each {param} into exactly one argv
// element, so a value containing spaces stays a single argument and cannot add
// or break into another. argv[0] must be a literal absolute path (the lint
// proves this; we re-check). Values are validated by constraint but never
// shell-quoted — there is no shell to quote for.
func renderSystemArgv(tmpl string, declared []appdef.Parameter, params map[string]string) ([]string, error) {
	constraintOf := make(map[string]string, len(declared))
	for _, p := range declared {
		constraintOf[p.Name] = p.Constraint
	}

	tokens := strings.Fields(tmpl)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty command template")
	}
	if placeholderRE.MatchString(tokens[0]) {
		return nil, fmt.Errorf("program %q must be a literal, not a parameter", tokens[0])
	}
	if !filepath.IsAbs(tokens[0]) {
		return nil, fmt.Errorf("program %q must be an absolute path", tokens[0])
	}

	argv := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		var subErr error
		rendered := placeholderRE.ReplaceAllStringFunc(tok, func(m string) string {
			name := m[1 : len(m)-1]
			val := params[name]
			if strings.ContainsAny(val, "\x00\n") {
				subErr = fmt.Errorf("parameter %q contains a NUL or newline", name)
				return ""
			}
			if constraintOf[name] == "path" {
				if !filepath.IsAbs(val) {
					subErr = fmt.Errorf("parameter %q must be an absolute path", name)
					return ""
				}
				val = filepath.Clean(val)
			}
			return val
		})
		if subErr != nil {
			return nil, subErr
		}
		argv = append(argv, rendered)
	}
	return argv, nil
}

var teamIDPattern = regexp.MustCompile(`Developer ID Installer:.*\(([A-Z0-9]{10})\)`)
var appTeamIDPattern = regexp.MustCompile(`TeamIdentifier=([A-Z0-9]{10})`)

// Overridable for tests so they need neither a real pkgutil/codesign nor a real
// install.
var (
	pkgTeamIDOf     = realPkgTeamID
	appTeamIDOf     = realAppTeamID
	launchInstaller = realLaunchInstaller
)

// installPkg installs a macOS .pkg as root. A pkg's pre/postinstall scripts run
// as root, so this is a powerful primitive; access is fail-closed across three
// composable gates (all configured ones must pass; at least one must be set):
// an allowed path prefix, a root-owned requirement (so the agent can't place or
// swap the pkg), and an allowed signing team ID (an agent can't forge it). The
// installer is launched DETACHED because installing OpenScope's own pkg boots
// the daemon out mid-run; the result is therefore async (confirm afterward).
func (e Executor) installPkg(cmds admin.SystemCommands, params map[string]string) (map[string]any, error) {
	pkg := strings.TrimSpace(params["pkg"])
	if pkg == "" {
		return nil, fmt.Errorf("pkg is required")
	}
	if err := validatePath(pkg); err != nil {
		return nil, err
	}
	pkg = filepath.Clean(pkg)
	if !strings.HasSuffix(pkg, ".pkg") {
		return nil, fmt.Errorf("install_pkg requires a .pkg path, got %q", pkg)
	}
	if geteuid() != 0 {
		return nil, fmt.Errorf("install_pkg needs a root broker — openscoped must run as root (see docs/macos-privileged-helper.md)")
	}
	if !admin.PkgScopeConfigured(cmds) {
		return nil, fmt.Errorf("install_pkg refused: no pkg scope configured — set at least one of pkg.allowed_team_ids, pkg.require_root_owned, or pkg.allowed_prefixes")
	}

	// Gate 1 — path prefix.
	if len(cmds.Pkg.AllowedPrefixes) > 0 && !admin.AllowsPkgPrefix(cmds, pkg) {
		return nil, fmt.Errorf("install_pkg refused: %q is not under an allowed prefix", pkg)
	}
	// Gate 2 — root-owned pkg + containing dir (the agent can't place or swap it).
	if cmds.Pkg.RequireRootOwned {
		if err := requireRootOwnedFile(pkg); err != nil {
			return nil, fmt.Errorf("install_pkg refused: %w", err)
		}
		if err := requireRootOwnedFile(filepath.Dir(pkg)); err != nil {
			return nil, fmt.Errorf("install_pkg refused: containing dir %w", err)
		}
	}
	// Gate 3 — signing team ID (tamper-proof: an agent can't sign as our team).
	if len(cmds.Pkg.AllowedTeamIDs) > 0 {
		team, err := pkgTeamIDOf(pkg)
		if err != nil {
			return nil, fmt.Errorf("install_pkg refused: cannot verify pkg signature: %w", err)
		}
		if team == "" {
			return nil, fmt.Errorf("install_pkg refused: %q is unsigned (no Developer ID Installer team) but pkg.allowed_team_ids is set", pkg)
		}
		if !slices.Contains(cmds.Pkg.AllowedTeamIDs, team) {
			return nil, fmt.Errorf("install_pkg refused: pkg signing team %q is not in pkg.allowed_team_ids", team)
		}
	}

	logPath := filepath.Join(os.TempDir(), "openscope-install.log")
	if err := launchInstaller(pkg, logPath); err != nil {
		return nil, fmt.Errorf("launch installer: %w", err)
	}
	return map[string]any{
		"op":     "install_pkg",
		"pkg":    pkg,
		"status": "installer launched detached; the daemon will restart — confirm with `openscope version`",
		"log":    logPath,
	}, nil
}

// requireRootOwnedFile fails unless path exists, is root-owned, and is not
// group/world-writable.
func requireRootOwnedFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%q: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%q is group/world-writable (mode %04o)", path, perm)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("%q is owned by uid %d, not root", path, st.Uid)
	}
	return nil
}

// realPkgTeamID extracts the Developer ID Installer team from a pkg's signature
// via pkgutil. Returns "" (no error) for an unsigned pkg; an error only when
// pkgutil itself can't run.
func realPkgTeamID(pkg string) (string, error) {
	out, err := exec.Command("/usr/sbin/pkgutil", "--check-signature", pkg).CombinedOutput()
	if m := teamIDPattern.FindStringSubmatch(string(out)); m != nil {
		return m[1], nil
	}
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return "", nil // unsigned / not Developer-ID — non-zero exit, no team id
		}
		return "", err // pkgutil missing or otherwise unrunnable
	}
	return "", nil
}

// realAppTeamID returns the signing team of a .app bundle, but ONLY after
// confirming the signature is valid and the bundle is intact. The verify step
// is load-bearing: reading TeamIdentifier without it would trust a field in a
// bundle the agent may have tampered. A broken/absent signature is an error (the
// gate refuses); a validly-signed-but-teamless bundle (ad-hoc `codesign -s -`)
// returns "" so the team-ID gate refuses it too.
func realAppTeamID(app string) (string, error) {
	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--deep", "--strict", "--", app).CombinedOutput(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("signature invalid or bundle tampered: %s", strings.TrimSpace(string(out)))
		}
		return "", err // codesign missing or otherwise unrunnable
	}
	// codesign writes the -dvv detail to stderr.
	out, _ := exec.Command("/usr/bin/codesign", "-dvv", "--", app).CombinedOutput()
	if m := appTeamIDPattern.FindStringSubmatch(string(out)); m != nil {
		return m[1], nil
	}
	return "", nil
}

// requireAppSourceProvenance enforces the configured manage_apps source gates
// (AND, mirroring install_pkg): a root-owned source so the agent can't swap the
// bundle, and/or a valid signature from an allowed team so a bundle from a
// writable build dir still proves its origin. With neither set, only the
// AllowedSourcePrefixes location check applies (the plan blocks that for a
// writable prefix via SYS-APP-CODEEXEC).
func requireAppSourceProvenance(cmds admin.SystemCommands, source string) error {
	if cmds.Apps.RequireRootOwnedSource {
		if err := requireRootOwnedFile(source); err != nil {
			return fmt.Errorf("source %w", err)
		}
		if err := requireRootOwnedFile(filepath.Dir(source)); err != nil {
			return fmt.Errorf("source containing dir %w", err)
		}
	}
	if len(cmds.Apps.AllowedTeamIDs) > 0 {
		team, err := appTeamIDOf(source)
		if err != nil {
			return fmt.Errorf("cannot verify app signature: %w", err)
		}
		if team == "" {
			return fmt.Errorf("%q has no Developer Team identity but apps.allowed_team_ids is set", source)
		}
		if !slices.Contains(cmds.Apps.AllowedTeamIDs, team) {
			return fmt.Errorf("app signing team %q is not in apps.allowed_team_ids", team)
		}
	}
	return nil
}

// realLaunchInstaller starts `installer -pkg <p> -target /` in a NEW SESSION so
// it survives the daemon being booted out by the pkg's own preinstall. Output
// goes to logPath. It does not wait — the install proceeds independently.
func realLaunchInstaller(pkg, logPath string) error {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command("/usr/sbin/installer", "-pkg", pkg, "-target", "/")
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = cmd.Start()
	logf.Close() // the child inherited its own dup of the fd
	return err
}

func (e Executor) managePackages(cmds admin.SystemCommands, params map[string]string) (map[string]any, error) {
	op := strings.TrimSpace(params["op"])
	managerName := strings.TrimSpace(params["manager"])
	pkg := strings.TrimSpace(params["package"])

	mgr, ok := admin.FindManager(cmds, managerName)
	if !ok {
		return nil, fmt.Errorf("package manager %q is not configured", managerName)
	}

	switch op {
	case "list":
		return e.packageList(mgr)
	case "install", "uninstall", "upgrade":
		if pkg == "" {
			return nil, fmt.Errorf("package is required for %s", op)
		}
		if !packagePattern.MatchString(pkg) {
			return nil, fmt.Errorf("package %q contains unsupported characters", pkg)
		}
		if !admin.AllowsPackage(cmds, pkg) {
			return nil, fmt.Errorf("package %q is not in the allowed list", pkg)
		}
		return e.packageMutate(mgr, op, pkg)
	default:
		return nil, fmt.Errorf("unsupported package op %q (use install, uninstall, upgrade, or list)", op)
	}
}

func (e Executor) packageList(mgr admin.ManagerConfig) (map[string]any, error) {
	args := listArgs(mgr)
	stdout, err := e.run(mgr.Sudo, mgr.Binary, args...)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"manager": mgr.Name,
		"op":      "list",
		"output":  strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) packageMutate(mgr admin.ManagerConfig, op, pkg string) (map[string]any, error) {
	args := mutateArgs(mgr, op, pkg)
	stdout, err := e.run(mgr.Sudo, mgr.Binary, args...)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"manager": mgr.Name,
		"op":      op,
		"package": pkg,
		"output":  strings.TrimRight(stdout, "\n"),
	}, nil
}

func listArgs(mgr admin.ManagerConfig) []string {
	if mgr.Name == "npm" {
		return npmOps["list"]
	}
	if mgr.Name == "pip3" {
		return []string{"list", "--format", "json"}
	}
	return []string{"list"}
}

func mutateArgs(mgr admin.ManagerConfig, op, pkg string) []string {
	if mgr.Name == "npm" {
		base := npmOps[op]
		return append(base, pkg)
	}
	return []string{op, pkg}
}

func (e Executor) manageServices(cmds admin.SystemCommands, params map[string]string) (map[string]any, error) {
	op := strings.TrimSpace(params["op"])
	service := strings.TrimSpace(params["service"])

	if service == "" {
		return nil, fmt.Errorf("service is required")
	}
	if !servicePattern.MatchString(service) {
		return nil, fmt.Errorf("service %q contains unsupported characters", service)
	}
	if !admin.AllowsService(cmds, service) {
		return nil, fmt.Errorf("service %q is not in the allowed list", service)
	}

	switch op {
	case "start":
		return e.brewService("start", service)
	case "stop":
		return e.brewService("stop", service)
	case "restart":
		return e.brewService("restart", service)
	case "status":
		return e.brewService("info", service)
	case "launchctl_list":
		if !cmds.Services.AllowLaunchctl {
			return nil, fmt.Errorf("launchctl is not enabled in system commands config")
		}
		return e.launchctlList(service)
	case "launchctl_start":
		if !cmds.Services.AllowLaunchctl {
			return nil, fmt.Errorf("launchctl is not enabled in system commands config")
		}
		return e.launchctlBootstrap(service)
	case "launchctl_stop":
		if !cmds.Services.AllowLaunchctl {
			return nil, fmt.Errorf("launchctl is not enabled in system commands config")
		}
		return e.launchctlBootout(service)
	default:
		return nil, fmt.Errorf("unsupported service op %q (use start, stop, restart, status, launchctl_list, launchctl_start, or launchctl_stop)", op)
	}
}

func (e Executor) brewService(subcommand, service string) (map[string]any, error) {
	args := []string{"services", subcommand, service}
	if subcommand == "info" {
		args = append(args, "--json")
	}
	stdout, err := e.run(false, "/opt/homebrew/bin/brew", args...)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"service": service,
		"op":      subcommand,
		"output":  strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) manageProcesses(cmds admin.SystemCommands, params map[string]string) (map[string]any, error) {
	op := strings.TrimSpace(params["op"])

	switch op {
	case "list":
		return e.processList(params)
	case "kill":
		return e.processKill(cmds, params)
	default:
		return nil, fmt.Errorf("unsupported process op %q (use kill or list)", op)
	}
}

func (e Executor) processList(params map[string]string) (map[string]any, error) {
	name := strings.TrimSpace(params["name"])

	var stdout string
	var err error
	if name != "" {
		if !processPattern.MatchString(name) {
			return nil, fmt.Errorf("process name %q contains unsupported characters", name)
		}
		stdout, err = e.run(false, "/bin/ps", "aux")
		if err != nil {
			return nil, err
		}
		var filtered []string
		for _, line := range strings.Split(stdout, "\n") {
			if strings.Contains(line, name) {
				filtered = append(filtered, line)
			}
		}
		stdout = strings.Join(filtered, "\n")
	} else {
		stdout, err = e.run(false, "/bin/ps", "aux")
		if err != nil {
			return nil, err
		}
	}

	return map[string]any{
		"op":     "list",
		"output": strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) processKill(cmds admin.SystemCommands, params map[string]string) (map[string]any, error) {
	name := strings.TrimSpace(params["name"])
	pidStr := strings.TrimSpace(params["pid"])
	signal := strings.TrimSpace(params["signal"])

	if signal == "" {
		signal = "TERM"
	}
	signal = strings.ToUpper(signal)
	if !validSignals[signal] {
		return nil, fmt.Errorf("signal %q is not valid (use TERM, HUP, INT, KILL, USR1, USR2, or QUIT)", signal)
	}
	if !admin.AllowsSignal(cmds, signal) {
		return nil, fmt.Errorf("signal %q is not in the allowed list", signal)
	}

	if name != "" {
		if !processPattern.MatchString(name) {
			return nil, fmt.Errorf("process name %q contains unsupported characters", name)
		}
		if !admin.AllowsProcess(cmds, name) {
			return nil, fmt.Errorf("process %q is not in the allowed list", name)
		}
		stdout, err := e.run(false, "/usr/bin/pkill", "-"+signal, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"op":     "kill",
			"name":   name,
			"signal": signal,
			"output": strings.TrimRight(stdout, "\n"),
		}, nil
	}

	if pidStr != "" {
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid < 2 {
			return nil, fmt.Errorf("pid must be a positive integer greater than 1")
		}
		if !cmds.Processes.AllowKillByPID {
			return nil, fmt.Errorf("kill by PID is not enabled in system commands config")
		}
		stdout, err := e.run(false, "/bin/kill", "-"+signal, pidStr)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"op":     "kill",
			"pid":    pid,
			"signal": signal,
			"output": strings.TrimRight(stdout, "\n"),
		}, nil
	}

	return nil, fmt.Errorf("either name or pid is required for kill")
}

func (e Executor) checkPort(params map[string]string) (map[string]any, error) {
	port, err := parsePort(params["port"])
	if err != nil {
		return nil, err
	}

	stdout, err := e.run(false, "/usr/sbin/lsof", "-i", ":"+strconv.Itoa(port), "-P", "-n")
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"port":   port,
		"output": strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) releasePort(cmds admin.SystemCommands, params map[string]string) (map[string]any, error) {
	port, err := parsePort(params["port"])
	if err != nil {
		return nil, err
	}
	if !admin.AllowsPort(cmds, port) {
		return nil, fmt.Errorf("port %d is not in the allowed list", port)
	}

	stdout, err := e.run(false, "/usr/sbin/lsof", "-ti", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}

	pids := strings.Fields(strings.TrimSpace(stdout))
	if len(pids) == 0 {
		return map[string]any{
			"port":     port,
			"released": false,
			"reason":   "no process found on port",
		}, nil
	}

	killArgs := append([]string{"-TERM"}, pids...)
	_, err = e.run(false, "/bin/kill", killArgs...)
	if err != nil {
		return nil, fmt.Errorf("kill processes on port %d: %w", port, err)
	}

	return map[string]any{
		"port":     port,
		"released": true,
		"pids":     pids,
	}, nil
}

func (e Executor) manageFiles(cmds admin.SystemCommands, params map[string]string) (map[string]any, error) {
	op := strings.TrimSpace(params["op"])
	path := strings.TrimSpace(params["path"])

	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if strings.Contains(path, "\x00") || strings.Contains(path, "\n") {
		return nil, fmt.Errorf("path contains unsupported characters")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("path must be absolute")
	}
	path = filepath.Clean(path)

	switch op {
	case "chmod":
		return e.chmod(cmds, path, params)
	case "chown":
		return e.chown(cmds, path, params)
	default:
		return nil, fmt.Errorf("unsupported file op %q (use chmod or chown)", op)
	}
}

func (e Executor) chmod(cmds admin.SystemCommands, path string, params map[string]string) (map[string]any, error) {
	mode := strings.TrimSpace(params["mode"])
	if mode == "" {
		return nil, fmt.Errorf("mode is required for chmod")
	}
	if !modePattern.MatchString(mode) {
		return nil, fmt.Errorf("mode %q is not valid (use octal like 755 or 0644)", mode)
	}
	if len(mode) == 4 && (mode[0] == '4' || mode[0] == '2') {
		return nil, fmt.Errorf("setuid/setgid modes are not allowed")
	}
	if !admin.AllowsFilePath(cmds.Files.AllowedChmodPrefixes, path) {
		return nil, fmt.Errorf("path %q is not in the allowed chmod paths", path)
	}

	_, err := e.run(false, "/bin/chmod", mode, path)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"op":   "chmod",
		"path": path,
		"mode": mode,
	}, nil
}

func (e Executor) chown(cmds admin.SystemCommands, path string, params map[string]string) (map[string]any, error) {
	owner := strings.TrimSpace(params["owner"])
	if owner == "" {
		return nil, fmt.Errorf("owner is required for chown")
	}
	if !ownerPattern.MatchString(owner) {
		return nil, fmt.Errorf("owner %q contains unsupported characters", owner)
	}
	if !admin.AllowsFilePath(cmds.Files.AllowedChownPrefixes, path) {
		return nil, fmt.Errorf("path %q is not in the allowed chown paths", path)
	}

	_, err := e.run(false, "/usr/sbin/chown", owner, path)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"op":    "chown",
		"path":  path,
		"owner": owner,
	}, nil
}

func (e Executor) launchctlList(service string) (map[string]any, error) {
	stdout, err := e.run(false, "/bin/launchctl", "list", service)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"service": service,
		"op":      "launchctl_list",
		"output":  strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) launchctlBootstrap(service string) (map[string]any, error) {
	stdout, err := e.run(false, "/bin/launchctl", "kickstart", "-k", "gui/"+currentUID()+"/"+service)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"service": service,
		"op":      "launchctl_start",
		"output":  strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) launchctlBootout(service string) (map[string]any, error) {
	stdout, err := e.run(false, "/bin/launchctl", "bootout", "gui/"+currentUID()+"/"+service)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"service": service,
		"op":      "launchctl_stop",
		"output":  strings.TrimRight(stdout, "\n"),
	}, nil
}

func currentUID() string {
	return strconv.Itoa(os.Getuid())
}

func (e Executor) manageApps(cmds admin.SystemCommands, params map[string]string) (map[string]any, error) {
	op := strings.TrimSpace(params["op"])
	name := strings.TrimSpace(params["name"])

	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if !appNamePattern.MatchString(name) {
		return nil, fmt.Errorf("app name %q contains unsupported characters", name)
	}
	if !admin.AllowsAppName(cmds, name) {
		return nil, fmt.Errorf("app %q is not in the allowed list", name)
	}

	switch op {
	case "quit":
		return e.appQuit(name)
	case "launch":
		return e.appLaunch(cmds, name)
	case "install":
		return e.appInstall(cmds, name, params)
	case "symlink":
		return e.appSymlink(cmds, name, params)
	case "uninstall":
		return e.appUninstall(cmds, name)
	default:
		return nil, fmt.Errorf("unsupported app op %q (use quit, launch, install, symlink, or uninstall)", op)
	}
}

func (e Executor) appQuit(name string) (map[string]any, error) {
	_, _ = e.run(false, "/usr/bin/osascript", "-e", fmt.Sprintf(`tell application "%s" to quit`, name))
	stdout, err := e.run(false, "/usr/bin/killall", name)
	if err != nil {
		return map[string]any{
			"op":   "quit",
			"name": name,
			"note": "app may not have been running",
		}, nil
	}
	return map[string]any{
		"op":     "quit",
		"name":   name,
		"output": strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) appLaunch(cmds admin.SystemCommands, name string) (map[string]any, error) {
	appPath := ""
	for _, dir := range cmds.Apps.AllowedInstallDirs {
		candidate := filepath.Join(dir, name+".app")
		appPath = candidate
		break
	}
	if appPath == "" {
		return nil, fmt.Errorf("no allowed install directory configured")
	}

	stdout, err := e.run(false, "/usr/bin/open", appPath)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"op":     "launch",
		"name":   name,
		"path":   appPath,
		"output": strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) appInstall(cmds admin.SystemCommands, name string, params map[string]string) (map[string]any, error) {
	source := strings.TrimSpace(params["source"])
	destDir := strings.TrimSpace(params["dest"])

	if source == "" {
		return nil, fmt.Errorf("source is required for install")
	}
	if err := validatePath(source); err != nil {
		return nil, err
	}
	if !admin.AllowsAppSource(cmds, source) {
		return nil, fmt.Errorf("source %q is not in the allowed source paths", source)
	}
	if err := requireAppSourceProvenance(cmds, source); err != nil {
		return nil, fmt.Errorf("manage_apps install refused: %w", err)
	}

	if destDir == "" {
		if len(cmds.Apps.AllowedInstallDirs) > 0 {
			destDir = cmds.Apps.AllowedInstallDirs[0]
		} else {
			return nil, fmt.Errorf("dest is required (no default install directory configured)")
		}
	}
	if err := validatePath(destDir); err != nil {
		return nil, err
	}
	if !admin.AllowsAppInstallDir(cmds, destDir) {
		return nil, fmt.Errorf("dest %q is not in the allowed install directories", destDir)
	}

	destPath := filepath.Join(destDir, name+".app")

	// Remove old install if present, then ditto the new one.
	_, _ = e.run(false, "/bin/rm", "-rf", destPath)
	stdout, err := e.run(false, "/usr/bin/ditto", source, destPath)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"op":     "install",
		"name":   name,
		"source": source,
		"dest":   destPath,
		"output": strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) appSymlink(cmds admin.SystemCommands, name string, params map[string]string) (map[string]any, error) {
	source := strings.TrimSpace(params["source"])
	destDir := strings.TrimSpace(params["dest"])

	if source == "" {
		return nil, fmt.Errorf("source is required for symlink")
	}
	if err := validatePath(source); err != nil {
		return nil, err
	}
	if !admin.AllowsAppSource(cmds, source) {
		return nil, fmt.Errorf("source %q is not in the allowed source paths", source)
	}
	if err := requireAppSourceProvenance(cmds, source); err != nil {
		return nil, fmt.Errorf("manage_apps symlink refused: %w", err)
	}

	if destDir == "" {
		if len(cmds.Apps.AllowedInstallDirs) > 0 {
			destDir = cmds.Apps.AllowedInstallDirs[0]
		} else {
			return nil, fmt.Errorf("dest is required (no default install directory configured)")
		}
	}
	if err := validatePath(destDir); err != nil {
		return nil, err
	}
	if !admin.AllowsAppInstallDir(cmds, destDir) {
		return nil, fmt.Errorf("dest %q is not in the allowed install directories", destDir)
	}

	destPath := filepath.Join(destDir, name+".app")

	_, _ = e.run(false, "/bin/rm", "-f", destPath)
	stdout, err := e.run(false, "/bin/ln", "-s", source, destPath)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"op":     "symlink",
		"name":   name,
		"source": source,
		"dest":   destPath,
		"output": strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) appUninstall(cmds admin.SystemCommands, name string) (map[string]any, error) {
	removed := []string{}
	for _, dir := range cmds.Apps.AllowedInstallDirs {
		appPath := filepath.Join(dir, name+".app")
		_, err := e.run(false, "/bin/rm", "-rf", appPath)
		if err == nil {
			removed = append(removed, appPath)
		}
	}
	return map[string]any{
		"op":      "uninstall",
		"name":    name,
		"removed": removed,
	}, nil
}

func (e Executor) build(cmds admin.SystemCommands, params map[string]string) (map[string]any, error) {
	op := strings.TrimSpace(params["op"])
	project := strings.TrimSpace(params["project"])
	target := strings.TrimSpace(params["target"])
	config := strings.TrimSpace(params["configuration"])

	if project == "" {
		return nil, fmt.Errorf("project is required")
	}
	if err := validatePath(project); err != nil {
		return nil, err
	}
	if !admin.AllowsBuildProject(cmds, project) {
		return nil, fmt.Errorf("project %q is not in the allowed build paths", project)
	}

	switch op {
	case "xcodebuild":
		return e.xcodebuild(project, target, config, params)
	default:
		return nil, fmt.Errorf("unsupported build op %q (use xcodebuild)", op)
	}
}

func (e Executor) xcodebuild(project, target, configuration string, params map[string]string) (map[string]any, error) {
	args := []string{}

	if strings.HasSuffix(project, ".xcworkspace") {
		args = append(args, "-workspace", project)
	} else {
		args = append(args, "-project", project)
	}

	if target != "" {
		if !buildConfigPattern.MatchString(target) {
			return nil, fmt.Errorf("target %q contains unsupported characters", target)
		}
		args = append(args, "-target", target)
	}
	if configuration != "" {
		if !buildConfigPattern.MatchString(configuration) {
			return nil, fmt.Errorf("configuration %q contains unsupported characters", configuration)
		}
		args = append(args, "-configuration", configuration)
	}

	scheme := strings.TrimSpace(params["scheme"])
	if scheme != "" {
		if !buildConfigPattern.MatchString(scheme) {
			return nil, fmt.Errorf("scheme %q contains unsupported characters", scheme)
		}
		args = append(args, "-scheme", scheme)
	}

	action := strings.TrimSpace(params["action"])
	if action == "" {
		action = "build"
	}
	validActions := map[string]bool{"build": true, "clean": true, "test": true, "archive": true}
	if !validActions[action] {
		return nil, fmt.Errorf("unsupported xcodebuild action %q (use build, clean, test, or archive)", action)
	}
	args = append(args, action)

	if strings.TrimSpace(params["allow_provisioning"]) == "true" {
		args = append(args, "-allowProvisioningUpdates")
	}
	if arch := strings.TrimSpace(params["arch"]); arch != "" {
		if !buildConfigPattern.MatchString(arch) {
			return nil, fmt.Errorf("arch %q contains unsupported characters", arch)
		}
		args = append(args, "ARCHS="+arch)
	}

	stdout, err := e.run(false, "/usr/bin/xcodebuild", args...)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"op":      "xcodebuild",
		"project": project,
		"target":  target,
		"output":  strings.TrimRight(stdout, "\n"),
	}, nil
}

func validatePath(path string) error {
	if strings.Contains(path, "\x00") || strings.Contains(path, "\n") {
		return fmt.Errorf("path %q contains unsupported characters", path)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path %q must be absolute", path)
	}
	return nil
}

// geteuid is overridable in tests; the daemon's effective uid decides how a
// privileged command escalates.
var geteuid = os.Geteuid

// allowSudoEscalation reports whether a non-root daemon may escalate privileged
// commands via NOPASSWD sudo. It is opt-in because on a same-uid install the
// agent shares the daemon's sudo grant and could run the command directly — the
// broker bypass. It is safe only when the daemon runs as a dedicated user
// distinct from the agent.
func allowSudoEscalation() bool {
	switch os.Getenv("OPENSCOPE_ALLOW_SUDO_ESCALATION") {
	case "1", "true", "TRUE", "yes", "on":
		return true
	}
	return false
}

func (e Executor) run(sudo bool, binary string, args ...string) (string, error) {
	runner := e.Runner
	if runner == nil {
		runner = execRunner{}
	}

	name := binary
	fullArgs := args
	if sudo {
		// A privileged command. Reject a user-writable binary regardless of how it
		// runs — root executing a tampered binary is privilege escalation, just as
		// a NOPASSWD sudo wildcard would be.
		if err := admin.RequireSudoSafe(binary); err != nil {
			return "", fmt.Errorf("refusing privileged execution: %w", err)
		}
		switch {
		case geteuid() == 0:
			// Root daemon / privileged helper: run directly. No sudo wrapper means
			// no NOPASSWD sudoers wildcard a same-uid agent could abuse.
		case allowSudoEscalation():
			name = "/usr/bin/sudo"
			fullArgs = append([]string{"-n", binary}, args...)
		default:
			return "", fmt.Errorf(
				"privileged command %q needs a root broker: run openscoped as root, or set "+
					"OPENSCOPE_ALLOW_SUDO_ESCALATION=1 only when the daemon's user differs from "+
					"the agent's (see docs/macos-privileged-helper.md)", binary)
		}
	}

	result, err := runner.Run(name, fullArgs)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		message := strings.TrimSpace(result.Stderr)
		if message == "" {
			message = strings.TrimSpace(result.Stdout)
		}
		if message == "" {
			message = fmt.Sprintf("command failed with exit code %d", result.ExitCode)
		}
		if name == "/usr/bin/sudo" && strings.Contains(message, "sudo") {
			message += "; run 'openscope system sudoers' to see required sudoers entries"
		}
		return "", fmt.Errorf("%s", message)
	}
	return result.Stdout, nil
}

func parsePort(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("port is required")
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be an integer between 1 and 65535")
	}
	return port, nil
}

type execRunner struct{}

func (execRunner) Run(name string, args []string) (executor.Result, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := executor.Result{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if err == nil {
		return result, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return executor.Result{}, fmt.Errorf("run %s: %w", name, err)
}

// GenerateSudoers returns sudoers lines for all managers and services that require sudo.
func GenerateSudoers(cmds admin.SystemCommands, username string) string {
	var lines []string
	lines = append(lines, "# Generated by openscope for system executor")
	lines = append(lines, "# Install to /etc/sudoers.d/openscope")
	lines = append(lines, "")

	for _, mgr := range cmds.Packages.Managers {
		if !mgr.Sudo {
			continue
		}
		for _, op := range []string{"install", "uninstall", "upgrade"} {
			lines = append(lines, fmt.Sprintf("%s ALL=(root) NOPASSWD: %s %s *", username, mgr.Binary, op))
		}
	}

	return strings.Join(lines, "\n") + "\n"
}
