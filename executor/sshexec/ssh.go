// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
)

var servicePattern = regexp.MustCompile(`^[A-Za-z0-9@_.:-]+$`)

type CommandRunner interface {
	Run(name string, args []string, stdin string) (executor.Result, error)
}

type Executor struct {
	Paths  config.Paths
	Runner CommandRunner
}

func (e Executor) Run(def appdef.Definition, actionName string, params map[string]string) (executor.Result, error) {
	targetAlias := strings.TrimSpace(params["target"])
	if targetAlias == "" {
		return executor.Result{}, fmt.Errorf("target is required")
	}

	targets, err := admin.LoadSSHTargetsOrDefault(e.Paths)
	if err != nil {
		return executor.Result{}, err
	}
	target, ok := admin.FindSSHTarget(targets, targetAlias)
	if !ok {
		return executor.Result{}, fmt.Errorf("ssh target %q not found", targetAlias)
	}

	warnings := AuditKeyProtection(target, e.Paths.HomeDir)

	// Enforce key custody at the point of use. The executor runs as root (the
	// privileged daemon), so — unlike the user-vantage planner — it can read a
	// 0700 key dir and verify the actual key files. If the configured key is
	// agent-readable or not a usable root-owned key, refuse: a key the agent can
	// read lets it ssh directly, bypassing the broker entirely.
	for _, w := range warnings {
		if AgentAccessible(w.Code) {
			return executor.Result{}, fmt.Errorf(
				"refusing ssh action for target %q: brokered key is agent-accessible or invalid — %s",
				target.Alias, w.Message)
		}
	}

	payload, err := e.runAction(def, target, actionName, params)
	if err != nil {
		return executor.Result{}, err
	}

	if len(warnings) > 0 {
		payload["key_warnings"] = warnings
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return executor.Result{}, fmt.Errorf("marshal ssh action output: %w", err)
	}
	return executor.Result{Stdout: string(data), ExitCode: 0}, nil
}

// runAction dispatches an action to its handler. The seven curated actions
// below ship structured, parsed output — they are the default verb set, not a
// limit. Any OTHER action is driven by the `command:` template in its app
// definition (runCommandAction): OpenScope brokers what the YAML declares and
// policy allows, it does not cap the verb set. The daemon has already verified
// the action exists in the (root-applied) app definition and that an allow rule
// grants it before we get here.
func (e Executor) runAction(def appdef.Definition, target admin.SSHTarget, actionName string, params map[string]string) (map[string]any, error) {
	switch actionName {
	case "check_host":
		return e.checkHost(target)
	case "service_status":
		service, err := requireAllowedService(target, params["service"])
		if err != nil {
			return nil, err
		}
		return e.serviceStatus(target, service)
	case "restart_service":
		service, err := requireAllowedService(target, params["service"])
		if err != nil {
			return nil, err
		}
		return e.restartService(target, service)
	case "tail_logs":
		service, err := requireAllowedService(target, params["service"])
		if err != nil {
			return nil, err
		}
		lines, err := parseLines(params["lines"])
		if err != nil {
			return nil, err
		}
		return e.tailLogs(target, service, lines)
	case "read_file":
		path, err := requireAllowedPath(target, params["path"])
		if err != nil {
			return nil, err
		}
		return e.readFile(target, path)
	case "list_dir":
		path, err := requireAllowedPath(target, params["path"])
		if err != nil {
			return nil, err
		}
		return e.listDir(target, path)
	case "host_metrics":
		return e.hostMetrics(target)
	default:
		return e.runCommandAction(def, target, actionName, params)
	}
}

// runCommandAction executes a user-defined ssh verb from its app-definition
// `command:` template. Each declared parameter is resolved — path/service
// parameters against the target's admin allow-lists, others as free input — and
// shell-quoted before substitution, so no parameter value can break out of the
// template into an injected command. Optional `stdin:` content is piped to the
// remote command (e.g. file bytes for a write verb) and is NOT shell-quoted, as
// it never touches the command line.
func (e Executor) runCommandAction(def appdef.Definition, target admin.SSHTarget, actionName string, params map[string]string) (map[string]any, error) {
	action, ok := def.Action(actionName)
	if !ok {
		// Should not happen — the daemon already resolved the action — but keep
		// a clear error for direct executor callers/tests.
		return nil, fmt.Errorf("unknown ssh action %q", actionName)
	}
	if strings.TrimSpace(action.Command) == "" {
		return nil, fmt.Errorf("ssh action %q declares no command — add a `command:` template to its app definition", actionName)
	}

	subs := make(map[string]string, len(action.Parameters))
	for _, p := range action.Parameters {
		raw := params[p.Name]
		switch p.Constraint {
		case "path":
			v, err := requireAllowedPath(target, raw)
			if err != nil {
				return nil, err
			}
			subs[p.Name] = shellQuote(v)
		case "service":
			v, err := requireAllowedService(target, raw)
			if err != nil {
				return nil, err
			}
			subs[p.Name] = shellQuote(v)
		default:
			if strings.ContainsRune(raw, 0) {
				return nil, fmt.Errorf("parameter %q contains a NUL byte", p.Name)
			}
			subs[p.Name] = shellQuote(raw)
		}
	}

	command := substitute(action.Command, subs)
	stdin := substituteRaw(action.Stdin, params)

	stdout, err := e.runRemote(target, stdin, command)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"target": target.Alias,
		"action": actionName,
		"output": strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) checkHost(target admin.SSHTarget) (map[string]any, error) {
	stdout, err := e.runSSH(target, "printf '%s\\n' \"$(hostname)\" \"$(whoami)\" \"$(id -u)\" \"$(uname -s)\" \"$(uname -r)\"")
	if err != nil {
		return nil, err
	}
	lines := splitLines(stdout)
	if len(lines) < 5 {
		return nil, fmt.Errorf("unexpected check_host output")
	}
	return map[string]any{
		"target":   target.Alias,
		"hostname": lines[0],
		"user":     lines[1],
		"uid":      lines[2],
		"os":       lines[3],
		"release":  lines[4],
	}, nil
}

func (e Executor) serviceStatus(target admin.SSHTarget, service string) (map[string]any, error) {
	stdout, err := e.runSSHArgs(
		target,
		"systemctl", "show", service,
		"--property=Id",
		"--property=LoadState",
		"--property=ActiveState",
		"--property=SubState",
		"--property=UnitFileState",
	)
	if err != nil {
		return nil, err
	}
	data := map[string]any{
		"target":  target.Alias,
		"service": service,
	}
	for _, line := range splitLines(stdout) {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch strings.TrimSpace(parts[0]) {
		case "Id":
			data["id"] = strings.TrimSpace(parts[1])
		case "LoadState":
			data["load_state"] = strings.TrimSpace(parts[1])
		case "ActiveState":
			data["active_state"] = strings.TrimSpace(parts[1])
		case "SubState":
			data["sub_state"] = strings.TrimSpace(parts[1])
		case "UnitFileState":
			data["unit_file_state"] = strings.TrimSpace(parts[1])
		}
	}
	return data, nil
}

func (e Executor) restartService(target admin.SSHTarget, service string) (map[string]any, error) {
	if _, err := e.runSSHArgs(target, "systemctl", "restart", service); err != nil {
		return nil, err
	}
	status, err := e.serviceStatus(target, service)
	if err != nil {
		return nil, err
	}
	status["restarted"] = true
	return status, nil
}

func (e Executor) tailLogs(target admin.SSHTarget, service string, lines int) (map[string]any, error) {
	stdout, err := e.runSSHArgs(target, "journalctl", "-u", service, "-n", strconv.Itoa(lines), "--no-pager")
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"target":  target.Alias,
		"service": service,
		"lines":   lines,
		"output":  strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) readFile(target admin.SSHTarget, path string) (map[string]any, error) {
	// Quote the path into a single remote command string rather than relying on
	// ssh's argument joining: a path under an allowed prefix can still contain
	// shell metacharacters (e.g. "/var/log/x; rm -rf /"), and ssh would hand the
	// joined args to the remote shell. shellQuote makes the path a literal.
	stdout, err := e.runRemote(target, "", "cat -- "+shellQuote(path))
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"target": target.Alias,
		"path":   path,
		"body":   strings.TrimRight(stdout, "\n"),
	}, nil
}

func (e Executor) listDir(target admin.SSHTarget, path string) (map[string]any, error) {
	stdout, err := e.runRemote(target, "", "ls -1A -- "+shellQuote(path))
	if err != nil {
		return nil, err
	}
	entries := splitLines(stdout)
	return map[string]any{
		"target":  target.Alias,
		"path":    path,
		"entries": entries,
	}, nil
}

func (e Executor) hostMetrics(target admin.SSHTarget) (map[string]any, error) {
	stdout, err := e.runSSH(target, "printf '%s\\n' \"$(uptime)\" \"$(cat /proc/loadavg 2>/dev/null || true)\" \"$(free -m 2>/dev/null | sed -n '2p' || true)\" \"$(df -Pk / | tail -1)\"")
	if err != nil {
		return nil, err
	}
	lines := splitLines(stdout)
	for len(lines) < 4 {
		lines = append(lines, "")
	}
	return map[string]any{
		"target":    target.Alias,
		"uptime":    lines[0],
		"loadavg":   lines[1],
		"memory":    lines[2],
		"disk_root": lines[3],
	}, nil
}

func (e Executor) runSSH(target admin.SSHTarget, remoteCommand string) (string, error) {
	return e.runSSHArgs(target, "sh", "-lc", remoteCommand)
}

func (e Executor) runSSHArgs(target admin.SSHTarget, remoteArgs ...string) (string, error) {
	return e.runRemote(target, "", remoteArgs...)
}

// runRemote invokes ssh against target, optionally piping stdin to the remote
// command, and returns its stdout. remoteArgs are the command sent to the
// remote host (ssh joins them and hands the result to the login shell).
func (e Executor) runRemote(target admin.SSHTarget, stdin string, remoteArgs ...string) (string, error) {
	runner := e.Runner
	if runner == nil {
		runner = execRunner{}
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
	}
	if target.Port > 0 {
		args = append(args, "-p", strconv.Itoa(target.Port))
	}
	if target.IdentityFile != "" {
		args = append(args, "-i", target.IdentityFile)
	}
	if target.ProxyJump != "" {
		args = append(args, "-J", target.ProxyJump)
	}
	args = append(args, target.User+"@"+target.Host)
	args = append(args, remoteArgs...)

	result, err := runner.Run("ssh", args, stdin)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		message := strings.TrimSpace(result.Stderr)
		if message == "" {
			message = strings.TrimSpace(result.Stdout)
		}
		if message == "" {
			message = "ssh command failed"
		}
		return "", fmt.Errorf("%s", message)
	}
	return result.Stdout, nil
}

type execRunner struct{}

func (execRunner) Run(name string, args []string, stdin string) (executor.Result, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
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

var placeholderRE = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

// substitute replaces each {name} placeholder in a command template with its
// (already shell-quoted) value from subs in a single pass, so a quoted value
// that happens to contain "{...}" is never re-expanded. Unknown placeholders
// are left intact (validation rejects them at app-load time).
func substitute(tmpl string, subs map[string]string) string {
	return placeholderRE.ReplaceAllStringFunc(tmpl, func(m string) string {
		if v, ok := subs[m[1:len(m)-1]]; ok {
			return v
		}
		return m
	})
}

// substituteRaw fills a stdin template with raw (unquoted) parameter values —
// stdin is piped to the remote command, never parsed as a command line.
func substituteRaw(tmpl string, params map[string]string) string {
	if tmpl == "" {
		return ""
	}
	return placeholderRE.ReplaceAllStringFunc(tmpl, func(m string) string {
		return params[m[1:len(m)-1]]
	})
}

// shellQuote wraps s in single quotes so the remote POSIX shell treats it as a
// single literal token, escaping any embedded single quotes. This is what makes
// substituting arbitrary parameter values into a command template injection-safe.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func requireAllowedService(target admin.SSHTarget, service string) (string, error) {
	service = strings.TrimSpace(service)
	if service == "" {
		return "", fmt.Errorf("service is required")
	}
	if !servicePattern.MatchString(service) {
		return "", fmt.Errorf("service %q contains unsupported characters", service)
	}
	if !admin.SSHTargetAllowsService(target, service) {
		return "", fmt.Errorf("service %q is not allowed for target %q", service, target.Alias)
	}
	return service, nil
}

func requireAllowedPath(target admin.SSHTarget, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if strings.Contains(path, "\x00") || strings.Contains(path, "\n") {
		return "", fmt.Errorf("path contains unsupported characters")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	path = filepath.Clean(path)
	if !admin.SSHTargetAllowsPath(target, path) {
		return "", fmt.Errorf("path %q is not allowed for target %q", path, target.Alias)
	}
	return path, nil
}

func parseLines(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 200, nil
	}
	lines, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("lines must be an integer")
	}
	if lines < 1 || lines > 500 {
		return 0, fmt.Errorf("lines must be between 1 and 500")
	}
	return lines, nil
}

func splitLines(value string) []string {
	trimmed := strings.TrimRight(value, "\n")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "\n")
}
