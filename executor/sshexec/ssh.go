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
	Run(name string, args []string) (executor.Result, error)
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

	payload, err := e.runAction(target, actionName, params)
	if err != nil {
		return executor.Result{}, err
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return executor.Result{}, fmt.Errorf("marshal ssh action output: %w", err)
	}
	return executor.Result{Stdout: string(data), ExitCode: 0}, nil
}

func (e Executor) runAction(target admin.SSHTarget, actionName string, params map[string]string) (map[string]any, error) {
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
		return nil, fmt.Errorf("unsupported ssh action %q", actionName)
	}
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
	stdout, err := e.runSSHArgs(target, "cat", path)
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
	stdout, err := e.runSSHArgs(target, "ls", "-1A", path)
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

	result, err := runner.Run("ssh", args)
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
