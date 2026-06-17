// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ssmexec runs governed verbs on EC2 instances over AWS Systems Manager
// (Run Command), the keyless counterpart to the ssh executor: no inbound SSH, no
// SSH key. It shells out to the `aws` CLI (no AWS SDK — the root module stays
// yaml.v3-only) exactly as sshexec shells out to `ssh`. The broker's AWS identity
// is the credential under custody (credaudit.go); the agent holds only an osk_
// token and, in the enterprise topology, no AWS identity at all.
//
// Phase 2 runs each verb's fixed `command:` template via the AWS-RunShellScript
// document. The command is broker-controlled (a reviewed template with typed,
// constrained params) — never agent-supplied — so it is not "arbitrary" execution
// (the plan lint blocks the passthrough shape). Pinning verbs to custom SSM
// documents (so IAM can deny RunShellScript entirely) is a planned follow-up.
package ssmexec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
)

var (
	placeholderRE  = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)
	servicePattern = regexp.MustCompile(`^[A-Za-z0-9@_.:-]+$`)
)

// CommandRunner runs the local `aws` CLI. Pluggable so tests can fake SSM without
// AWS — the same seam sshexec uses for `ssh`.
type CommandRunner interface {
	Run(name string, args []string, stdin io.Reader) (executor.Result, error)
}

type Executor struct {
	Paths  config.Paths
	Runner CommandRunner
	// PollInterval between get-command-invocation polls (default 2s); set to 0 in
	// tests whose runner returns a terminal status on the first poll.
	PollInterval time.Duration
	// MaxPolls bounds the wait for a command to finish (default 60).
	MaxPolls int
}

func (e Executor) Run(def appdef.Definition, actionName string, params map[string]string) (executor.Result, error) {
	targetAlias := strings.TrimSpace(params["target"])
	if targetAlias == "" {
		return executor.Result{}, fmt.Errorf("target is required")
	}
	targets, err := admin.LoadSSMTargetsOrDefault(e.Paths)
	if err != nil {
		return executor.Result{}, err
	}
	target, ok := admin.FindSSMTarget(targets, targetAlias)
	if !ok {
		return executor.Result{}, fmt.Errorf("ssm target %q not found", targetAlias)
	}

	// Credential custody: the broker's AWS identity must be agent-unreadable, or
	// the agent could call `aws ssm` directly and bypass the broker. Refuse if the
	// resolved credentials file is agent-accessible — the cred analog of an
	// agent-readable SSH key.
	for _, w := range AuditCredCustody(resolveCredFile()) {
		if AgentAccessible(w.Code) {
			return executor.Result{}, fmt.Errorf(
				"refusing ssm action for target %q: broker AWS credentials are agent-accessible — %s",
				target.Alias, w.Message)
		}
	}

	payload, err := e.runAction(def, target, actionName, params)
	if err != nil {
		return executor.Result{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return executor.Result{}, fmt.Errorf("marshal ssm action output: %w", err)
	}
	return executor.Result{Stdout: string(data), ExitCode: 0}, nil
}

// runAction renders the verb's command template (path/service params validated
// against the target's allow-lists and shell-quoted, like sshexec) and runs it
// via SSM Run Command.
func (e Executor) runAction(def appdef.Definition, target admin.SSMTarget, actionName string, params map[string]string) (map[string]any, error) {
	action, ok := def.Action(actionName)
	if !ok {
		return nil, fmt.Errorf("unknown ssm action %q", actionName)
	}
	if strings.TrimSpace(action.Command) == "" {
		return nil, fmt.Errorf("ssm action %q declares no command — add a `command:` template to its app definition", actionName)
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
	stdout, err := e.runRemote(target, command, "openscope ssm/"+actionName)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"target": target.Alias,
		"action": actionName,
		"output": strings.TrimRight(stdout, "\n"),
	}, nil
}

// runRemote sends a single shell command to the instance via AWS-RunShellScript
// and returns its stdout once the invocation completes. The command travels in a
// JSON --parameters value so any metacharacter survives the CLI's shorthand
// parser. comment is recorded on the SSM command (visible in CloudTrail).
func (e Executor) runRemote(target admin.SSMTarget, command, comment string) (string, error) {
	runner := e.Runner
	if runner == nil {
		runner = execRunner{}
	}
	paramsJSON, err := json.Marshal(map[string][]string{"commands": {command}})
	if err != nil {
		return "", err
	}
	send := []string{
		"ssm", "send-command",
		"--region", target.Region,
		"--instance-ids", target.InstanceID,
		"--document-name", "AWS-RunShellScript",
		"--parameters", string(paramsJSON),
		"--comment", comment,
		"--query", "Command.CommandId",
		"--output", "text",
	}
	res, err := runner.Run("aws", send, nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s", firstNonEmpty(strings.TrimSpace(res.Stderr), "ssm send-command failed"))
	}
	commandID := strings.TrimSpace(res.Stdout)
	if commandID == "" {
		return "", fmt.Errorf("ssm send-command returned no command id")
	}
	return e.pollInvocation(runner, target, commandID)
}

type invocation struct {
	Status                string `json:"Status"`
	StandardOutputContent string `json:"StandardOutputContent"`
	StandardErrorContent  string `json:"StandardErrorContent"`
}

func (e Executor) pollInvocation(runner CommandRunner, target admin.SSMTarget, commandID string) (string, error) {
	interval := e.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	maxPolls := e.MaxPolls
	if maxPolls <= 0 {
		maxPolls = 60
	}
	args := []string{
		"ssm", "get-command-invocation",
		"--region", target.Region,
		"--command-id", commandID,
		"--instance-id", target.InstanceID,
		"--output", "json",
	}
	for i := 0; i < maxPolls; i++ {
		res, err := runner.Run("aws", args, nil)
		if err != nil {
			return "", err
		}
		if res.ExitCode != 0 {
			return "", fmt.Errorf("%s", firstNonEmpty(strings.TrimSpace(res.Stderr), "ssm get-command-invocation failed"))
		}
		var inv invocation
		if err := json.Unmarshal([]byte(res.Stdout), &inv); err != nil {
			return "", fmt.Errorf("parse ssm invocation: %w", err)
		}
		switch inv.Status {
		case "Success":
			return inv.StandardOutputContent, nil
		case "Pending", "InProgress", "Delayed":
			time.Sleep(interval)
		default: // Failed, Cancelled, TimedOut, …
			return "", fmt.Errorf("%s", firstNonEmpty(strings.TrimSpace(inv.StandardErrorContent), "ssm command "+inv.Status))
		}
	}
	return "", fmt.Errorf("ssm command %s did not complete in time", commandID)
}

func requireAllowedService(target admin.SSMTarget, service string) (string, error) {
	service = strings.TrimSpace(service)
	if service == "" {
		return "", fmt.Errorf("service is required")
	}
	if !servicePattern.MatchString(service) {
		return "", fmt.Errorf("service %q contains unsupported characters", service)
	}
	if !admin.SSMTargetAllowsService(target, service) {
		return "", fmt.Errorf("service %q is not allowed for target %q", service, target.Alias)
	}
	return service, nil
}

func requireAllowedPath(target admin.SSMTarget, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if strings.ContainsAny(path, "\x00\n") {
		return "", fmt.Errorf("path contains unsupported characters")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	path = filepath.Clean(path)
	if !admin.SSMTargetAllowsPath(target, path) {
		return "", fmt.Errorf("path %q is not allowed for target %q", path, target.Alias)
	}
	return path, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func substitute(tmpl string, subs map[string]string) string {
	return placeholderRE.ReplaceAllStringFunc(tmpl, func(m string) string {
		if v, ok := subs[m[1:len(m)-1]]; ok {
			return v
		}
		return m
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type execRunner struct{}

func (execRunner) Run(name string, args []string, stdin io.Reader) (executor.Result, error) {
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := executor.Result{Stdout: out.String(), Stderr: errb.String()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		return executor.Result{}, err
	}
	return res, nil
}
