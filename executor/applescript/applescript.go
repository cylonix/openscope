// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package applescript

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/executor"
	"github.com/openscope/openscope/resources"
)

type Executor struct{}

type runnerRequest struct {
	ScriptPath string            `json:"scriptPath"`
	Params     map[string]string `json:"params"`
}

func (Executor) Run(def appdef.Definition, actionName string, params map[string]string) (executor.Result, error) {
	action, ok := def.Action(actionName)
	if !ok {
		return executor.Result{}, fmt.Errorf("unknown action %q", actionName)
	}

	scriptPath, cleanup, err := materializeScript(def, action.Script)
	if err != nil {
		return executor.Result{}, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	helperPath, err := runnerPath()
	if err != nil {
		return executor.Result{}, err
	}

	requestPayload, err := json.Marshal(runnerRequest{
		ScriptPath: scriptPath,
		Params:     orderedParamMap(action, params),
	})
	if err != nil {
		return executor.Result{}, fmt.Errorf("marshal runner request: %w", err)
	}

	cmd := exec.Command(helperPath)
	cmd.Stdin = bytes.NewReader(requestPayload)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	result := executor.Result{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if runErr == nil {
		return result, nil
	}

	var exitErr *exec.ExitError
	if ok := asExitError(runErr, &exitErr); ok {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}

	return result, fmt.Errorf("run AppleScript helper: %w", runErr)
}

func orderedParamMap(action appdef.Action, params map[string]string) map[string]string {
	values := make(map[string]string, len(action.Parameters))
	for _, parameter := range action.Parameters {
		values[parameter.Name] = params[parameter.Name]
	}
	return values
}

func materializeScript(def appdef.Definition, scriptRef string) (string, func(), error) {
	if def.Bundled {
		bundledPath := filepath.ToSlash(filepath.Join("bundled", "scripts", scriptRef))
		data, err := resources.FS.ReadFile(bundledPath)
		if err != nil {
			return "", nil, fmt.Errorf("read bundled script %q: %w", bundledPath, err)
		}

		file, err := os.CreateTemp(validTempDir(), "openscope-*.applescript")
		if err != nil {
			return "", nil, fmt.Errorf("create temp script: %w", err)
		}
		if _, err := file.Write(data); err != nil {
			file.Close()
			return "", nil, fmt.Errorf("write temp script: %w", err)
		}
		if err := file.Close(); err != nil {
			return "", nil, fmt.Errorf("close temp script: %w", err)
		}

		cleanup := func() {
			_ = os.Remove(file.Name())
		}
		return file.Name(), cleanup, nil
	}

	baseDir := filepath.Dir(def.ManifestPath)
	return filepath.Join(baseDir, scriptRef), nil, nil
}

func runnerPath() (string, error) {
	if configured := os.Getenv("OPENSCOPE_APPLESCRIPT_HELPER"); configured != "" {
		return configured, nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}

	candidate := filepath.Join(filepath.Dir(exePath), "asapple")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	return "", fmt.Errorf("AppleScript helper not found at %q; build the macOS app bundle so asapple is embedded", candidate)
}

// validTempDir returns os.TempDir() if it exists, otherwise /private/tmp.
// When openscoped is started by the macOS PKG installer its TMPDIR points to the
// installer sandbox (PKInstallSandbox.*), which is deleted after install.
func validTempDir() string {
	d := os.TempDir()
	if _, err := os.Stat(d); err == nil {
		return d
	}
	return "/private/tmp"
}

func asExitError(err error, target **exec.ExitError) bool {
	exitErr, ok := err.(*exec.ExitError)
	if ok {
		*target = exitErr
	}
	return ok
}
