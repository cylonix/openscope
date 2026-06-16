// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appdef

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Definition struct {
	Version      int               `yaml:"version"`
	App          App               `yaml:"app"`
	Actions      map[string]Action `yaml:"actions"`
	Source       string            `yaml:"-"`
	Bundled      bool              `yaml:"-"`
	// RootApplied marks a definition that came from the root-owned applied-verb
	// registry (<AdminDir>/app_definitions.yaml) — a human-reviewed, pinned
	// command template a same-uid agent cannot rewrite. Set by LoadAppliedFile.
	RootApplied  bool   `yaml:"-"`
	ManifestPath string `yaml:"-"`
}

type App struct {
	Name         string `yaml:"name"`
	DisplayName  string `yaml:"display_name"`
	Executor     string `yaml:"executor"`
	Description  string `yaml:"description"`
	SecurityMode string `yaml:"security_mode"`
}

type Action struct {
	Description string      `yaml:"description"`
	Parameters  []Parameter `yaml:"parameters"`
	Output      Output      `yaml:"output"`
	// Script names a bundled/templated artifact (e.g. an AppleScript file) for
	// executors that render a script. Command is the alternative for the ssh
	// executor: a remote sh command template whose `{param}` placeholders are
	// substituted with the (shell-quoted) parameter values at run time. An
	// action declares one or the other. Stdin, if set, is rendered the same way
	// and piped to the remote command's standard input (e.g. file content for a
	// write action). The executor — not this schema — decides which it reads.
	Script  string `yaml:"script"`
	Command string `yaml:"command"`
	Stdin   string `yaml:"stdin"`
	// StdinFile names a parameter (constraint: local_source) whose VALUE is a
	// local file path; the executor opens that file and streams it to the remote
	// Command's stdin without buffering — the way a large artifact (e.g. a docker
	// image tar piped to `docker load`) moves without hitting ARG_MAX or the
	// broker's small-JSON request model. Mutually exclusive with Stdin; requires
	// Command. The named local_source parameter is consumed by the stream, never
	// substituted into the command, so the local path can't leak into it.
	StdinFile string `yaml:"stdin_file"`
	// RootApplied marks an action whose command template came from the root-owned
	// applied-verb registry (a same-uid agent cannot rewrite it). Provenance is
	// tracked PER ACTION, not per app: an apps.d verb merged onto a namespace that
	// also has a registry verb must not inherit the registry verb's trust. Set by
	// LoadAppliedFile; the system executor refuses to run a privileged command
	// template whose action is not RootApplied. yaml:"-" so it is never declared.
	RootApplied bool `yaml:"-"`
}

type Parameter struct {
	Name      string `yaml:"name" json:"name"`
	Type      string `yaml:"type" json:"type"`
	Required  bool   `yaml:"required" json:"required"`
	PolicyKey string `yaml:"policy_key" json:"policy_key,omitempty"`
	// Constraint binds a parameter to the target's admin allow-lists before it
	// is substituted into a Command/Stdin template: "path" → must satisfy the
	// SSH target's allowed_paths/allowed_path_prefixes; "service" → must satisfy
	// allowed_services. Empty means a free parameter (still shell-quoted, so it
	// cannot inject). Enforced by the ssh executor.
	Constraint string `yaml:"constraint,omitempty" json:"constraint,omitempty"`
}

type Output struct {
	Mode     string   `yaml:"mode"`
	Schema   string   `yaml:"schema"`
	RawModes []string `yaml:"raw_modes"`
}

type EnabledFile struct {
	Version int      `yaml:"version"`
	Apps    []string `yaml:"apps"`
}

func Parse(data []byte, source string) (Definition, error) {
	var def Definition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return Definition{}, fmt.Errorf("parse app definition: %w", err)
	}

	def.Source = source
	def.ManifestPath = source
	if err := def.Validate(); err != nil {
		return Definition{}, err
	}

	return def, nil
}

func LoadFile(path string) (Definition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Definition{}, fmt.Errorf("read app definition: %w", err)
	}

	def, err := Parse(data, path)
	if err != nil {
		return Definition{}, err
	}
	def.ManifestPath = path
	return def, nil
}

func LoadDir(path string) ([]Definition, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read app definitions dir: %w", err)
	}

	var defs []Definition
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}

		def, err := LoadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}

	sort.Slice(defs, func(i, j int) bool {
		return defs[i].App.Name < defs[j].App.Name
	})

	return defs, nil
}

func (d *Definition) Validate() error {
	if d.Version == 0 {
		return errors.New("app definition version is required")
	}
	if d.App.Name == "" {
		return errors.New("app.name is required")
	}
	if d.App.Executor == "" {
		return errors.New("app.executor is required")
	}
	if d.App.SecurityMode == "" {
		d.App.SecurityMode = "protected"
	}
	if d.App.SecurityMode != "protected" && d.App.SecurityMode != "passthrough" {
		return fmt.Errorf("app.security_mode must be protected or passthrough, got %q", d.App.SecurityMode)
	}
	if len(d.Actions) == 0 {
		return errors.New("at least one action is required")
	}

	for name, action := range d.Actions {
		if strings.TrimSpace(name) == "" {
			return errors.New("action name is required")
		}
		if action.Script == "" && action.Command == "" {
			return fmt.Errorf("action %q must declare a script or a command", name)
		}
		declared := map[string]struct{}{}
		for _, param := range action.Parameters {
			if param.Name == "" {
				return fmt.Errorf("action %q has parameter with missing name", name)
			}
			if param.Type == "" {
				return fmt.Errorf("action %q parameter %q missing type", name, param.Name)
			}
			switch param.Constraint {
			case "", "path", "service", "local_source":
			default:
				return fmt.Errorf("action %q parameter %q has unknown constraint %q (want path|service|local_source)", name, param.Name, param.Constraint)
			}
			declared[param.Name] = struct{}{}
		}
		// Every {placeholder} in the command/stdin template must name a declared
		// parameter — otherwise it would silently substitute to the empty string.
		for _, tmpl := range []string{action.Command, action.Stdin} {
			for _, ref := range referencedParams(tmpl) {
				if _, ok := declared[ref]; !ok {
					return fmt.Errorf("action %q template references undeclared parameter %q", name, ref)
				}
			}
		}
		if err := validateStdinFile(name, action); err != nil {
			return err
		}
	}

	return nil
}

// validateStdinFile enforces the rules for streaming a local file to stdin: the
// stdin_file/local_source pairing is consistent and the local path can never
// leak into the remote command line.
func validateStdinFile(name string, action Action) error {
	// A local_source parameter is only meaningful as the stdin_file stream
	// source, and must never be substituted into the command (which would put a
	// local path on the remote command line).
	for _, p := range action.Parameters {
		if p.Constraint != "local_source" {
			continue
		}
		if strings.TrimSpace(action.StdinFile) != p.Name {
			return fmt.Errorf("action %q: parameter %q (constraint: local_source) must be consumed by stdin_file", name, p.Name)
		}
		for _, tmpl := range []string{action.Command, action.Stdin} {
			if slices.Contains(referencedParams(tmpl), p.Name) {
				return fmt.Errorf("action %q: local_source parameter %q must not appear in the command/stdin template", name, p.Name)
			}
		}
	}

	sf := strings.TrimSpace(action.StdinFile)
	if sf == "" {
		return nil
	}
	if strings.TrimSpace(action.Stdin) != "" {
		return fmt.Errorf("action %q: stdin_file and stdin are mutually exclusive", name)
	}
	if strings.TrimSpace(action.Command) == "" {
		return fmt.Errorf("action %q: stdin_file requires a command to pipe into", name)
	}
	p, ok := paramByName(action.Parameters, sf)
	if !ok {
		return fmt.Errorf("action %q: stdin_file names undeclared parameter %q", name, sf)
	}
	if p.Constraint != "local_source" {
		return fmt.Errorf("action %q: stdin_file parameter %q must have constraint: local_source", name, sf)
	}
	return nil
}

func paramByName(params []Parameter, name string) (Parameter, bool) {
	for _, p := range params {
		if p.Name == name {
			return p, true
		}
	}
	return Parameter{}, false
}

var placeholderRE = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

// referencedParams returns the parameter names a command/stdin template
// references via {name} placeholders.
func referencedParams(tmpl string) []string {
	var out []string
	for _, m := range placeholderRE.FindAllStringSubmatch(tmpl, -1) {
		out = append(out, m[1])
	}
	return out
}

func (d Definition) Action(name string) (Action, bool) {
	action, ok := d.Actions[name]
	return action, ok
}

func (a Action) OrderedArgs(params map[string]string) []string {
	args := make([]string, 0, len(a.Parameters))
	for _, parameter := range a.Parameters {
		args = append(args, params[parameter.Name])
	}
	return args
}

func (a Action) PolicyContext(params map[string]string) map[string]string {
	context := make(map[string]string, len(a.Parameters))
	for _, parameter := range a.Parameters {
		key := parameter.PolicyKey
		if key == "" {
			key = parameter.Name
		}
		if value := strings.TrimSpace(params[parameter.Name]); value != "" {
			context[key] = value
		}
	}
	return context
}

func (d Definition) PolicyContext(actionName string, params map[string]string) map[string]string {
	action, ok := d.Action(actionName)
	if !ok {
		return map[string]string{}
	}
	if d.App.SecurityMode == "passthrough" {
		return map[string]string{}
	}
	return action.PolicyContext(params)
}

func LoadEnabledFile(path string) (EnabledFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EnabledFile{}, fmt.Errorf("read enabled apps file: %w", err)
	}

	var enabled EnabledFile
	if err := yaml.Unmarshal(data, &enabled); err != nil {
		return EnabledFile{}, fmt.Errorf("parse enabled apps file: %w", err)
	}
	if enabled.Version == 0 {
		enabled.Version = 1
	}
	return enabled, nil
}

func LoadEnabledFileOrEmpty(path string) (EnabledFile, error) {
	enabled, err := LoadEnabledFile(path)
	if err == nil {
		return enabled, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return EnabledFile{Version: 1, Apps: []string{}}, nil
	}
	return EnabledFile{}, err
}

func SaveEnabledFile(path string, enabled EnabledFile) error {
	if enabled.Version == 0 {
		enabled.Version = 1
	}
	sort.Strings(enabled.Apps)
	data, err := yaml.Marshal(enabled)
	if err != nil {
		return fmt.Errorf("marshal enabled apps file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write enabled apps file: %w", err)
	}
	return nil
}

func isYAML(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}
