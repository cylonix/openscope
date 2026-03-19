// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appdef

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	ManifestPath string            `yaml:"-"`
}

type App struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"display_name"`
	Executor    string `yaml:"executor"`
	Description string `yaml:"description"`
}

type Action struct {
	Description string      `yaml:"description"`
	Parameters  []Parameter `yaml:"parameters"`
	Output      Output      `yaml:"output"`
	Script      string      `yaml:"script"`
}

type Parameter struct {
	Name      string `yaml:"name"`
	Type      string `yaml:"type"`
	Required  bool   `yaml:"required"`
	PolicyKey string `yaml:"policy_key"`
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

func (d Definition) Validate() error {
	if d.Version == 0 {
		return errors.New("app definition version is required")
	}
	if d.App.Name == "" {
		return errors.New("app.name is required")
	}
	if d.App.Executor == "" {
		return errors.New("app.executor is required")
	}
	if len(d.Actions) == 0 {
		return errors.New("at least one action is required")
	}

	for name, action := range d.Actions {
		if strings.TrimSpace(name) == "" {
			return errors.New("action name is required")
		}
		if action.Script == "" {
			return fmt.Errorf("action %q missing script", name)
		}
		for _, param := range action.Parameters {
			if param.Name == "" {
				return fmt.Errorf("action %q has parameter with missing name", name)
			}
			if param.Type == "" {
				return fmt.Errorf("action %q parameter %q missing type", name, param.Name)
			}
		}
	}

	return nil
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
