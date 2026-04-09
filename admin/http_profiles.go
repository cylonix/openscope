// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package admin

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openscope/openscope/config"
	"gopkg.in/yaml.v3"
)

type HTTPProfiles struct {
	Version  int           `yaml:"version"`
	Profiles []HTTPProfile `yaml:"profiles"`
}

type HTTPProfile struct {
	Name           string            `yaml:"name"`
	BaseURL        string            `yaml:"base_url"`
	Headers        map[string]string `yaml:"headers,omitempty"`
	TimeoutSeconds int               `yaml:"timeout_seconds,omitempty"`
}

func LoadHTTPProfiles(path string) (HTTPProfiles, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return HTTPProfiles{}, fmt.Errorf("read http profiles file: %w", err)
	}

	var profiles HTTPProfiles
	if err := yaml.Unmarshal(data, &profiles); err != nil {
		return HTTPProfiles{}, fmt.Errorf("parse http profiles file: %w", err)
	}
	return normalizeHTTPProfiles(profiles), profiles.Validate()
}

func LoadHTTPProfilesOrDefault(paths config.Paths) (HTTPProfiles, error) {
	profiles, err := LoadHTTPProfiles(paths.HTTPProfilesFile)
	if err == nil {
		return profiles, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return HTTPProfiles{Version: 1, Profiles: []HTTPProfile{}}, nil
	}
	return HTTPProfiles{}, err
}

func SaveHTTPProfiles(path string, profiles HTTPProfiles) error {
	profiles = normalizeHTTPProfiles(profiles)
	if profiles.Version == 0 {
		profiles.Version = 1
	}
	if err := profiles.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create admin config dir: %w", err)
	}
	data, err := yaml.Marshal(profiles)
	if err != nil {
		return fmt.Errorf("marshal http profiles file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write http profiles file: %w", err)
	}
	return nil
}

func SaveDefaultHTTPProfiles(paths config.Paths, profiles HTTPProfiles) error {
	return SaveHTTPProfiles(paths.HTTPProfilesFile, profiles)
}

func AddHTTPProfile(paths config.Paths, profile HTTPProfile) (HTTPProfiles, bool, error) {
	profiles, err := LoadHTTPProfilesOrDefault(paths)
	if err != nil {
		return HTTPProfiles{}, false, err
	}
	profile = normalizeHTTPProfile(profile)
	if err := profile.Validate(); err != nil {
		return HTTPProfiles{}, false, err
	}
	for _, existing := range profiles.Profiles {
		if existing.Name == profile.Name {
			return profiles, false, nil
		}
	}
	profiles.Profiles = append(profiles.Profiles, profile)
	if err := SaveDefaultHTTPProfiles(paths, profiles); err != nil {
		return HTTPProfiles{}, false, err
	}
	return normalizeHTTPProfiles(profiles), true, nil
}

func RemoveHTTPProfile(paths config.Paths, name string) (HTTPProfiles, bool, error) {
	profiles, err := LoadHTTPProfilesOrDefault(paths)
	if err != nil {
		return HTTPProfiles{}, false, err
	}
	name = strings.TrimSpace(name)
	filtered := make([]HTTPProfile, 0, len(profiles.Profiles))
	removed := false
	for _, profile := range profiles.Profiles {
		if profile.Name == name {
			removed = true
			continue
		}
		filtered = append(filtered, profile)
	}
	if !removed {
		return profiles, false, nil
	}
	profiles.Profiles = filtered
	if err := SaveDefaultHTTPProfiles(paths, profiles); err != nil {
		return HTTPProfiles{}, false, err
	}
	return normalizeHTTPProfiles(profiles), true, nil
}

func FindHTTPProfile(profiles HTTPProfiles, name string) (HTTPProfile, bool) {
	for _, profile := range profiles.Profiles {
		if profile.Name == name {
			return profile, true
		}
	}
	return HTTPProfile{}, false
}

func (f HTTPProfiles) Validate() error {
	if f.Version == 0 {
		return fmt.Errorf("http profiles version is required")
	}
	seen := map[string]struct{}{}
	for _, profile := range f.Profiles {
		if err := profile.Validate(); err != nil {
			return err
		}
		if _, exists := seen[profile.Name]; exists {
			return fmt.Errorf("http profile %q is duplicated", profile.Name)
		}
		seen[profile.Name] = struct{}{}
	}
	return nil
}

func (p HTTPProfile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("http profile name is required")
	}
	if strings.TrimSpace(p.BaseURL) == "" {
		return fmt.Errorf("http profile %q base_url is required", p.Name)
	}
	parsed, err := url.Parse(p.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("http profile %q base_url must be an absolute URL", p.Name)
	}
	if p.TimeoutSeconds < 0 {
		return fmt.Errorf("http profile %q timeout_seconds must be non-negative", p.Name)
	}
	for key := range p.Headers {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("http profile %q header names must not be empty", p.Name)
		}
	}
	return nil
}

func normalizeHTTPProfiles(profiles HTTPProfiles) HTTPProfiles {
	if profiles.Version == 0 {
		profiles.Version = 1
	}
	normalized := make([]HTTPProfile, 0, len(profiles.Profiles))
	for _, profile := range profiles.Profiles {
		normalized = append(normalized, normalizeHTTPProfile(profile))
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Name < normalized[j].Name
	})
	profiles.Profiles = normalized
	return profiles
}

func normalizeHTTPProfile(profile HTTPProfile) HTTPProfile {
	profile.Name = strings.TrimSpace(profile.Name)
	profile.BaseURL = strings.TrimRight(strings.TrimSpace(profile.BaseURL), "/")
	if profile.TimeoutSeconds == 0 {
		profile.TimeoutSeconds = 30
	}
	headers := map[string]string{}
	for key, value := range profile.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		headers[key] = value
	}
	profile.Headers = headers
	return profile
}
