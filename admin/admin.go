// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/openscope/openscope/config"
	"gopkg.in/yaml.v3"
)

var DefaultProtectedFolderKeywords = []string{"private", "hidden"}

type ProtectedFolders struct {
	Version  int      `yaml:"version"`
	Keywords []string `yaml:"keywords"`
}

func LoadProtectedFolders(path string) (ProtectedFolders, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ProtectedFolders{}, fmt.Errorf("read protected folders file: %w", err)
	}

	var protected ProtectedFolders
	if err := yaml.Unmarshal(data, &protected); err != nil {
		return ProtectedFolders{}, fmt.Errorf("parse protected folders file: %w", err)
	}

	return normalizeProtectedFolders(protected), protected.Validate()
}

func LoadProtectedFoldersOrDefault(paths config.Paths) (ProtectedFolders, error) {
	protected, err := LoadProtectedFolders(paths.ProtectedFoldersFile)
	if err == nil {
		return protected, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return normalizeProtectedFolders(ProtectedFolders{
			Version:  1,
			Keywords: append([]string(nil), DefaultProtectedFolderKeywords...),
		}), nil
	}
	return ProtectedFolders{}, err
}

func SaveProtectedFolders(path string, protected ProtectedFolders) error {
	protected = normalizeProtectedFolders(protected)
	if protected.Version == 0 {
		protected.Version = 1
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create admin config dir: %w", err)
	}

	data, err := yaml.Marshal(protected)
	if err != nil {
		return fmt.Errorf("marshal protected folders file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write protected folders file: %w", err)
	}
	return nil
}

func SaveDefaultProtectedFolders(paths config.Paths, protected ProtectedFolders) error {
	return SaveProtectedFolders(paths.ProtectedFoldersFile, protected)
}

func AddProtectedFolderKeyword(paths config.Paths, keyword string) (ProtectedFolders, bool, error) {
	protected, err := LoadProtectedFoldersOrDefault(paths)
	if err != nil {
		return ProtectedFolders{}, false, err
	}

	keyword = normalizeKeyword(keyword)
	if keyword == "" {
		return ProtectedFolders{}, false, fmt.Errorf("keyword cannot be empty")
	}
	if slices.Contains(protected.Keywords, keyword) {
		return protected, false, nil
	}

	protected.Keywords = append(protected.Keywords, keyword)
	if err := SaveDefaultProtectedFolders(paths, protected); err != nil {
		return ProtectedFolders{}, false, err
	}
	return normalizeProtectedFolders(protected), true, nil
}

func RemoveProtectedFolderKeyword(paths config.Paths, keyword string) (ProtectedFolders, bool, error) {
	protected, err := LoadProtectedFoldersOrDefault(paths)
	if err != nil {
		return ProtectedFolders{}, false, err
	}

	keyword = normalizeKeyword(keyword)
	index := slices.Index(protected.Keywords, keyword)
	if index < 0 {
		return protected, false, nil
	}

	protected.Keywords = append(protected.Keywords[:index], protected.Keywords[index+1:]...)
	if err := SaveDefaultProtectedFolders(paths, protected); err != nil {
		return ProtectedFolders{}, false, err
	}
	return normalizeProtectedFolders(protected), true, nil
}

func MatchProtectedFolder(protected ProtectedFolders, folder string) (string, bool) {
	folder = strings.ToLower(folder)
	for _, keyword := range protected.Keywords {
		if keyword != "" && strings.Contains(folder, keyword) {
			return keyword, true
		}
	}
	return "", false
}

func (p ProtectedFolders) Validate() error {
	if p.Version == 0 {
		return fmt.Errorf("protected folders version is required")
	}
	for _, keyword := range p.Keywords {
		if normalizeKeyword(keyword) == "" {
			return fmt.Errorf("protected folder keywords must not be empty")
		}
	}
	return nil
}

func normalizeProtectedFolders(protected ProtectedFolders) ProtectedFolders {
	protected.Version = max(protected.Version, 1)
	seen := map[string]struct{}{}
	keywords := make([]string, 0, len(protected.Keywords))
	for _, keyword := range protected.Keywords {
		normalized := normalizeKeyword(keyword)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		keywords = append(keywords, normalized)
	}
	sort.Strings(keywords)
	protected.Keywords = keywords
	return protected
}

func normalizeKeyword(keyword string) string {
	return strings.ToLower(strings.TrimSpace(keyword))
}
