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
var DefaultMailAllowedSenderDomains = []string{}

type ProtectedFolders struct {
	Version  int      `yaml:"version"`
	Keywords []string `yaml:"keywords"`
}

type MailFilters struct {
	Version              int      `yaml:"version"`
	AllowedSenderDomains []string `yaml:"allowed_sender_domains"`
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

func LoadMailFilters(path string) (MailFilters, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return MailFilters{}, fmt.Errorf("read mail filters file: %w", err)
	}

	var filters MailFilters
	if err := yaml.Unmarshal(data, &filters); err != nil {
		return MailFilters{}, fmt.Errorf("parse mail filters file: %w", err)
	}

	return normalizeMailFilters(filters), filters.Validate()
}

func LoadMailFiltersOrDefault(paths config.Paths) (MailFilters, error) {
	filters, err := LoadMailFilters(paths.MailFiltersFile)
	if err == nil {
		return filters, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return normalizeMailFilters(MailFilters{
			Version:              1,
			AllowedSenderDomains: append([]string(nil), DefaultMailAllowedSenderDomains...),
		}), nil
	}
	return MailFilters{}, err
}

func SaveMailFilters(path string, filters MailFilters) error {
	filters = normalizeMailFilters(filters)
	if filters.Version == 0 {
		filters.Version = 1
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create admin config dir: %w", err)
	}

	data, err := yaml.Marshal(filters)
	if err != nil {
		return fmt.Errorf("marshal mail filters file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write mail filters file: %w", err)
	}
	return nil
}

func SaveDefaultMailFilters(paths config.Paths, filters MailFilters) error {
	return SaveMailFilters(paths.MailFiltersFile, filters)
}

func AddAllowedSenderDomain(paths config.Paths, domain string) (MailFilters, bool, error) {
	filters, err := LoadMailFiltersOrDefault(paths)
	if err != nil {
		return MailFilters{}, false, err
	}

	domain = normalizeDomain(domain)
	if domain == "" {
		return MailFilters{}, false, fmt.Errorf("domain cannot be empty")
	}
	if slices.Contains(filters.AllowedSenderDomains, domain) {
		return filters, false, nil
	}

	filters.AllowedSenderDomains = append(filters.AllowedSenderDomains, domain)
	if err := SaveDefaultMailFilters(paths, filters); err != nil {
		return MailFilters{}, false, err
	}
	return normalizeMailFilters(filters), true, nil
}

func RemoveAllowedSenderDomain(paths config.Paths, domain string) (MailFilters, bool, error) {
	filters, err := LoadMailFiltersOrDefault(paths)
	if err != nil {
		return MailFilters{}, false, err
	}

	domain = normalizeDomain(domain)
	index := slices.Index(filters.AllowedSenderDomains, domain)
	if index < 0 {
		return filters, false, nil
	}

	filters.AllowedSenderDomains = append(filters.AllowedSenderDomains[:index], filters.AllowedSenderDomains[index+1:]...)
	if err := SaveDefaultMailFilters(paths, filters); err != nil {
		return MailFilters{}, false, err
	}
	return normalizeMailFilters(filters), true, nil
}

func SenderAllowed(filters MailFilters, sender string) bool {
	if len(filters.AllowedSenderDomains) == 0 {
		return true
	}

	domain := senderDomain(sender)
	if domain == "" {
		return false
	}
	return slices.Contains(filters.AllowedSenderDomains, domain)
}

func (f MailFilters) Validate() error {
	if f.Version == 0 {
		return fmt.Errorf("mail filters version is required")
	}
	for _, domain := range f.AllowedSenderDomains {
		if normalizeDomain(domain) == "" {
			return fmt.Errorf("allowed sender domains must not be empty")
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

func normalizeMailFilters(filters MailFilters) MailFilters {
	filters.Version = max(filters.Version, 1)
	seen := map[string]struct{}{}
	domains := make([]string, 0, len(filters.AllowedSenderDomains))
	for _, domain := range filters.AllowedSenderDomains {
		normalized := normalizeDomain(domain)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		domains = append(domains, normalized)
	}
	sort.Strings(domains)
	filters.AllowedSenderDomains = domains
	return filters
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "@")
	return domain
}

func senderDomain(sender string) string {
	sender = strings.TrimSpace(strings.ToLower(sender))
	if sender == "" {
		return ""
	}

	if start := strings.LastIndex(sender, "<"); start >= 0 {
		if end := strings.LastIndex(sender, ">"); end > start {
			sender = sender[start+1 : end]
		}
	}

	at := strings.LastIndex(sender, "@")
	if at < 0 || at == len(sender)-1 {
		return ""
	}
	return sender[at+1:]
}
