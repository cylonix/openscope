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

type SystemCommands struct {
	Version   int              `yaml:"version"`
	Packages  PackageConfig    `yaml:"packages"`
	Services  ServiceConfig    `yaml:"services"`
	Processes ProcessConfig    `yaml:"processes"`
	Ports     PortConfig       `yaml:"ports"`
	Files     FileConfig       `yaml:"files"`
	Apps      AppConfig        `yaml:"apps"`
	Pkg       PkgConfig        `yaml:"pkg"`
	Builds    BuildConfig      `yaml:"builds"`
}

// PkgConfig scopes the install_pkg action (running `installer -pkg` as root —
// a powerful primitive, since a pkg's pre/postinstall scripts run as root). The
// three gates compose and are ALL enforced when set; at least one must be set or
// install_pkg refuses (fail closed). AllowedTeamIDs is the strongest (an agent
// cannot forge a signing identity); RequireRootOwned stops the agent swapping or
// renaming a pkg into place; AllowedPrefixes alone is weakest (a writable prefix
// lets the agent drop any pkg there).
type PkgConfig struct {
	AllowedPrefixes  []string `yaml:"allowed_prefixes"`
	RequireRootOwned bool     `yaml:"require_root_owned"`
	AllowedTeamIDs   []string `yaml:"allowed_team_ids"`
}

type PackageConfig struct {
	Managers []ManagerConfig `yaml:"managers"`
	Allowed  []string        `yaml:"allowed"`
	Blocked  []string        `yaml:"blocked"`
}

type ManagerConfig struct {
	Name   string `yaml:"name"`
	Sudo   bool   `yaml:"sudo"`
	Binary string `yaml:"binary"`
}

type ServiceConfig struct {
	Allowed        []string `yaml:"allowed"`
	AllowLaunchctl bool     `yaml:"allow_launchctl"`
}

// AppConfig scopes manage_apps. The install op copies (or symlinks) a .app into
// an install dir — arbitrary code execution as the user once launched, so the
// SOURCE is gated like install_pkg's PkgConfig: AllowedSourcePrefixes bounds
// where an app may come from; the two provenance gates below, when set, are
// ALSO enforced (AND, mirroring install_pkg) so a build dir the agent can write
// is acceptable only when the bundle proves its origin. RequireRootOwnedSource
// stops the agent swapping the bundle; AllowedTeamIDs requires a valid code
// signature from an allowed team (an agent cannot forge it), which is what lets
// a test app install from a NON-root build dir.
type AppConfig struct {
	AllowedSourcePrefixes  []string `yaml:"allowed_source_prefixes"`
	AllowedInstallDirs     []string `yaml:"allowed_install_dirs"`
	AllowedNames           []string `yaml:"allowed_names"`
	RequireRootOwnedSource bool     `yaml:"require_root_owned_source"`
	AllowedTeamIDs         []string `yaml:"allowed_team_ids"`
}

type BuildConfig struct {
	AllowedProjectPrefixes []string `yaml:"allowed_project_prefixes"`
}

type ProcessConfig struct {
	AllowedSignals []string `yaml:"allowed_signals"`
	AllowedNames   []string `yaml:"allowed_names"`
	AllowKillByPID bool     `yaml:"allow_kill_by_pid"`
}

type PortConfig struct {
	Allowed []int `yaml:"allowed"`
}

type FileConfig struct {
	AllowedChmodPrefixes []string `yaml:"allowed_chmod_prefixes"`
	AllowedChownPrefixes []string `yaml:"allowed_chown_prefixes"`
}

func LoadSystemCommands(path string) (SystemCommands, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SystemCommands{}, fmt.Errorf("read system commands file: %w", err)
	}

	var cmds SystemCommands
	if err := yaml.Unmarshal(data, &cmds); err != nil {
		return SystemCommands{}, fmt.Errorf("parse system commands file: %w", err)
	}

	return normalizeSystemCommands(cmds), cmds.Validate()
}

func LoadSystemCommandsOrDefault(paths config.Paths) (SystemCommands, error) {
	cmds, err := LoadSystemCommands(paths.SystemCommandsFile)
	if err == nil {
		return cmds, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return SystemCommands{Version: 1}, nil
	}
	return SystemCommands{}, err
}

func SaveSystemCommands(path string, cmds SystemCommands) error {
	cmds = normalizeSystemCommands(cmds)
	if cmds.Version == 0 {
		cmds.Version = 1
	}
	if err := cmds.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create admin config dir: %w", err)
	}
	data, err := yaml.Marshal(cmds)
	if err != nil {
		return fmt.Errorf("marshal system commands file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write system commands file: %w", err)
	}
	return nil
}

func SaveDefaultSystemCommands(paths config.Paths, cmds SystemCommands) error {
	return SaveSystemCommands(paths.SystemCommandsFile, cmds)
}

func AddManager(paths config.Paths, mgr ManagerConfig) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	mgr.Name = strings.TrimSpace(mgr.Name)
	mgr.Binary = strings.TrimSpace(mgr.Binary)
	if mgr.Name == "" {
		return SystemCommands{}, false, fmt.Errorf("manager name is required")
	}
	if mgr.Binary == "" {
		return SystemCommands{}, false, fmt.Errorf("manager binary is required")
	}
	if !filepath.IsAbs(mgr.Binary) {
		return SystemCommands{}, false, fmt.Errorf("manager binary must be an absolute path")
	}
	if mgr.Sudo {
		if err := RequireSudoSafe(mgr.Binary); err != nil {
			return SystemCommands{}, false, fmt.Errorf("manager %q: %w", mgr.Name, err)
		}
	}

	for _, existing := range cmds.Packages.Managers {
		if existing.Name == mgr.Name {
			return cmds, false, nil
		}
	}

	cmds.Packages.Managers = append(cmds.Packages.Managers, mgr)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func RemoveManager(paths config.Paths, name string) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	name = strings.TrimSpace(name)
	index := -1
	for i, mgr := range cmds.Packages.Managers {
		if mgr.Name == name {
			index = i
			break
		}
	}
	if index < 0 {
		return cmds, false, nil
	}

	cmds.Packages.Managers = append(cmds.Packages.Managers[:index], cmds.Packages.Managers[index+1:]...)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func AddAllowedPackage(paths config.Paths, pkg string) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return SystemCommands{}, false, fmt.Errorf("package name is required")
	}
	if slices.Contains(cmds.Packages.Allowed, pkg) {
		return cmds, false, nil
	}

	cmds.Packages.Allowed = append(cmds.Packages.Allowed, pkg)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func RemoveAllowedPackage(paths config.Paths, pkg string) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	pkg = strings.TrimSpace(pkg)
	index := slices.Index(cmds.Packages.Allowed, pkg)
	if index < 0 {
		return cmds, false, nil
	}

	cmds.Packages.Allowed = append(cmds.Packages.Allowed[:index], cmds.Packages.Allowed[index+1:]...)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func AddAllowedService(paths config.Paths, service string) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	service = strings.TrimSpace(service)
	if service == "" {
		return SystemCommands{}, false, fmt.Errorf("service name is required")
	}
	if slices.Contains(cmds.Services.Allowed, service) {
		return cmds, false, nil
	}

	cmds.Services.Allowed = append(cmds.Services.Allowed, service)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func RemoveAllowedService(paths config.Paths, service string) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	service = strings.TrimSpace(service)
	index := slices.Index(cmds.Services.Allowed, service)
	if index < 0 {
		return cmds, false, nil
	}

	cmds.Services.Allowed = append(cmds.Services.Allowed[:index], cmds.Services.Allowed[index+1:]...)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func AddAllowedApp(paths config.Paths, name string) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return SystemCommands{}, false, fmt.Errorf("app name is required")
	}
	if slices.Contains(cmds.Apps.AllowedNames, name) {
		return cmds, false, nil
	}

	cmds.Apps.AllowedNames = append(cmds.Apps.AllowedNames, name)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func RemoveAllowedApp(paths config.Paths, name string) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	name = strings.TrimSpace(name)
	index := slices.Index(cmds.Apps.AllowedNames, name)
	if index < 0 {
		return cmds, false, nil
	}

	cmds.Apps.AllowedNames = append(cmds.Apps.AllowedNames[:index], cmds.Apps.AllowedNames[index+1:]...)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func AddBuildPrefix(paths config.Paths, prefix string) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return SystemCommands{}, false, fmt.Errorf("build prefix is required")
	}
	if !filepath.IsAbs(prefix) {
		return SystemCommands{}, false, fmt.Errorf("build prefix must be an absolute path")
	}
	prefix = filepath.Clean(prefix)
	if slices.Contains(cmds.Builds.AllowedProjectPrefixes, prefix) {
		return cmds, false, nil
	}

	cmds.Builds.AllowedProjectPrefixes = append(cmds.Builds.AllowedProjectPrefixes, prefix)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func RemoveBuildPrefix(paths config.Paths, prefix string) (SystemCommands, bool, error) {
	cmds, err := LoadSystemCommandsOrDefault(paths)
	if err != nil {
		return SystemCommands{}, false, err
	}

	prefix = filepath.Clean(strings.TrimSpace(prefix))
	index := slices.Index(cmds.Builds.AllowedProjectPrefixes, prefix)
	if index < 0 {
		return cmds, false, nil
	}

	cmds.Builds.AllowedProjectPrefixes = append(cmds.Builds.AllowedProjectPrefixes[:index], cmds.Builds.AllowedProjectPrefixes[index+1:]...)
	if err := SaveDefaultSystemCommands(paths, cmds); err != nil {
		return SystemCommands{}, false, err
	}
	return normalizeSystemCommands(cmds), true, nil
}

func FindManager(cmds SystemCommands, name string) (ManagerConfig, bool) {
	for _, mgr := range cmds.Packages.Managers {
		if mgr.Name == name {
			return mgr, true
		}
	}
	return ManagerConfig{}, false
}

func AllowsPackage(cmds SystemCommands, pkg string) bool {
	if pkg == "" || len(cmds.Packages.Allowed) == 0 {
		return false
	}
	if slices.Contains(cmds.Packages.Blocked, pkg) {
		return false
	}
	return slices.Contains(cmds.Packages.Allowed, pkg)
}

func AllowsService(cmds SystemCommands, service string) bool {
	if service == "" || len(cmds.Services.Allowed) == 0 {
		return false
	}
	return slices.Contains(cmds.Services.Allowed, service)
}

func AllowsSignal(cmds SystemCommands, signal string) bool {
	if signal == "" || len(cmds.Processes.AllowedSignals) == 0 {
		return false
	}
	return slices.Contains(cmds.Processes.AllowedSignals, strings.ToUpper(signal))
}

func AllowsProcess(cmds SystemCommands, name string) bool {
	if name == "" || len(cmds.Processes.AllowedNames) == 0 {
		return false
	}
	return slices.Contains(cmds.Processes.AllowedNames, name)
}

func AllowsPort(cmds SystemCommands, port int) bool {
	if port <= 0 || len(cmds.Ports.Allowed) == 0 {
		return false
	}
	return slices.Contains(cmds.Ports.Allowed, port)
}

func AllowsAppName(cmds SystemCommands, name string) bool {
	if name == "" || len(cmds.Apps.AllowedNames) == 0 {
		return false
	}
	return slices.Contains(cmds.Apps.AllowedNames, name)
}

func AllowsAppSource(cmds SystemCommands, path string) bool {
	return AllowsFilePath(cmds.Apps.AllowedSourcePrefixes, path)
}

func AllowsAppInstallDir(cmds SystemCommands, dir string) bool {
	if dir == "" || len(cmds.Apps.AllowedInstallDirs) == 0 {
		return false
	}
	clean := filepath.Clean(dir)
	return slices.Contains(cmds.Apps.AllowedInstallDirs, clean)
}

func AllowsBuildProject(cmds SystemCommands, projectPath string) bool {
	return AllowsFilePath(cmds.Builds.AllowedProjectPrefixes, projectPath)
}

// AllowsPkgPrefix reports whether path sits under an allowed pkg prefix.
func AllowsPkgPrefix(cmds SystemCommands, path string) bool {
	return AllowsFilePath(cmds.Pkg.AllowedPrefixes, path)
}

// PkgScopeConfigured reports whether at least one install_pkg gate is set. With
// none set, install_pkg must refuse (fail closed) rather than allow any pkg.
func PkgScopeConfigured(cmds SystemCommands) bool {
	return len(cmds.Pkg.AllowedPrefixes) > 0 || cmds.Pkg.RequireRootOwned || len(cmds.Pkg.AllowedTeamIDs) > 0
}

// RequireSudoSafe rejects binaries that are writable by the current user.
// A user-writable binary with sudo is a privilege escalation path: an agent
// can modify the script, then execute it through OpenScope with root.
func RequireSudoSafe(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("sudo binary %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sudo binary %q is a symlink — resolve it to the real path", path)
	}
	// Writable by group or other is always unsafe.
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("sudo binary %q is writable by group or other (mode %o)", path, info.Mode().Perm())
	}
	// If the file is owned by the current user, they can modify it.
	stat := fileOwnerUID(info)
	if stat >= 0 && stat == os.Getuid() {
		return fmt.Errorf("sudo binary %q is owned by the current user — an agent could modify it before execution", path)
	}
	return nil
}

func AllowsFilePath(prefixes []string, path string) bool {
	if path == "" || len(prefixes) == 0 {
		return false
	}
	clean := filepath.Clean(path)
	for _, prefix := range prefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func (f SystemCommands) Validate() error {
	if f.Version == 0 {
		return fmt.Errorf("system commands version is required")
	}
	seen := map[string]struct{}{}
	for _, mgr := range f.Packages.Managers {
		if strings.TrimSpace(mgr.Name) == "" {
			return fmt.Errorf("manager name is required")
		}
		if strings.TrimSpace(mgr.Binary) == "" {
			return fmt.Errorf("manager %q binary is required", mgr.Name)
		}
		if !filepath.IsAbs(mgr.Binary) {
			return fmt.Errorf("manager %q binary must be an absolute path", mgr.Name)
		}
		if _, exists := seen[mgr.Name]; exists {
			return fmt.Errorf("manager %q is duplicated", mgr.Name)
		}
		seen[mgr.Name] = struct{}{}
	}
	for _, prefix := range f.Files.AllowedChmodPrefixes {
		if !filepath.IsAbs(prefix) {
			return fmt.Errorf("chmod prefix %q must be an absolute path", prefix)
		}
	}
	for _, prefix := range f.Files.AllowedChownPrefixes {
		if !filepath.IsAbs(prefix) {
			return fmt.Errorf("chown prefix %q must be an absolute path", prefix)
		}
	}
	for _, prefix := range f.Apps.AllowedSourcePrefixes {
		if !filepath.IsAbs(prefix) {
			return fmt.Errorf("app source prefix %q must be an absolute path", prefix)
		}
	}
	for _, dir := range f.Apps.AllowedInstallDirs {
		if !filepath.IsAbs(dir) {
			return fmt.Errorf("app install dir %q must be an absolute path", dir)
		}
	}
	for _, prefix := range f.Builds.AllowedProjectPrefixes {
		if !filepath.IsAbs(prefix) {
			return fmt.Errorf("build project prefix %q must be an absolute path", prefix)
		}
	}
	return nil
}

func normalizeSystemCommands(cmds SystemCommands) SystemCommands {
	if cmds.Version == 0 {
		cmds.Version = 1
	}
	sort.Slice(cmds.Packages.Managers, func(i, j int) bool {
		return cmds.Packages.Managers[i].Name < cmds.Packages.Managers[j].Name
	})
	cmds.Packages.Allowed = normalizeStringList(cmds.Packages.Allowed)
	cmds.Packages.Blocked = normalizeStringList(cmds.Packages.Blocked)
	cmds.Services.Allowed = normalizeStringList(cmds.Services.Allowed)
	cmds.Processes.AllowedSignals = normalizeUpperStringList(cmds.Processes.AllowedSignals)
	cmds.Processes.AllowedNames = normalizeStringList(cmds.Processes.AllowedNames)
	cmds.Ports.Allowed = normalizeIntList(cmds.Ports.Allowed)
	cmds.Files.AllowedChmodPrefixes = normalizePathList(cmds.Files.AllowedChmodPrefixes)
	cmds.Files.AllowedChownPrefixes = normalizePathList(cmds.Files.AllowedChownPrefixes)
	cmds.Apps.AllowedSourcePrefixes = normalizePathList(cmds.Apps.AllowedSourcePrefixes)
	cmds.Apps.AllowedInstallDirs = normalizePathList(cmds.Apps.AllowedInstallDirs)
	cmds.Apps.AllowedNames = normalizeStringList(cmds.Apps.AllowedNames)
	cmds.Apps.AllowedTeamIDs = normalizeUpperStringList(cmds.Apps.AllowedTeamIDs)
	cmds.Pkg.AllowedPrefixes = normalizePathList(cmds.Pkg.AllowedPrefixes)
	cmds.Pkg.AllowedTeamIDs = normalizeUpperStringList(cmds.Pkg.AllowedTeamIDs)
	cmds.Builds.AllowedProjectPrefixes = normalizePathList(cmds.Builds.AllowedProjectPrefixes)
	return cmds
}

func normalizeUpperStringList(values []string) []string {
	set := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, seen := set[value]; seen {
			continue
		}
		set[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeIntList(values []int) []int {
	set := map[int]struct{}{}
	normalized := make([]int, 0, len(values))
	for _, value := range values {
		if _, seen := set[value]; seen {
			continue
		}
		set[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Ints(normalized)
	return normalized
}
