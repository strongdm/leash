package configstore

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Mount describes a bind mount to apply when launching containers.
type Mount struct {
	Name      string
	Host      string
	Container string
	Mode      string
	Scope     DecisionScope
	Persisted bool
	Kind      MountKind
}

// MountKind distinguishes between directory and file mounts.
type MountKind int

const (
	// MountKindDirectory indicates the host path is a directory.
	MountKindDirectory MountKind = iota
	// MountKindFile indicates the host path is a file.
	MountKindFile
	// MountKindUnknown defers to runtime inspection.
	MountKindUnknown
)

// ComputeExtraMountsFor converts a prompt outcome into mount definitions, ensuring
// the host directory still exists and returning read-write container targets.
func ComputeExtraMountsFor(cmd string, outcome PromptOutcome, statFn func(string) (os.FileInfo, error)) ([]Mount, error) {
	if !outcome.Mount {
		return nil, nil
	}
	if err := ensureSupportedCommand(cmd); err != nil {
		return nil, err
	}
	if strings.TrimSpace(outcome.HostDir) == "" {
		return nil, fmt.Errorf("host directory not provided for %s", cmd)
	}

	check := statFn
	if check == nil {
		check = os.Stat
	}

	if cmd == "opencode" {
		return computeOpencodeMounts(outcome, check)
	}

	info, err := check(outcome.HostDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("check host dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("host path %s must be a directory", outcome.HostDir)
	}

	host := filepath.Clean(outcome.HostDir)
	container := fmt.Sprintf("/root/.%s", cmd)
	mounts := []Mount{{
		Name:      cmd,
		Host:      host,
		Container: container,
		Mode:      "rw",
		Scope:     outcome.Scope,
		Persisted: outcome.Persisted,
		Kind:      MountKindDirectory,
	}}

	if cmd == "claude" {
		// Claude-specific: include ~/.claude.json alongside ~/.claude.
		configPath := filepath.Join(filepath.Dir(host), ".claude.json")
		info, err := check(configPath)
		switch {
		case err == nil:
			if info.IsDir() {
				return nil, fmt.Errorf("expected file for %s, found directory", configPath)
			}
			mounts = append(mounts, Mount{
				Name:      cmd + "-config",
				Host:      filepath.Clean(configPath),
				Container: "/root/.claude.json",
				Mode:      "rw",
				Scope:     outcome.Scope,
				Persisted: outcome.Persisted,
				Kind:      MountKindFile,
			})
		case os.IsNotExist(err):
			// Optional file; skip if absent.
		case err != nil:
			return nil, fmt.Errorf("check claude config file: %w", err)
		}
	}

	return mounts, nil
}

func computeOpencodeMounts(outcome PromptOutcome, statFn func(string) (os.FileInfo, error)) ([]Mount, error) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		if err == nil {
			err = fmt.Errorf("home directory not found")
		}
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}

	paths := opencodePaths(home)
	dataRoot := paths.dataDir

	type candidate struct {
		name      string
		host      string
		container string
		kind      MountKind
	}

	candidates := []candidate{
		{name: "opencode-config", host: paths.configDir, container: "/root/.config/opencode", kind: MountKindDirectory},
		{name: "opencode-state", host: paths.stateDir, container: "/root/.local/state/opencode", kind: MountKindDirectory},
		{name: "opencode-auth", host: filepath.Join(dataRoot, "auth.json"), container: "/root/.local/share/opencode/auth.json", kind: MountKindFile},
		{name: "opencode-log", host: filepath.Join(dataRoot, "log"), container: "/root/.local/share/opencode/log", kind: MountKindDirectory},
		{name: "opencode-snapshot", host: filepath.Join(dataRoot, "snapshot"), container: "/root/.local/share/opencode/snapshot", kind: MountKindDirectory},
		{name: "opencode-storage", host: filepath.Join(dataRoot, "storage"), container: "/root/.local/share/opencode/storage", kind: MountKindDirectory},
		{name: "opencode-legacy", host: paths.legacyDir, container: "/root/.opencode", kind: MountKindDirectory},
	}

	check := statFn
	if check == nil {
		check = os.Stat
	}

	seen := make(map[string]struct{})
	mounts := make([]Mount, 0, len(candidates))

	for _, c := range candidates {
		trimmedHost := strings.TrimSpace(c.host)
		if trimmedHost == "" {
			continue
		}
		info, err := check(trimmedHost)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("check opencode path %s: %w", trimmedHost, err)
		}
		switch c.kind {
		case MountKindDirectory:
			if !info.IsDir() {
				return nil, fmt.Errorf("expected directory for %s", trimmedHost)
			}
		case MountKindFile:
			if info.IsDir() {
				return nil, fmt.Errorf("expected file for %s", trimmedHost)
			}
		}

		key := trimmedHost + "->" + c.container
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		mounts = append(mounts, Mount{
			Name:      c.name,
			Host:      filepath.Clean(trimmedHost),
			Container: c.container,
			Mode:      "rw",
			Scope:     outcome.Scope,
			Persisted: outcome.Persisted,
			Kind:      c.kind,
		})
	}

	return mounts, nil
}

// ResolveCustomVolumes produces bind mount definitions declared via configuration for
// the provided project path. Project-specific definitions override global entries
// with the same identifier. When a project explicitly sets an identifier to false
// the corresponding global mount is suppressed.
func (c Config) ResolveCustomVolumes(projectPath, cwd string) ([]Mount, error) {
	c.ensureInitialized()

	type mountDef struct {
		spec  string
		scope DecisionScope
	}

	resolved := make(map[string]mountDef)
	disableCandidates := make(map[string]struct{})
	for id, spec := range c.CustomVolumes {
		trimmed := strings.TrimSpace(spec)
		if trimmed == "" {
			continue
		}
		resolved[id] = mountDef{spec: trimmed, scope: ScopeGlobal}
	}

	var projectBase string
	if strings.TrimSpace(projectPath) != "" {
		key, err := normalizeProjectKey(projectPath)
		if err != nil {
			return nil, err
		}
		projectBase = key

		if toggles, ok := c.ProjectVolumeDisables[key]; ok {
			for id := range toggles {
				delete(resolved, id)
				disableCandidates[id] = struct{}{}
			}
		}
		if specs, ok := c.ProjectCustomVolumes[key]; ok {
			for id, spec := range specs {
				trimmed := strings.TrimSpace(spec)
				if trimmed == "" {
					delete(resolved, id)
					continue
				}
				resolved[id] = mountDef{spec: trimmed, scope: ScopeProject}
			}
		}
	}

	if len(resolved) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(resolved))
	for id := range resolved {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	disabled := make(map[string]struct{})
	if projectBase != "" && len(disableCandidates) > 0 {
		for raw := range disableCandidates {
			resolvedHost, err := resolveVolumeHost(raw, projectBase)
			if err != nil {
				return nil, fmt.Errorf("resolve host for disabled volume %q: %w", raw, err)
			}
			disabled[filepath.Clean(resolvedHost)] = struct{}{}
		}
	}

	mounts := make([]Mount, 0, len(ids))

	for _, hostKey := range ids {
		def := resolved[hostKey]
		containerSpec, mode, err := parseVolumeSpec(def.spec)
		if err != nil {
			return nil, fmt.Errorf("parse custom volume %q: %w", hostKey, err)
		}

		base := cwd
		if def.scope == ScopeProject && projectBase != "" {
			base = projectBase
		}

		hostPath, err := resolveVolumeHost(hostKey, base)
		if err != nil {
			return nil, fmt.Errorf("resolve host for volume %q: %w", hostKey, err)
		}
		hostPath = filepath.Clean(hostPath)
		if _, skip := disabled[hostPath]; skip {
			continue
		}

		if !strings.HasPrefix(containerSpec, "/") {
			return nil, fmt.Errorf("custom volume %q target must be an absolute container path", hostKey)
		}

		mounts = append(mounts, Mount{
			Name:      hostKey,
			Host:      hostPath,
			Container: path.Clean(containerSpec),
			Mode:      mode,
			Scope:     def.scope,
			Persisted: true,
			Kind:      MountKindUnknown,
		})
	}

	return mounts, nil
}

func parseVolumeSpec(spec string) (string, string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return "", "", fmt.Errorf("volume specification cannot be empty")
	}

	container := trimmed
	mode := "rw"
	if tgt, modePart, ok := strings.Cut(trimmed, ":"); ok {
		container = strings.TrimSpace(tgt)
		candidate := strings.TrimSpace(modePart)
		if candidate != "" {
			mode = candidate
		}
	}
	if container == "" {
		return "", "", fmt.Errorf("volume target cannot be empty")
	}
	if strings.ContainsAny(mode, " \t\n") {
		return "", "", fmt.Errorf("volume mode must not contain whitespace")
	}

	return container, mode, nil
}

func resolveVolumeHost(raw, base string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("host path cannot be empty")
	}
	expanded := os.ExpandEnv(trimmed)
	expanded, err := expandLeadingTilde(expanded)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(expanded) {
		return filepath.Clean(expanded), nil
	}
	if base == "" {
		return "", fmt.Errorf("host path %q must be absolute or start with '~'", raw)
	}
	return filepath.Clean(filepath.Join(base, expanded)), nil
}
