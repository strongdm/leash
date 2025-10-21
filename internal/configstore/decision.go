package configstore

import (
	"fmt"
	"strings"
)

// GetEffectiveVolume returns the persisted decision for the given command and
// project path using the precedence rules: project > global > unset.
func (c Config) GetEffectiveVolume(cmd, projectPath string) (Decision, error) {
	if err := ensureSupportedCommand(cmd); err != nil {
		return Decision{}, err
	}

	if projectPath != "" {
		key, err := normalizeProjectKey(projectPath)
		if err != nil {
			return Decision{}, err
		}
		if project, ok := c.ProjectCommandVolumes[key]; ok {
			if decision, ok := project[cmd]; ok && decision != nil {
				return Decision{
					Enabled: *decision,
					Scope:   ScopeProject,
				}, nil
			}
		}
	}

	if decision, ok := c.CommandVolumes[cmd]; ok && decision != nil {
		return Decision{
			Enabled: *decision,
			Scope:   ScopeGlobal,
		}, nil
	}

	return Decision{
		Enabled: false,
		Scope:   ScopeUnset,
	}, nil
}

// GetTargetImage returns the configured target image and its scope for the given
// project path. Project-specific values take precedence over the global
// configuration, mirroring the mount decision precedence rules.
func (c Config) GetTargetImage(projectPath string) (string, DecisionScope, error) {
	if projectPath != "" {
		key, err := normalizeProjectKey(projectPath)
		if err != nil {
			return "", ScopeUnset, err
		}
		if image, ok := c.ProjectTargetImages[key]; ok {
			trimmed := strings.TrimSpace(image)
			if trimmed != "" {
				return trimmed, ScopeProject, nil
			}
		}
	}

	trimmed := strings.TrimSpace(c.TargetImage)
	if trimmed != "" {
		return trimmed, ScopeGlobal, nil
	}

	return "", ScopeUnset, nil
}

// ResolveEnvVars merges global and project-specific environment variables following
// the precedence rules (project > global). The resulting map is keyed by the
// environment variable name with its effective value and scope.
func (c Config) ResolveEnvVars(projectPath string) (map[string]EnvVarValue, error) {
	result := make(map[string]EnvVarValue)

	for key, value := range c.EnvVars {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		result[trimmedKey] = EnvVarValue{
			Value: value,
			Scope: ScopeGlobal,
		}
	}

	if strings.TrimSpace(projectPath) == "" {
		return result, nil
	}

	normalized, err := normalizeProjectKey(projectPath)
	if err != nil {
		return nil, err
	}

	if envs, ok := c.ProjectEnvVars[normalized]; ok {
		for key, value := range envs {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				continue
			}
			result[trimmedKey] = EnvVarValue{
				Value: value,
				Scope: ScopeProject,
			}
		}
	}

	return result, nil
}

// SetGlobalVolume persists the global decision for a command.
func (c *Config) SetGlobalVolume(cmd string, enabled bool) error {
	if err := ensureSupportedCommand(cmd); err != nil {
		return err
	}
	if c.CommandVolumes == nil {
		c.CommandVolumes = make(map[string]*bool)
	}
	c.CommandVolumes[cmd] = boolPtr(enabled)
	return nil
}

// SetProjectVolume sets the project-scoped decision for a command.
func (c *Config) SetProjectVolume(projectPath, cmd string, enabled bool) error {
	if err := ensureSupportedCommand(cmd); err != nil {
		return err
	}
	key, err := normalizeProjectKey(projectPath)
	if err != nil {
		return err
	}
	if c.ProjectCommandVolumes == nil {
		c.ProjectCommandVolumes = make(map[string]map[string]*bool)
	}
	settings := c.ProjectCommandVolumes[key]
	if settings == nil {
		settings = make(map[string]*bool)
	}
	settings[cmd] = boolPtr(enabled)
	c.ProjectCommandVolumes[key] = settings
	return nil
}

// UnsetProjectVolume removes the project-scoped decision for a command.
func (c *Config) UnsetProjectVolume(projectPath, cmd string) error {
	if err := ensureSupportedCommand(cmd); err != nil {
		return err
	}
	key, err := normalizeProjectKey(projectPath)
	if err != nil {
		return err
	}
	settings, ok := c.ProjectCommandVolumes[key]
	if !ok || settings == nil {
		return nil
	}
	delete(settings, cmd)
	if len(settings) == 0 {
		delete(c.ProjectCommandVolumes, key)
		return nil
	}
	c.ProjectCommandVolumes[key] = settings
	return nil
}

func ensureSupportedCommand(cmd string) error {
	if _, ok := supportedCommands[cmd]; !ok {
		return fmt.Errorf("unsupported command %q", cmd)
	}
	return nil
}
