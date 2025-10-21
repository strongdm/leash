package configstore

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Config represents the persisted leash configuration.
type Config struct {
	CommandVolumes        map[string]*bool            `toml:"-"`
	ProjectCommandVolumes map[string]map[string]*bool `toml:"-"`
	CustomVolumes         map[string]string           `toml:"-"`
	ProjectCustomVolumes  map[string]map[string]string
	ProjectVolumeDisables map[string]map[string]bool
	TargetImage           string
	ProjectTargetImages   map[string]string
	EnvVars               map[string]string
	ProjectEnvVars        map[string]map[string]string
}

// DecisionScope models the precedence layer that yielded an effective choice.
type DecisionScope string

const (
	ScopeUnset     DecisionScope = "unset"
	ScopeGlobal    DecisionScope = "global"
	ScopeProject   DecisionScope = "project"
	ScopeEphemeral DecisionScope = "ephemeral"
)

// Decision represents the effective state for a command after applying the
// precedence rules.
type Decision struct {
	Enabled bool
	Scope   DecisionScope
}

// EnvVarValue captures the effective value and scope for an environment variable.
type EnvVarValue struct {
	Value string
	Scope DecisionScope
}

// New returns a Config with initialized maps. Callers that mutate the
// configuration should always start from this constructor to avoid nil maps.
func New() Config {
	return Config{
		CommandVolumes:        make(map[string]*bool),
		ProjectCommandVolumes: make(map[string]map[string]*bool),
		CustomVolumes:         make(map[string]string),
		ProjectCustomVolumes:  make(map[string]map[string]string),
		ProjectVolumeDisables: make(map[string]map[string]bool),
		ProjectTargetImages:   make(map[string]string),
		EnvVars:               make(map[string]string),
		ProjectEnvVars:        make(map[string]map[string]string),
	}
}

// Clone produces a deep copy suitable for mutation without affecting the
// original instance.
func (c Config) Clone() Config {
	out := New()
	for cmd, value := range c.CommandVolumes {
		if value == nil {
			continue
		}
		out.CommandVolumes[cmd] = boolPtr(*value)
	}
	for host, spec := range c.CustomVolumes {
		out.CustomVolumes[host] = spec
	}
	for projectPath, settings := range c.ProjectCommandVolumes {
		if settings == nil {
			out.ProjectCommandVolumes[projectPath] = make(map[string]*bool)
			continue
		}
		dst := make(map[string]*bool, len(settings))
		for cmd, value := range settings {
			if value == nil {
				continue
			}
			dst[cmd] = boolPtr(*value)
		}
		out.ProjectCommandVolumes[projectPath] = dst
	}
	for projectPath, specs := range c.ProjectCustomVolumes {
		if specs == nil {
			out.ProjectCustomVolumes[projectPath] = make(map[string]string)
			continue
		}
		dst := make(map[string]string, len(specs))
		for key, value := range specs {
			dst[key] = value
		}
		out.ProjectCustomVolumes[projectPath] = dst
	}
	for projectPath, disables := range c.ProjectVolumeDisables {
		if disables == nil {
			out.ProjectVolumeDisables[projectPath] = make(map[string]bool)
			continue
		}
		dst := make(map[string]bool, len(disables))
		for key, value := range disables {
			dst[key] = value
		}
		out.ProjectVolumeDisables[projectPath] = dst
	}
	for projectPath, image := range c.ProjectTargetImages {
		out.ProjectTargetImages[projectPath] = image
	}
	for key, value := range c.EnvVars {
		out.EnvVars[key] = value
	}
	for projectPath, envs := range c.ProjectEnvVars {
		if envs == nil {
			out.ProjectEnvVars[projectPath] = make(map[string]string)
			continue
		}
		dst := make(map[string]string, len(envs))
		for key, value := range envs {
			dst[key] = value
		}
		out.ProjectEnvVars[projectPath] = dst
	}
	out.TargetImage = c.TargetImage
	return out
}

// normalizeProjectKey resolves the absolute path for use as a project key.
func normalizeProjectKey(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("project path must not be empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("abs project path: %w", err)
	}
	normalized, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// If the path does not exist yet, fall back to cleaned absolute path.
		if os.IsNotExist(err) {
			return filepath.Clean(abs), nil
		}
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return filepath.Clean(normalized), nil
}

func expandProjectSpecifier(spec string) (string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return "", fmt.Errorf("project key must not be empty")
	}
	expanded := os.ExpandEnv(trimmed)
	return expandLeadingTilde(expanded)
}

func expandLeadingTilde(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return path, nil
	}

	if len(path) == 1 || isPathSeparator(path[1]) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		if len(path) == 1 {
			return home, nil
		}
		return filepath.Join(home, strings.TrimLeft(path[2:], "/\\")), nil
	}

	sep := strings.IndexAny(path, "/\\")
	var username, rest string
	if sep == -1 {
		username = path[1:]
		rest = ""
	} else {
		username = path[1:sep]
		rest = path[sep:]
	}
	if username == "" {
		return path, nil
	}
	account, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("lookup home for %s: %w", username, err)
	}
	trimmed := strings.TrimLeft(rest, "/\\")
	if trimmed == "" {
		return account.HomeDir, nil
	}
	return filepath.Join(account.HomeDir, trimmed), nil
}

func isPathSeparator(r byte) bool {
	return r == '/' || r == '\\'
}

func resolveConfigProjectKey(spec string) (string, error) {
	expanded, err := expandProjectSpecifier(spec)
	if err != nil {
		return "", err
	}
	return normalizeProjectKey(expanded)
}

func (c *Config) ensureInitialized() {
	if c.CommandVolumes == nil {
		c.CommandVolumes = make(map[string]*bool)
	}
	if c.ProjectCommandVolumes == nil {
		c.ProjectCommandVolumes = make(map[string]map[string]*bool)
	}
	if c.CustomVolumes == nil {
		c.CustomVolumes = make(map[string]string)
	}
	if c.ProjectCustomVolumes == nil {
		c.ProjectCustomVolumes = make(map[string]map[string]string)
	}
	if c.ProjectVolumeDisables == nil {
		c.ProjectVolumeDisables = make(map[string]map[string]bool)
	}
	for key, settings := range c.ProjectCommandVolumes {
		if settings == nil {
			c.ProjectCommandVolumes[key] = make(map[string]*bool)
		}
	}
	for key, specs := range c.ProjectCustomVolumes {
		if specs == nil {
			c.ProjectCustomVolumes[key] = make(map[string]string)
		}
	}
	for key, disables := range c.ProjectVolumeDisables {
		if disables == nil {
			c.ProjectVolumeDisables[key] = make(map[string]bool)
		}
	}
	if c.ProjectTargetImages == nil {
		c.ProjectTargetImages = make(map[string]string)
	}
	if c.EnvVars == nil {
		c.EnvVars = make(map[string]string)
	}
	if c.ProjectEnvVars == nil {
		c.ProjectEnvVars = make(map[string]map[string]string)
	}
	for key, envs := range c.ProjectEnvVars {
		if envs == nil {
			c.ProjectEnvVars[key] = make(map[string]string)
		}
	}
}

func boolPtr(v bool) *bool {
	b := v
	return &b
}

// SetGlobalTargetImage records the default container image for leash-managed sessions.
func (c *Config) SetGlobalTargetImage(image string) {
	c.TargetImage = strings.TrimSpace(image)
}

// SetProjectTargetImage associates a target image with the given project path.
// Passing an empty image removes the override.
func (c *Config) SetProjectTargetImage(projectPath, image string) error {
	key, err := normalizeProjectKey(projectPath)
	if err != nil {
		return err
	}
	c.ensureInitialized()
	trimmed := strings.TrimSpace(image)
	if trimmed == "" {
		delete(c.ProjectTargetImages, key)
		return nil
	}
	c.ProjectTargetImages[key] = trimmed
	return nil
}

// UnsetProjectTargetImage removes any project-specific image override.
func (c *Config) UnsetProjectTargetImage(projectPath string) error {
	key, err := normalizeProjectKey(projectPath)
	if err != nil {
		return err
	}
	if c.ProjectTargetImages == nil {
		return nil
	}
	delete(c.ProjectTargetImages, key)
	return nil
}

// SetGlobalEnvVar records a global environment variable to be injected into leash-managed containers.
// An empty value is permitted and results in KEY= being emitted.
func (c *Config) SetGlobalEnvVar(key, value string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("environment variable key must not be empty")
	}
	c.ensureInitialized()
	c.EnvVars[key] = value
	return nil
}

// UnsetGlobalEnvVar removes a global environment variable override.
func (c *Config) UnsetGlobalEnvVar(key string) {
	if c.EnvVars == nil {
		return
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	delete(c.EnvVars, key)
}

// SetProjectEnvVar assigns a project-scoped environment variable override. The project path is normalized
// to ensure consistent keys regardless of symlinks or relative inputs.
func (c *Config) SetProjectEnvVar(projectPath, key, value string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("environment variable key must not be empty")
	}
	projectKey, err := normalizeProjectKey(projectPath)
	if err != nil {
		return err
	}
	c.ensureInitialized()
	envs := c.ProjectEnvVars[projectKey]
	if envs == nil {
		envs = make(map[string]string)
	}
	envs[key] = value
	c.ProjectEnvVars[projectKey] = envs
	return nil
}

// UnsetProjectEnvVar removes a project-specific environment variable override.
func (c *Config) UnsetProjectEnvVar(projectPath, key string) error {
	if c.ProjectEnvVars == nil {
		return nil
	}
	projectKey, err := normalizeProjectKey(projectPath)
	if err != nil {
		return err
	}
	envs, ok := c.ProjectEnvVars[projectKey]
	if !ok || envs == nil {
		return nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	delete(envs, key)
	if len(envs) == 0 {
		delete(c.ProjectEnvVars, projectKey)
		return nil
	}
	c.ProjectEnvVars[projectKey] = envs
	return nil
}
