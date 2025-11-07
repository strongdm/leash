package configstore

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// ParseError represents a TOML decode failure.
type ParseError struct {
	Path string
	Err  error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("parse config %s: %v", e.Path, e.Err)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

// Load reads the persisted config from disk. Missing files result in an empty
// configuration with defaults.
func Load() (Config, error) {
	cfg := New()
	_, file, err := GetConfigPath()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := decodeConfig(data, file, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func decodeConfig(data []byte, path string, cfg *Config) error {
	cfg.ensureInitialized()

	var raw map[string]any
	err := toml.Unmarshal(data, &raw)
	if err != nil && needsDollarEscapeFix(err) {
		if fixed, changed := sanitizeDollarEscapes(data); changed {
			data = fixed
			err = toml.Unmarshal(data, &raw)
		}
	}
	if err != nil {
		var decodeErr *toml.DecodeError
		if errors.As(err, &decodeErr) {
			return &ParseError{Path: path, Err: decodeErr}
		}
		return err
	}

	parseGlobalVolumeTable := func(table map[string]any) error {
		for key, value := range table {
			if _, supported := supportedCommands[key]; supported {
				boolVal, err := toBool(value)
				if err != nil {
					return fmt.Errorf("parse volumes.%s: %w", key, err)
				}
				cfg.CommandVolumes[key] = boolPtr(boolVal)
				continue
			}
			spec, err := toString(value)
			if err != nil {
				return fmt.Errorf("parse volumes.%s: expected string specification; %w", key, err)
			}
			trimmed := strings.TrimSpace(spec)
			if trimmed == "" {
				return fmt.Errorf("parse volumes.%s: volume specification cannot be empty", key)
			}
			cfg.CustomVolumes[key] = trimmed
		}
		return nil
	}

	if volumes, ok := raw["volumes"].(map[string]any); ok {
		if err := parseGlobalVolumeTable(volumes); err != nil {
			return err
		}
	}

	if secrets, ok := raw["secrets"].(map[string]any); ok {
		for key, value := range secrets {
			strVal, err := toString(value)
			if err != nil {
				return fmt.Errorf("parse secrets.%s: %w", key, err)
			}
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				continue
			}
			cfg.Secrets[trimmedKey] = expandConfigValue(strVal)
		}
	}

	if projects, ok := raw["projects"].(map[string]any); ok {
		for projectKey, rawValue := range projects {
			projectTable, ok := rawValue.(map[string]any)
			if !ok {
				continue
			}
			normalizedKey, err := resolveConfigProjectKey(projectKey)
			if err != nil {
				return fmt.Errorf("parse projects.%s: %w", projectKey, err)
			}
			commandToggles := make(map[string]*bool)
			envVars := make(map[string]string)
			customVolumes := make(map[string]string)
			volumeDisables := make(map[string]bool)
			projectSecrets := make(map[string]string)

			for key, value := range projectTable {
				switch key {
				case "mounts":
					return fmt.Errorf("parse projects.%s.mounts: legacy table is no longer supported; use 'volumes'", projectKey)
				case "volumes":
					mountTable, ok := value.(map[string]any)
					if !ok {
						return fmt.Errorf("parse projects.%s.volumes: expected table", projectKey)
					}
					for cmd, mountValue := range mountTable {
						if _, supported := supportedCommands[cmd]; supported {
							boolVal, err := toBool(mountValue)
							if err != nil {
								return fmt.Errorf("parse projects.%s.volumes.%s: %w", projectKey, cmd, err)
							}
							commandToggles[cmd] = boolPtr(boolVal)
							continue
						}
						switch mv := mountValue.(type) {
						case string:
							trimmed := strings.TrimSpace(mv)
							if trimmed == "" {
								return fmt.Errorf("parse projects.%s.volumes.%s: volume specification cannot be empty", projectKey, cmd)
							}
							customVolumes[cmd] = trimmed
						case bool:
							if mv {
								return fmt.Errorf("parse projects.%s.volumes.%s: boolean true is not supported; provide a volume specification", projectKey, cmd)
							}
							volumeDisables[cmd] = true
						default:
							return fmt.Errorf("parse projects.%s.volumes.%s: expected string or boolean, got %T", projectKey, cmd, mountValue)
						}
					}
					continue
				case "target_image":
					if s, ok := value.(string); ok {
						cfg.ProjectTargetImages[normalizedKey] = strings.TrimSpace(s)
					}
				case "envvars":
					envTable, ok := value.(map[string]any)
					if !ok {
						return fmt.Errorf("parse projects.%s.envvars: expected table", projectKey)
					}
					for envKey, rawVal := range envTable {
						strVal, err := toString(rawVal)
						if err != nil {
							return fmt.Errorf("parse projects.%s.envvars.%s: %w", projectKey, envKey, err)
						}
						trimmedKey := strings.TrimSpace(envKey)
						if trimmedKey == "" {
							continue
						}
						envVars[trimmedKey] = strVal
					}
				case "secrets":
					secretTable, ok := value.(map[string]any)
					if !ok {
						return fmt.Errorf("parse projects.%s.secrets: expected table", projectKey)
					}
					for secretKey, rawVal := range secretTable {
						strVal, err := toString(rawVal)
						if err != nil {
							return fmt.Errorf("parse projects.%s.secrets.%s: %w", projectKey, secretKey, err)
						}
						trimmedKey := strings.TrimSpace(secretKey)
						if trimmedKey == "" {
							continue
						}
						projectSecrets[trimmedKey] = expandConfigValue(strVal)
					}
				default:
					if _, supported := supportedCommands[key]; supported {
						boolVal, err := toBool(value)
						if err != nil {
							return fmt.Errorf("parse projects.%s.%s: %w", projectKey, key, err)
						}
						commandToggles[key] = boolPtr(boolVal)
						continue
					}
					switch v := value.(type) {
					case string:
						trimmed := strings.TrimSpace(v)
						if trimmed == "" {
							return fmt.Errorf("parse projects.%s.%s: volume specification cannot be empty", projectKey, key)
						}
						customVolumes[key] = trimmed
					case bool:
						if v {
							return fmt.Errorf("parse projects.%s.%s: boolean true is not supported; provide a volume specification", projectKey, key)
						}
						volumeDisables[key] = true
					case map[string]any:
						if len(v) == 0 {
							// Ignore empty tables so users can comment out sections without errors.
							continue
						}
						return fmt.Errorf("parse projects.%s.%s: unexpected table", projectKey, key)
					default:
						return fmt.Errorf("parse projects.%s.%s: expected string or boolean, got %T", projectKey, key, value)
					}
				}
			}

			if len(commandToggles) > 0 {
				cfg.ProjectCommandVolumes[normalizedKey] = commandToggles
			} else if _, ok := cfg.ProjectTargetImages[normalizedKey]; ok {
				cfg.ProjectCommandVolumes[normalizedKey] = make(map[string]*bool)
			}
			if len(envVars) > 0 {
				cfg.ProjectEnvVars[normalizedKey] = envVars
			}
			if len(customVolumes) > 0 {
				cfg.ProjectCustomVolumes[normalizedKey] = customVolumes
			}
			if len(volumeDisables) > 0 {
				cfg.ProjectVolumeDisables[normalizedKey] = volumeDisables
			}
			if len(projectSecrets) > 0 {
				cfg.ProjectSecrets[normalizedKey] = projectSecrets
			}
		}
	}

	if leash, ok := raw["leash"].(map[string]any); ok {
		if target, ok := leash["target_image"].(string); ok {
			cfg.TargetImage = strings.TrimSpace(target)
		}
		if envTable, ok := leash["envvars"].(map[string]any); ok {
			for key, rawVal := range envTable {
				strVal, err := toString(rawVal)
				if err != nil {
					return fmt.Errorf("parse leash.envvars.%s: %w", key, err)
				}
				trimmedKey := strings.TrimSpace(key)
				if trimmedKey == "" {
					continue
				}
				cfg.EnvVars[trimmedKey] = strVal
			}
		}
	}

	cfg.ensureInitialized()
	return nil
}

// Save atomically writes the configuration to disk.
func Save(cfg Config) error {
	cfg.ensureInitialized()

	dir, file, err := GetConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleaned := false
	defer func() {
		if !cleaned {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}

	out := buildPersisted(cfg)
	encoder := toml.NewEncoder(tmp)
	if err := encoder.Encode(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}

	if err := os.Rename(tmpName, file); err != nil {
		return fmt.Errorf("rename temp config: %w", err)
	}
	cleaned = true
	return nil
}

type persistedConfig struct {
	Volumes  map[string]any            `toml:"volumes,omitempty"`
	Secrets  map[string]string         `toml:"secrets,omitempty"`
	Projects map[string]map[string]any `toml:"projects,omitempty"`
	Leash    map[string]any            `toml:"leash,omitempty"`
}

func buildPersisted(cfg Config) persistedConfig {
	result := persistedConfig{
		Volumes:  nil,
		Projects: nil,
		Leash:    nil,
	}

	if len(cfg.CommandVolumes) > 0 || len(cfg.CustomVolumes) > 0 {
		volumes := make(map[string]any)
		for cmd, value := range cfg.CommandVolumes {
			if value == nil {
				continue
			}
			volumes[cmd] = *value
		}
		for host, spec := range cfg.CustomVolumes {
			trimmed := strings.TrimSpace(spec)
			if trimmed == "" {
				continue
			}
			volumes[host] = trimmed
		}
		if len(volumes) > 0 {
			result.Volumes = volumes
		}
	}

	if len(cfg.Secrets) > 0 {
		secrets := make(map[string]string, len(cfg.Secrets))
		for key, value := range cfg.Secrets {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				continue
			}
			secrets[trimmedKey] = value
		}
		if len(secrets) > 0 {
			result.Secrets = secrets
		}
	}

	projectKeys := make(map[string]struct{})
	for key := range cfg.ProjectCommandVolumes {
		projectKeys[key] = struct{}{}
	}
	for key := range cfg.ProjectCustomVolumes {
		projectKeys[key] = struct{}{}
	}
	for key := range cfg.ProjectVolumeDisables {
		projectKeys[key] = struct{}{}
	}
	for key := range cfg.ProjectTargetImages {
		projectKeys[key] = struct{}{}
	}
	for key := range cfg.ProjectEnvVars {
		projectKeys[key] = struct{}{}
	}
	for key := range cfg.ProjectSecrets {
		projectKeys[key] = struct{}{}
	}

	if len(projectKeys) > 0 {
		projects := make(map[string]map[string]any, len(projectKeys))
		for key := range projectKeys {
			entry := make(map[string]any)
			volumeEntries := make(map[string]any)
			if mounts, ok := cfg.ProjectCommandVolumes[key]; ok && mounts != nil {
				for cmd, value := range mounts {
					if value == nil {
						continue
					}
					entry[cmd] = *value
				}
			}
			if customSpecs, ok := cfg.ProjectCustomVolumes[key]; ok && len(customSpecs) > 0 {
				for id, spec := range customSpecs {
					trimmed := strings.TrimSpace(spec)
					if trimmed == "" {
						continue
					}
					volumeEntries[id] = trimmed
				}
			}
			if disables, ok := cfg.ProjectVolumeDisables[key]; ok && len(disables) > 0 {
				for id := range disables {
					volumeEntries[id] = false
				}
			}
			if envs, ok := cfg.ProjectEnvVars[key]; ok && len(envs) > 0 {
				envCopy := make(map[string]string, len(envs))
				for envKey, value := range envs {
					trimmedKey := strings.TrimSpace(envKey)
					if trimmedKey == "" {
						continue
					}
					envCopy[trimmedKey] = value
				}
				if len(envCopy) > 0 {
					entry["envvars"] = envCopy
				}
			}
			if secrets, ok := cfg.ProjectSecrets[key]; ok && len(secrets) > 0 {
				secretCopy := make(map[string]string, len(secrets))
				for secretKey, value := range secrets {
					trimmedKey := strings.TrimSpace(secretKey)
					if trimmedKey == "" {
						continue
					}
					secretCopy[trimmedKey] = value
				}
				if len(secretCopy) > 0 {
					entry["secrets"] = secretCopy
				}
			}
			if img := strings.TrimSpace(cfg.ProjectTargetImages[key]); img != "" {
				entry["target_image"] = img
			}
			if len(volumeEntries) > 0 {
				entry["volumes"] = volumeEntries
			}
			if len(entry) > 0 {
				projects[key] = entry
			}
		}
		if len(projects) > 0 {
			result.Projects = projects
		}
	}

	if img := strings.TrimSpace(cfg.TargetImage); img != "" {
		if result.Leash == nil {
			result.Leash = make(map[string]any)
		}
		result.Leash["target_image"] = img
	}

	if len(cfg.EnvVars) > 0 {
		envCopy := make(map[string]string, len(cfg.EnvVars))
		for key, value := range cfg.EnvVars {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				continue
			}
			envCopy[trimmedKey] = value
		}
		if len(envCopy) > 0 {
			if result.Leash == nil {
				result.Leash = make(map[string]any)
			}
			result.Leash["envvars"] = envCopy
		}
	}

	return result
}

func toBool(value any) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case *bool:
		if v == nil {
			return false, fmt.Errorf("unexpected nil bool pointer")
		}
		return *v, nil
	default:
		return false, fmt.Errorf("expected boolean, got %T", value)
	}
}

func toString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	default:
		return "", fmt.Errorf("expected string, got %T", value)
	}
}
