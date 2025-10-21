package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const configFileName = "config.toml"

// GetConfigPath resolves the leash configuration directory and file path using
// XDG rules with a fallback to ~/.config/leash/config.toml.
func GetConfigPath() (string, string, error) {
	if override := strings.TrimSpace(os.Getenv("LEASH_HOME")); override != "" {
		dir := filepath.Clean(override)
		if !filepath.IsAbs(dir) {
			abs, err := filepath.Abs(dir)
			if err != nil {
				return "", "", fmt.Errorf("resolve LEASH_HOME %q: %w", override, err)
			}
			dir = abs
		}
		return dir, filepath.Join(dir, configFileName), nil
	}

	base := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if base != "" {
		dir := buildConfigDir(base)
		return dir, filepath.Join(dir, configFileName), nil
	}

	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		if err == nil {
			err = fmt.Errorf("home directory not found")
		}
		return "", "", fmt.Errorf("resolve home dir: %w", err)
	}
	base = filepath.Join(home, ".config")
	dir := buildConfigDir(base)
	return dir, filepath.Join(dir, configFileName), nil
}

func buildConfigDir(base string) string {
	return filepath.Join(base, "leash")
}
