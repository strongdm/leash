package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const configFileName = "config.toml"

// LocalConfigFileName is the name of the project-local override file that
// users can place in their working directory to layer additional configuration
// (e.g. secrets) on top of the global XDG config.
const LocalConfigFileName = ".leash.toml"

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

	home, err := resolveHomeDir()
	if err != nil {
		return "", "", err
	}
	base = filepath.Join(home, ".config")
	dir := buildConfigDir(base)
	return dir, filepath.Join(dir, configFileName), nil
}

// GetLocalConfigPath returns the path to the project-local override file
// within the given directory.
func GetLocalConfigPath(dir string) string {
	return filepath.Join(dir, LocalConfigFileName)
}

func buildConfigDir(base string) string {
	return filepath.Join(base, "leash")
}
