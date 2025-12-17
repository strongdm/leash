package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveHomeDir evaluates HOME-style environment variables on each call to
// avoid relying on os.UserHomeDir's cached value, which can be stale in tests
// that mutate the process environment.
func resolveHomeDir() (string, error) {
	home := strings.TrimSpace(os.Getenv("HOME"))
	if home == "" {
		drive := strings.TrimSpace(os.Getenv("HOMEDRIVE"))
		path := strings.TrimSpace(os.Getenv("HOMEPATH"))
		if drive != "" && path != "" {
			home = filepath.Join(drive, path)
		} else {
			home = strings.TrimSpace(os.Getenv("USERPROFILE"))
		}
	}
	if home != "" {
		return filepath.Clean(home), nil
	}

	resolved, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(resolved) == "" {
		if err == nil {
			err = fmt.Errorf("home directory not found")
		}
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Clean(resolved), nil
}
