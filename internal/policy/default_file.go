package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// EnsureDefaultCedarFile makes sure the policy file exists with default contents,
// creating parent directories and writing the baseline policy when missing.
func EnsureDefaultCedarFile(policyPath string) error {
	cleaned := strings.TrimSpace(policyPath)
	if cleaned == "" {
		return fmt.Errorf("Cedar policy file path required")
	}

	dir := filepath.Dir(cleaned)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create Cedar policy directory %q: %w", dir, err)
		}
	}

	if _, err := os.Stat(cleaned); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			content := strings.TrimSpace(DefaultCedar()) + "\n"
			if err := os.WriteFile(cleaned, []byte(content), 0o644); err != nil {
				return fmt.Errorf("write default Cedar policy to %q: %w", cleaned, err)
			}
			return nil
		}
		return fmt.Errorf("check Cedar policy file %q: %w", cleaned, err)
	}
	return nil
}
