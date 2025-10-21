//go:build darwin

package runner

import (
	"fmt"
	"os/exec"
	"strings"
)

// readClaudeKeychainCredentials attempts to read Claude Code credentials from the macOS keychain.
// Returns the JSON credentials as a string, or an error if the keychain entry doesn't exist or can't be read.
func readClaudeKeychainCredentials() (string, error) {
	cmd := exec.Command("security", "find-generic-password",
		"-s", "Claude Code-credentials",
		"-w")

	output, err := cmd.CombinedOutput()
	if err != nil {
		// security command returns exit code 44 if the item doesn't exist
		return "", fmt.Errorf("keychain lookup failed: %w", err)
	}

	credentials := strings.TrimSpace(string(output))
	if credentials == "" {
		return "", fmt.Errorf("keychain entry exists but is empty")
	}

	return credentials, nil
}
