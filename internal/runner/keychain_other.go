//go:build !darwin

package runner

import "fmt"

// readClaudeKeychainCredentials is a no-op on non-macOS platforms.
func readClaudeKeychainCredentials() (string, error) {
	return "", fmt.Errorf("keychain access only supported on macOS")
}
