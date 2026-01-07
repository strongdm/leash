package openflag

import (
	"os"
	"strings"
)

// Enabled reports whether the OPEN environment variable requests that the
// Control UI be opened automatically.
func Enabled() bool {
	value, ok := os.LookupEnv("OPEN")
	if !ok {
		return false
	}
	return IsTruthy(value)
}

// IsTruthy returns true when the provided value matches an accepted truthy
// form for the OPEN environment variable.
func IsTruthy(value string) bool {
	trimmed := strings.TrimSpace(value)
	switch strings.ToLower(trimmed) {
	case "1", "t", "true":
		return true
	default:
		return false
	}
}
