package runner

import "strings"

var productVersion = "dev"

// SetVersion sets the human-readable leash version used in interactive UIs.
func SetVersion(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	productVersion = v
}

func versionTag() string {
	v := strings.TrimSpace(productVersion)
	if v == "" {
		return "dev"
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "v") {
		return v
	}
	return "v" + v
}
