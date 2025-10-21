package runner

import (
	"path/filepath"
	"strings"
)

func volumeContainerPath(volume string) string {
	parts := strings.Split(volume, ":")
	for i := len(parts) - 1; i >= 0; i-- {
		segment := strings.TrimSpace(parts[i])
		if strings.HasPrefix(segment, "/") {
			return segment
		}
	}
	return ""
}

func volumeHostContainer(volume string) (string, string, bool) {
	parts := strings.Split(volume, ":")
	if len(parts) < 2 {
		return "", "", false
	}
	host := strings.TrimSpace(parts[0])
	container := strings.TrimSpace(parts[1])
	if host == "" || container == "" {
		return "", "", false
	}
	return filepath.Clean(host), filepath.Clean(container), true
}
