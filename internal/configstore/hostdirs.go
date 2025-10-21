package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// supportedCommands enumerates subcommands that may request host config mounts.
var supportedCommands = map[string]struct{}{
	"codex":    {},
	"claude":   {},
	"gemini":   {},
	"qwen":     {},
	"opencode": {},
}

// HostDirForCommand resolves the expected host configuration directory for a
// supported command (e.g. ~/.codex). HOME must be resolvable; otherwise an
// error is returned.
func HostDirForCommand(cmd string) (string, error) {
	if _, ok := supportedCommands[cmd]; !ok {
		return "", fmt.Errorf("unsupported command %q", cmd)
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		if err == nil {
			err = fmt.Errorf("home directory not found")
		}
		return "", fmt.Errorf("resolve home dir: %w", err)
	}

	if cmd == "claude" {
		if override := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); override != "" {
			resolved, err := resolveClaudeConfigDir(override, home)
			if err != nil {
				return "", err
			}
			return resolved, nil
		}
	}

	return filepath.Join(home, fmt.Sprintf(".%s", cmd)), nil
}

func resolveClaudeConfigDir(override, home string) (string, error) {
	dir := override
	if dir == "~" {
		dir = home
	} else if strings.HasPrefix(dir, "~/") {
		dir = filepath.Join(home, dir[2:])
	} else if strings.HasPrefix(dir, "~"+string(os.PathSeparator)) {
		dir = filepath.Join(home, dir[2:])
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(home, dir)
	}
	return filepath.Clean(dir), nil
}

// SupportedCommands returns a sorted slice of commands that participate in the
// host configuration mount workflow. Primarily intended for tests and callers
// that need deterministic iteration order.
func SupportedCommands() []string {
	commands := make([]string, 0, len(supportedCommands))
	for cmd := range supportedCommands {
		commands = append(commands, cmd)
	}
	sort.Strings(commands)
	return commands
}
