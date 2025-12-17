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
	home, err := resolveHomeDir()
	if err != nil {
		return "", err
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

	if cmd == "opencode" {
		return resolveOpencodeHostDir(home), nil
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

func resolveOpencodeHostDir(home string) string {
	candidates := opencodeCandidatePaths(home)
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() {
			return candidate
		}
	}
	return candidates[0]
}

func opencodeCandidatePaths(home string) []string {
	paths := opencodePaths(home)

	candidates := []string{
		paths.configDir,
		paths.stateDir,
		paths.dataDir,
		paths.legacyDir,
	}

	seen := make(map[string]struct{}, len(candidates))
	deduped := make([]string, 0, len(candidates))
	for _, p := range candidates {
		clean := filepath.Clean(p)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		deduped = append(deduped, clean)
	}
	return deduped
}

type opencodeHostPaths struct {
	configDir string
	stateDir  string
	dataDir   string
	legacyDir string
}

func opencodePaths(home string) opencodeHostPaths {
	configBase := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if configBase == "" {
		configBase = filepath.Join(home, ".config")
	}
	stateBase := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
	if stateBase == "" {
		stateBase = filepath.Join(home, ".local", "state")
	}
	dataBase := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if dataBase == "" {
		dataBase = filepath.Join(home, ".local", "share")
	}

	return opencodeHostPaths{
		configDir: filepath.Join(configBase, "opencode"),
		stateDir:  filepath.Join(stateBase, "opencode"),
		dataDir:   filepath.Join(dataBase, "opencode"),
		legacyDir: filepath.Join(home, ".opencode"),
	}
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
