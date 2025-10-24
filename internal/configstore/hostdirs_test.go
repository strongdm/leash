package configstore

import (
	"path/filepath"
	"runtime"
	"testing"
)

// This test rewires HOME/CLAUDE_CONFIG_DIR and must remain serial to avoid
// leaking temporary paths into other tests.
func TestHostDirsAllCommandsCovered(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	testSetEnv(t, "CLAUDE_CONFIG_DIR", "")
	home := t.TempDir()
	setHome(t, home)

	for _, cmd := range SupportedCommands() {
		dir, err := HostDirForCommand(cmd)
		if err != nil {
			t.Fatalf("hostDirForCommand(%q) returned error: %v", cmd, err)
		}
		want := filepath.Join(home, "."+cmd)
		if dir != want {
			t.Fatalf("hostDirForCommand(%q) = %q, want %q", cmd, dir, want)
		}
	}
}

// This test modifies HOME while validating error handling, so it cannot run in
// parallel with other environment-sensitive tests.
func TestUnsupportedCommandPanics(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	testSetEnv(t, "CLAUDE_CONFIG_DIR", "")
	setHome(t, t.TempDir())

	if _, err := HostDirForCommand("notreal"); err == nil {
		t.Fatal("expected error for unsupported command")
	}
}

// This test unsets HOME to exercise error paths and must execute serially.
func TestHostDirsMissingHomeErrors(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	testSetEnv(t, "CLAUDE_CONFIG_DIR", "")
	unsetHome(t)

	if _, err := HostDirForCommand("codex"); err == nil {
		t.Fatal("expected error when home cannot be resolved")
	}
}

// This test sets HOME and CLAUDE_CONFIG_DIR and cannot safely run in parallel.
func TestClaudeHostDirUsesEnvOverride(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	home := t.TempDir()
	setHome(t, home)

	override := filepath.Join(home, "custom-claude")
	testSetEnv(t, "CLAUDE_CONFIG_DIR", override)

	dir, err := HostDirForCommand("claude")
	if err != nil {
		t.Fatalf("HostDirForCommand returned error: %v", err)
	}
	if dir != override {
		t.Fatalf("HostDirForCommand = %q, want %q", dir, override)
	}
}

// This test updates HOME and CLAUDE_CONFIG_DIR to resolve tilde expansion; keep
// it serial to prevent environment leaks.
func TestClaudeHostDirTildeOverride(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	home := t.TempDir()
	setHome(t, home)

	testSetEnv(t, "CLAUDE_CONFIG_DIR", "~/my-claude")

	dir, err := HostDirForCommand("claude")
	if err != nil {
		t.Fatalf("HostDirForCommand returned error: %v", err)
	}
	want := filepath.Join(home, "my-claude")
	if dir != want {
		t.Fatalf("HostDirForCommand = %q, want %q", dir, want)
	}
}

func setHome(t *testing.T, dir string) {
	t.Helper()
	switch runtime.GOOS {
	case "windows":
		testSetEnv(t, "USERPROFILE", dir)
		testSetEnv(t, "HOMEDRIVE", "")
		testSetEnv(t, "HOMEPATH", "")
	default:
		testSetEnv(t, "HOME", dir)
	}
}

func unsetHome(t *testing.T) {
	t.Helper()
	switch runtime.GOOS {
	case "windows":
		testSetEnv(t, "USERPROFILE", "")
	default:
		testSetEnv(t, "HOME", "")
	}
}
