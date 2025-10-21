package configstore

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestHostDirsAllCommandsCovered(t *testing.T) {
	t.Parallel()
	lockEnv(t)
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

func TestUnsupportedCommandPanics(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	testSetEnv(t, "CLAUDE_CONFIG_DIR", "")
	setHome(t, t.TempDir())

	if _, err := HostDirForCommand("notreal"); err == nil {
		t.Fatal("expected error for unsupported command")
	}
}

func TestHostDirsMissingHomeErrors(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	testSetEnv(t, "CLAUDE_CONFIG_DIR", "")
	unsetHome(t)

	if _, err := HostDirForCommand("codex"); err == nil {
		t.Fatal("expected error when home cannot be resolved")
	}
}

func TestClaudeHostDirUsesEnvOverride(t *testing.T) {
	t.Parallel()
	lockEnv(t)
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

func TestClaudeHostDirTildeOverride(t *testing.T) {
	t.Parallel()
	lockEnv(t)
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
