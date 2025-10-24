package configstore

import (
	"path/filepath"
	"testing"
)

// This test sets XDG_CONFIG_HOME and HOME to exercise precedence; keep it
// serial so other tests do not observe the temporary directories.
func TestGetConfigPathPrefersXDG(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(t.TempDir(), "ignored"))

	dir, file, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath returned error: %v", err)
	}
	wantDir := filepath.Join(base, "leash")
	wantFile := filepath.Join(wantDir, configFileName)
	if dir != wantDir {
		t.Fatalf("dir = %q, want %q", dir, wantDir)
	}
	if file != wantFile {
		t.Fatalf("file = %q, want %q", file, wantFile)
	}
}

// This test clears HOME to cover the error path; run it serially to avoid
// leaking the unset environment to other tests.
func TestGetConfigPathMissingHomeErrors(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	testSetEnv(t, "XDG_CONFIG_HOME", "")
	unsetHome(t)

	if _, _, err := GetConfigPath(); err == nil {
		t.Fatal("expected error when home cannot be resolved")
	}
}

// This test overrides LEASH_HOME and HOME to verify precedence; keep it serial
// so parallel tests do not inherit the override.
func TestGetConfigPathPrefersLeashHome(t *testing.T) {
	base := filepath.Join(t.TempDir(), "leash-home")
	testSetEnv(t, "LEASH_HOME", base)
	testSetEnv(t, "XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "xdg"))
	setHome(t, filepath.Join(t.TempDir(), "ignored"))

	dir, file, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath returned error: %v", err)
	}
	wantDir, err := filepath.Abs(base)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	wantFile := filepath.Join(wantDir, configFileName)
	if dir != wantDir {
		t.Fatalf("dir = %q, want %q", dir, wantDir)
	}
	if file != wantFile {
		t.Fatalf("file = %q, want %q", file, wantFile)
	}
}
