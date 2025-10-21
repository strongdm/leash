package configstore

import (
	"path/filepath"
	"testing"
)

func TestGetConfigPathPrefersXDG(t *testing.T) {
	t.Parallel()
	lockEnv(t)
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

func TestGetConfigPathMissingHomeErrors(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	testSetEnv(t, "XDG_CONFIG_HOME", "")
	unsetHome(t)

	if _, _, err := GetConfigPath(); err == nil {
		t.Fatal("expected error when home cannot be resolved")
	}
}

func TestGetConfigPathPrefersLeashHome(t *testing.T) {
	t.Parallel()
	lockEnv(t)
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
