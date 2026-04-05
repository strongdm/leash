package configstore

import (
	"os"
	"path/filepath"
	"testing"
)

// These tests override XDG_CONFIG_HOME and HOME; run serially.

func TestLoadWithOverlayNoLocalFile(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	// Write a global config with a target image.
	cfgDir := filepath.Join(base, "leash")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	globalTOML := `[leash]
target_image = "global-image"

[leash.envvars]
GH_CONFIG_DIR = "/root/.config/gh"
`
	if err := os.WriteFile(filepath.Join(cfgDir, configFileName), []byte(globalTOML), 0o600); err != nil {
		t.Fatal(err)
	}

	// Load with a directory that has no .leash.toml.
	projectDir := t.TempDir()
	cfg, err := LoadWithOverlay(projectDir)
	if err != nil {
		t.Fatalf("LoadWithOverlay: %v", err)
	}

	if cfg.TargetImage != "global-image" {
		t.Fatalf("TargetImage = %q, want %q", cfg.TargetImage, "global-image")
	}
	if cfg.EnvVars["GH_CONFIG_DIR"] != "/root/.config/gh" {
		t.Fatalf("GH_CONFIG_DIR = %q, want %q", cfg.EnvVars["GH_CONFIG_DIR"], "/root/.config/gh")
	}
}

func TestLoadWithOverlayMergesLocalFile(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	// Write global config.
	cfgDir := filepath.Join(base, "leash")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	globalTOML := `[leash]
target_image = "global-image"

[leash.envvars]
GH_CONFIG_DIR = "/root/.config/gh"
SHARED_KEY = "global"
`
	if err := os.WriteFile(filepath.Join(cfgDir, configFileName), []byte(globalTOML), 0o600); err != nil {
		t.Fatal(err)
	}

	// Write local override.
	projectDir := t.TempDir()
	localTOML := `[leash.envvars]
ATLASSIAN_USER = "secret-user"
SHARED_KEY = "local-override"
`
	if err := os.WriteFile(filepath.Join(projectDir, LocalConfigFileName), []byte(localTOML), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadWithOverlay(projectDir)
	if err != nil {
		t.Fatalf("LoadWithOverlay: %v", err)
	}

	// Global values preserved.
	if cfg.TargetImage != "global-image" {
		t.Fatalf("TargetImage = %q, want %q", cfg.TargetImage, "global-image")
	}
	if cfg.EnvVars["GH_CONFIG_DIR"] != "/root/.config/gh" {
		t.Fatalf("GH_CONFIG_DIR = %q, want %q", cfg.EnvVars["GH_CONFIG_DIR"], "/root/.config/gh")
	}

	// Local values added.
	if cfg.EnvVars["ATLASSIAN_USER"] != "secret-user" {
		t.Fatalf("ATLASSIAN_USER = %q, want %q", cfg.EnvVars["ATLASSIAN_USER"], "secret-user")
	}

	// Local overrides global.
	if cfg.EnvVars["SHARED_KEY"] != "local-override" {
		t.Fatalf("SHARED_KEY = %q, want %q", cfg.EnvVars["SHARED_KEY"], "local-override")
	}
}

func TestLoadWithOverlayLocalOverridesTargetImage(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	cfgDir := filepath.Join(base, "leash")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	globalTOML := `[leash]
target_image = "global-image"
`
	if err := os.WriteFile(filepath.Join(cfgDir, configFileName), []byte(globalTOML), 0o600); err != nil {
		t.Fatal(err)
	}

	projectDir := t.TempDir()
	localTOML := `[leash]
target_image = "local-image"
`
	if err := os.WriteFile(filepath.Join(projectDir, LocalConfigFileName), []byte(localTOML), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadWithOverlay(projectDir)
	if err != nil {
		t.Fatalf("LoadWithOverlay: %v", err)
	}

	if cfg.TargetImage != "local-image" {
		t.Fatalf("TargetImage = %q, want %q", cfg.TargetImage, "local-image")
	}
}

func TestLoadWithOverlayEmptyDirSkipsLocal(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	cfg, err := LoadWithOverlay("")
	if err != nil {
		t.Fatalf("LoadWithOverlay: %v", err)
	}
	// Should just return defaults with no error.
	if cfg.TargetImage != "" {
		t.Fatalf("expected empty TargetImage, got %q", cfg.TargetImage)
	}
}

func TestLoadWithOverlayBadLocalTOMLReturnsError(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, LocalConfigFileName), []byte("not valid {{{ toml"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadWithOverlay(projectDir)
	if err == nil {
		t.Fatal("expected error for invalid local TOML")
	}
}

func TestGetLocalConfigPath(t *testing.T) {
	t.Parallel()
	got := GetLocalConfigPath("/some/project")
	want := filepath.Join("/some/project", LocalConfigFileName)
	if got != want {
		t.Fatalf("GetLocalConfigPath = %q, want %q", got, want)
	}
}
