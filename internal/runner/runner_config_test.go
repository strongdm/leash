package runner

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoadConfigCreatesTemporaryWorkDir(t *testing.T) {
	t.Parallel()

	lockEnv(t)
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	clearEnv(t, "LEASH_TARGET_IMAGE")
	clearEnv(t, "TARGET_IMAGE")
	clearEnv(t, "TARGET_CONTAINER")
	clearEnv(t, "LEASH_CONTAINER")

	caller := t.TempDir()

	cfg, _, err := loadConfig(caller, options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if !cfg.workDirIsTemp {
		t.Fatal("expected workDirIsTemp to be true when LEASH_WORK_DIR is unset")
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(cfg.workDir)
	})

	base := filepath.Base(cfg.workDir)
	prefix := tempWorkDirPrefix(caller)
	if !strings.HasPrefix(base, prefix) {
		t.Fatalf("temporary directory %q does not start with prefix %q", base, prefix)
	}

	info, err := os.Stat(cfg.workDir)
	if err != nil {
		t.Fatalf("stat work dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected work dir %q to be a directory", cfg.workDir)
	}
}

func TestLoadConfigRespectsEnvWorkDir(t *testing.T) {
	t.Parallel()

	lockEnv(t)

	caller := t.TempDir()
	custom := filepath.Join(t.TempDir(), "manual")

	setEnv(t, "LEASH_WORK_DIR", custom)
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	clearEnv(t, "LEASH_TARGET_IMAGE")
	clearEnv(t, "TARGET_IMAGE")
	clearEnv(t, "TARGET_CONTAINER")
	clearEnv(t, "LEASH_CONTAINER")

	cfg, _, err := loadConfig(caller, options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if cfg.workDirIsTemp {
		t.Fatal("expected workDirIsTemp to be false when LEASH_WORK_DIR is set")
	}
	if cfg.workDir != custom {
		t.Fatalf("expected workDir %q, got %q", custom, cfg.workDir)
	}
}

var envMu sync.Mutex

func lockEnv(t *testing.T) {
	t.Helper()
	envMu.Lock()
	t.Cleanup(envMu.Unlock)
}

func clearEnv(t *testing.T, key string) {
	t.Helper()
	old, ok := os.LookupEnv(key)
	if ok {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset env %s: %v", key, err)
		}
		t.Cleanup(func() {
			if err := os.Setenv(key, old); err != nil {
				t.Fatalf("restore env %s: %v", key, err)
			}
		})
		return
	}
	t.Cleanup(func() {})
}

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	old, ok := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("set env %s: %v", key, err)
	}
	t.Cleanup(func() {
		if !ok {
			if err := os.Unsetenv(key); err != nil {
				t.Fatalf("unset env %s: %v", key, err)
			}
			return
		}
		if err := os.Setenv(key, old); err != nil {
			t.Fatalf("restore env %s: %v", key, err)
		}
	})
}

func TestSanitizeProjectName(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"My Project":                      "my-project",
		"Proj_Name_123":                   "proj-name-123",
		"   Leading And Trailing   ":      "leading-and-trailing",
		"$$$":                             "",
		"A-Name-With---Dashes":            "a-name-with-dashes",
		"UPPER lower Mixed":               "upper-lower-mixed",
		"ends.with.dot.":                  "ends-with-dot",
		"   MULTIPLE   spaces    here   ": "multiple-spaces-here",
		"123numbers-start":                "123numbers-start",
		"--hyphen-prefix":                 "hyphen-prefix",
	}

	for input, want := range tests {
		if got := sanitizeProjectName(input); got != want {
			t.Fatalf("sanitizeProjectName(%q) = %q, want %q", input, got, want)
		}
	}

	var long strings.Builder
	long.WriteString("project")
	for i := 0; i < 20; i++ {
		long.WriteString("-segment")
	}
	if got := sanitizeProjectName(long.String()); len(got) > 63 {
		t.Fatalf("sanitizeProjectName produced name longer than 63 characters: %q (%d)", got, len(got))
	}
}

func TestLoadConfigDefaultsContainerNamesFromProject(t *testing.T) {
	t.Parallel()

	lockEnv(t)
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	clearEnv(t, "LEASH_TARGET_IMAGE")
	clearEnv(t, "TARGET_IMAGE")
	clearEnv(t, "TARGET_CONTAINER")
	clearEnv(t, "LEASH_CONTAINER")

	root := t.TempDir()
	projectDir := filepath.Join(root, "Cool Project_42")
	if err := os.Mkdir(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", projectDir, err)
	}

	cfg, _, err := loadConfig(projectDir, options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if got, want := cfg.targetContainer, "cool-project-42"; got != want {
		t.Fatalf("target container mismatch: got %q want %q", got, want)
	}
	if got, want := cfg.leashContainer, "cool-project-42-leash"; got != want {
		t.Fatalf("leash container mismatch: got %q want %q", got, want)
	}
	if got, want := cfg.targetContainerBase, "cool-project-42"; got != want {
		t.Fatalf("target container base mismatch: got %q want %q", got, want)
	}
	if got, want := cfg.leashContainerBase, "cool-project-42-leash"; got != want {
		t.Fatalf("leash container base mismatch: got %q want %q", got, want)
	}
}

func TestLoadConfigRespectsTargetContainerEnv(t *testing.T) {
	t.Parallel()

	lockEnv(t)
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	clearEnv(t, "LEASH_TARGET_IMAGE")
	clearEnv(t, "TARGET_IMAGE")
	clearEnv(t, "TARGET_CONTAINER")
	caller := t.TempDir()

	setEnv(t, "TARGET_CONTAINER", "custom-target")
	clearEnv(t, "LEASH_CONTAINER")

	cfg, _, err := loadConfig(caller, options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if got, want := cfg.targetContainer, "custom-target"; got != want {
		t.Fatalf("target container mismatch: got %q want %q", got, want)
	}
	if got, want := cfg.targetContainerBase, "custom-target"; got != want {
		t.Fatalf("target container base mismatch: got %q want %q", got, want)
	}
}

func TestLoadConfigRespectsTargetImageEnv(t *testing.T) {
	t.Parallel()

	lockEnv(t)
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	clearEnv(t, "LEASH_TARGET_IMAGE")
	clearEnv(t, "TARGET_IMAGE")
	caller := t.TempDir()

	setEnv(t, "TARGET_IMAGE", "example.com/custom:latest")

	cfg, _, err := loadConfig(caller, options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if got, want := cfg.targetImage, "example.com/custom:latest"; got != want {
		t.Fatalf("target image mismatch: got %q want %q", got, want)
	}
}
