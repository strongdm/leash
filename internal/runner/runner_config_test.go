package runner

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This test resets many env vars to exercise temp workdir creation; keep it
// serial to avoid leaking overrides.
func TestLoadConfigCreatesTemporaryWorkDir(t *testing.T) {
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

	cfg, _, _, err := loadConfig(caller, options{})
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

// This test sets LEASH_WORK_DIR explicitly; run serially to avoid affecting
// other tests.
func TestLoadConfigRespectsEnvWorkDir(t *testing.T) {

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

	cfg, _, _, err := loadConfig(caller, options{})
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

// This test mutates env configuration while deriving container names; keep it
// serial.
func TestLoadConfigDefaultsContainerNamesFromProject(t *testing.T) {
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

	cfg, _, _, err := loadConfig(projectDir, options{})
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

// This test depends on TARGET_CONTAINER overrides; run serially.
func TestLoadConfigRespectsTargetContainerEnv(t *testing.T) {
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

	cfg, _, _, err := loadConfig(caller, options{})
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

// This test reads TARGET_IMAGE from the environment; keep it serial.
func TestLoadConfigRespectsTargetImageEnv(t *testing.T) {
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	clearEnv(t, "LEASH_TARGET_IMAGE")
	clearEnv(t, "TARGET_IMAGE")
	caller := t.TempDir()

	setEnv(t, "TARGET_IMAGE", "example.com/custom:latest")

	cfg, _, _, err := loadConfig(caller, options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if got, want := cfg.targetImage, "example.com/custom:latest"; got != want {
		t.Fatalf("target image mismatch: got %q want %q", got, want)
	}
}

// This test inspects dev docker files with env overrides; run serially.
func TestLoadConfigUsesDevDockerFiles(t *testing.T) {
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	clearEnv(t, "LEASH_TARGET_IMAGE")
	clearEnv(t, "TARGET_IMAGE")
	clearEnv(t, "LEASH_IMAGE")
	clearEnv(t, "TARGET_CONTAINER")
	clearEnv(t, "LEASH_CONTAINER")

	caller := t.TempDir()
	coderID := "sha256:test-coder"
	leashID := "sha256:test-leash"

	if err := os.WriteFile(filepath.Join(caller, devDockerCoderFile), []byte(coderID+"\n"), 0o644); err != nil {
		t.Fatalf("write coder dev file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caller, devDockerLeashFile), []byte(leashID+"\n"), 0o644); err != nil {
		t.Fatalf("write leash dev file: %v", err)
	}

	cfg, _, _, err := loadConfig(caller, options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if cfg.targetImage != coderID {
		t.Fatalf("expected target image %q, got %q", coderID, cfg.targetImage)
	}
	if cfg.targetImageSource != imageSourceDevFile {
		t.Fatalf("expected target image source %q, got %q", imageSourceDevFile, cfg.targetImageSource)
	}
	if want := filepath.Join(caller, devDockerCoderFile); filepath.Clean(cfg.targetImageDevFile) != filepath.Clean(want) {
		t.Fatalf("expected target image dev file %q, got %q", want, cfg.targetImageDevFile)
	}

	if cfg.leashImage != leashID {
		t.Fatalf("expected leash image %q, got %q", leashID, cfg.leashImage)
	}
	if cfg.leashImageSource != imageSourceDevFile {
		t.Fatalf("expected leash image source %q, got %q", imageSourceDevFile, cfg.leashImageSource)
	}
	if want := filepath.Join(caller, devDockerLeashFile); filepath.Clean(cfg.leashImageDevFile) != filepath.Clean(want) {
		t.Fatalf("expected leash image dev file %q, got %q", want, cfg.leashImageDevFile)
	}
}

// This test ensures env overrides beat dev docker files; keep it serial.
func TestLoadConfigDevDockerFilesIgnoredWhenEnvOverrides(t *testing.T) {
	clearEnv(t, "LEASH_WORK_DIR")
	clearEnv(t, "LEASH_LOG_DIR")
	clearEnv(t, "LEASH_CFG_DIR")
	clearEnv(t, "LEASH_WORKSPACE_DIR")
	setEnv(t, "XDG_CONFIG_HOME", t.TempDir())
	clearEnv(t, "LEASH_TARGET_IMAGE")
	clearEnv(t, "TARGET_IMAGE")
	clearEnv(t, "LEASH_IMAGE")
	clearEnv(t, "TARGET_CONTAINER")
	clearEnv(t, "LEASH_CONTAINER")

	caller := t.TempDir()

	if err := os.WriteFile(filepath.Join(caller, devDockerCoderFile), []byte("sha256:dev-coder\n"), 0o644); err != nil {
		t.Fatalf("write coder dev file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caller, devDockerLeashFile), []byte("sha256:dev-leash\n"), 0o644); err != nil {
		t.Fatalf("write leash dev file: %v", err)
	}

	setEnv(t, "TARGET_IMAGE", "example.com/env-target:latest")
	setEnv(t, "LEASH_IMAGE", "example.com/env-leash:latest")

	cfg, _, _, err := loadConfig(caller, options{})
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if cfg.targetImage != "example.com/env-target:latest" {
		t.Fatalf("expected target image to use env override, got %q", cfg.targetImage)
	}
	if cfg.targetImageSource != imageSourceEnv {
		t.Fatalf("expected target image source %q, got %q", imageSourceEnv, cfg.targetImageSource)
	}
	if cfg.targetImageDevFile != "" {
		t.Fatalf("expected no target dev file usage, got %q", cfg.targetImageDevFile)
	}

	if cfg.leashImage != "example.com/env-leash:latest" {
		t.Fatalf("expected leash image to use env override, got %q", cfg.leashImage)
	}
	if cfg.leashImageSource != imageSourceEnv {
		t.Fatalf("expected leash image source %q, got %q", imageSourceEnv, cfg.leashImageSource)
	}
	if cfg.leashImageDevFile != "" {
		t.Fatalf("expected no leash dev file usage, got %q", cfg.leashImageDevFile)
	}
}

func TestLogDevImageSelectionsEmitsMessage(t *testing.T) {
	t.Parallel()

	caller := t.TempDir()
	devPath := filepath.Join(caller, devDockerCoderFile)
	cfg := config{
		callerDir:          caller,
		targetImage:        "sha256:log-coder",
		targetImageSource:  imageSourceDevFile,
		targetImageDevFile: devPath,
		leashImage:         "sha256:default-leash",
		leashImageSource:   imageSourceDefault,
	}

	var buf bytes.Buffer
	r := &runner{
		cfg:     cfg,
		logger:  log.New(&buf, "", 0),
		verbose: true,
	}

	r.logDevImageSelections()

	output := buf.String()
	if !strings.Contains(output, "using target image override") {
		t.Fatalf("expected log output to mention target override, got %q", output)
	}
	if !strings.Contains(output, "sha256:log-coder") {
		t.Fatalf("expected log output to include image id, got %q", output)
	}
	if !strings.Contains(output, devDockerCoderFile) {
		t.Fatalf("expected log output to reference dev file, got %q", output)
	}
	if strings.Contains(output, "leash image override") {
		t.Fatalf("expected only target override to be logged, got %q", output)
	}
}
