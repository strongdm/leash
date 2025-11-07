package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestDecodeConfigExpandsEnvInProjectSecrets(t *testing.T) {
	projectRoot := t.TempDir()
	suffix := "delta"
	testSetEnv(t, "PROJECT_ROOT", projectRoot)
	testSetEnv(t, "SUFFIX", suffix)
	testSetEnv(t, "NV_API_KEY", "supervalue")

	const configTemplate = `
[projects."${PROJECT_ROOT}/nested-$SUFFIX".secrets]
OPENAI_API_KEY = "${NV_API_KEY}-lolllllllllllllll!"
`

	cfg := New()
	if err := decodeConfig([]byte(configTemplate), "config.toml", &cfg); err != nil {
		t.Fatalf("decodeConfig returned error: %v", err)
	}

	normalizedPath, err := normalizeProjectKey(filepath.Join(projectRoot, "nested-"+suffix))
	if err != nil {
		t.Fatalf("normalizeProjectKey returned error: %v", err)
	}

	projectSecrets, ok := cfg.ProjectSecrets[normalizedPath]
	if !ok {
		t.Fatalf("missing project secrets for %q (all: %#v)", normalizedPath, cfg.ProjectSecrets)
	}

	got := projectSecrets["OPENAI_API_KEY"]
	want := "supervalue-lolllllllllllllll!"
	if got != want {
		t.Fatalf("OPENAI_API_KEY = %q, want %q", got, want)
	}
}

func TestDecodeConfigExpandsEnvInProjectSecretsWithPathVariable(t *testing.T) {
	projectPath := t.TempDir()
	testSetEnv(t, "LEASH_PROJECT_PATH", projectPath)
	testSetEnv(t, "API_KEY", "apikey123")
	testSetEnv(t, "TOKEN_SUFFIX", "omega")

	const configTemplate = `
[projects."$LEASH_PROJECT_PATH".secrets]
API_KEY = "$API_KEY-$TOKEN_SUFFIX"
`

	cfg := New()
	if err := decodeConfig([]byte(configTemplate), "config.toml", &cfg); err != nil {
		t.Fatalf("decodeConfig returned error: %v", err)
	}

	normalizedPath, err := normalizeProjectKey(projectPath)
	if err != nil {
		t.Fatalf("normalizeProjectKey returned error: %v", err)
	}

	projectSecrets, ok := cfg.ProjectSecrets[normalizedPath]
	if !ok {
		t.Fatalf("missing project secrets for %q", normalizedPath)
	}

	got := projectSecrets["API_KEY"]
	want := "apikey123-omega"
	if got != want {
		t.Fatalf("API_KEY = %q, want %q", got, want)
	}
}

func TestDecodeConfigExpandsEnvInProjectSecretValuesMixedSyntax(t *testing.T) {
	projectRoot := t.TempDir()
	testSetEnv(t, "PROJECT_DIR", projectRoot)
	testSetEnv(t, "TOKEN", "tok")
	testSetEnv(t, "SUFFIX", "tail")

	const configTemplate = `
[projects."${PROJECT_DIR}".secrets]
BRACED = "${TOKEN}"
UNBRACED = "$TOKEN$SUFFIX"
ESCAPED = '\$TOKEN'
ESCAPEDBRACED = '\${TOKEN}'
`

	cfg := New()
	if err := decodeConfig([]byte(configTemplate), "config.toml", &cfg); err != nil {
		t.Fatalf("decodeConfig returned error: %v", err)
	}

	normalizedPath, err := normalizeProjectKey(projectRoot)
	if err != nil {
		t.Fatalf("normalizeProjectKey returned error: %v", err)
	}

	projectSecrets, ok := cfg.ProjectSecrets[normalizedPath]
	if !ok {
		t.Fatalf("missing project secrets for %q", normalizedPath)
	}

	if got, want := projectSecrets["BRACED"], "tok"; got != want {
		t.Fatalf("BRACED = %q, want %q", got, want)
	}
	if got, want := projectSecrets["UNBRACED"], "toktail"; got != want {
		t.Fatalf("UNBRACED = %q, want %q", got, want)
	}
	if got, want := projectSecrets["ESCAPED"], "$TOKEN"; got != want {
		t.Fatalf("ESCAPED = %q, want %q", got, want)
	}
	if got, want := projectSecrets["ESCAPEDBRACED"], "${TOKEN}"; got != want {
		t.Fatalf("ESCAPEDBRACED = %q, want %q", got, want)
	}
}

func TestDecodeConfigAllowsSingleBackslashDollarInSecrets(t *testing.T) {
	base := t.TempDir()
	setHome(t, base)

	projectRoot := filepath.Join(base, "src", "leash", "worktree", "jay", "secrets-002")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	testSetEnv(t, "NV_API_KEY", "supervalue")

	const configTemplate = `
[projects."${HOME}/src/leash/worktree/jay/secrets-002".secrets]
OPENAI_API_KEY="rofl-sir-${NV_API_KEY}-lolllllllllllllll\$FOO\$BOO"
`

	cfg := New()
	if err := decodeConfig([]byte(configTemplate), "config.toml", &cfg); err != nil {
		t.Fatalf("decodeConfig returned error: %v", err)
	}

	normalizedPath, err := normalizeProjectKey(projectRoot)
	if err != nil {
		t.Fatalf("normalizeProjectKey returned error: %v", err)
	}

	projectSecrets, ok := cfg.ProjectSecrets[normalizedPath]
	if !ok {
		t.Fatalf("missing project secrets for %q (all: %#v)", normalizedPath, cfg.ProjectSecrets)
	}

	const want = "rofl-sir-supervalue-lolllllllllllllll$FOO$BOO"
	if got := projectSecrets["OPENAI_API_KEY"]; got != want {
		t.Fatalf("OPENAI_API_KEY = %q, want %q (project map: %#v)", got, want, projectSecrets)
	}
}

func TestDecodeConfigAllowsEmptyProjectSecretsTable(t *testing.T) {
	base := t.TempDir()
	setHome(t, base)

	projectRoot := filepath.Join(base, "src", "leash", "worktree", "jay", "secrets-002")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	const configTemplate = `
[projects."${HOME}/src/leash/worktree/jay/secrets-002".secrets]
`

	cfg := New()
	if err := decodeConfig([]byte(configTemplate), "config.toml", &cfg); err != nil {
		t.Fatalf("decodeConfig returned error: %v", err)
	}

	normalizedPath, err := normalizeProjectKey(projectRoot)
	if err != nil {
		t.Fatalf("normalizeProjectKey returned error: %v", err)
	}

	if _, ok := cfg.ProjectSecrets[normalizedPath]; ok {
		t.Fatalf("unexpected secrets entry for %q", normalizedPath)
	}
}

func TestDecodeConfigHandlesWorkspaceSample(t *testing.T) {
	base := t.TempDir()
	setHome(t, base)

	secretsProject := filepath.Join(base, "src", "leash", "worktree", "jay", "secrets-002")
	if err := os.MkdirAll(secretsProject, 0o755); err != nil {
		t.Fatalf("MkdirAll secrets project: %v", err)
	}

	toggleProject := filepath.Join(base, "src", "leash5", "worktree", "jay", "squash-config-5-0")
	if err := os.MkdirAll(toggleProject, 0o755); err != nil {
		t.Fatalf("MkdirAll toggle project: %v", err)
	}

	configTemplate := fmt.Sprintf(`
[mounts]

[projects]
[projects."${HOME}/src/leash/worktree/jay/secrets-002".secrets]
# n.b. env-vars are fair game!
#OPENAI_API_KEY="rofl-sir-${NV_API_KEY}-lolllllllllllllll$FOO$BOO"

[projects.%s]
claude = true

[volumes]
codex = true
`, strconv.Quote(filepath.ToSlash(toggleProject)))

	cfg := New()
	if err := decodeConfig([]byte(configTemplate), "config.toml", &cfg); err != nil {
		t.Fatalf("decodeConfig returned error: %v", err)
	}

	if got := cfg.CommandVolumes["codex"]; got == nil || !*got {
		t.Fatalf("expected global codex toggle true, got %v", got)
	}

	normalizedSecrets, err := normalizeProjectKey(secretsProject)
	if err != nil {
		t.Fatalf("normalizeProjectKey(secretsProject): %v", err)
	}
	if _, ok := cfg.ProjectSecrets[normalizedSecrets]; ok {
		t.Fatalf("expected no secrets registered for %q, got %#v", normalizedSecrets, cfg.ProjectSecrets[normalizedSecrets])
	}

	normalizedToggle, err := normalizeProjectKey(toggleProject)
	if err != nil {
		t.Fatalf("normalizeProjectKey(toggleProject): %v", err)
	}
	toggles, ok := cfg.ProjectCommandVolumes[normalizedToggle]
	if !ok {
		t.Fatalf("missing project command toggles for %q", normalizedToggle)
	}
	if got := toggles["claude"]; got == nil || !*got {
		t.Fatalf("expected claude toggle true for %q, got %v", normalizedToggle, got)
	}
}
