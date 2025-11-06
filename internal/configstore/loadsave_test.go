package configstore

import (
	"os"
	"path/filepath"
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
