package runner

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestLogContainerConfigSanitizesEnv(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	r := &runner{
		logger: log.New(&buf, "", 0),
	}
	r.verbose = true

	mounts := []string{leashPublicMount, "/workspace", leashPublicMount}
	env := []string{
		"LEASH_DIR=/leash",
		"LEASH_DIR=/leash", // duplicate to ensure dedupe
		"SECRET_TOKEN=super-secret",
		"TRAILING_WHITESPACE =value ",
		"EMPTY_VALUE=",
	}

	r.logContainerConfig("target", mounts, env)

	got := buf.String()
	if !strings.Contains(got, "event=runner.container-config role=target") {
		t.Fatalf("expected role field in log, got %q", got)
	}
	if strings.Contains(got, "super-secret") {
		t.Fatalf("expected secret value to be redacted, got log %q", got)
	}
	if strings.Contains(got, "=/leash") {
		t.Fatalf("expected env values to be removed, got log %q", got)
	}
	for _, expected := range []string{`"LEASH_DIR"`, `"SECRET_TOKEN"`, `"TRAILING_WHITESPACE"`, `"EMPTY_VALUE"`} {
		if !strings.Contains(got, expected) {
			t.Fatalf("expected sanitized env list to contain %s, got log %q", expected, got)
		}
	}
}

func TestLogContainerConfigDeduplicatesMounts(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	r := &runner{
		logger: log.New(&buf, "", 0),
	}
	r.verbose = true

	mounts := []string{"/leash", "/workspace", "/workspace"}
	env := []string{"LEASH_DIR=/leash", "LEASH_DIR=/leash"}

	r.logContainerConfig("leash", mounts, env)

	got := buf.String()
	if strings.Count(got, `/workspace"`) != 1 {
		t.Fatalf("expected workspace mount to appear once, got %q", got)
	}
	if strings.Count(got, `"LEASH_DIR"`) != 1 {
		t.Fatalf("expected LEASH_DIR env key once, got %q", got)
	}
}

func TestSanitizeEnvKeysHandlesEmptyInput(t *testing.T) {
	t.Parallel()

	out := sanitizeEnvKeys(nil)
	if out != nil {
		t.Fatalf("expected nil output for nil input, got %v", out)
	}

	out = sanitizeEnvKeys([]string{"   ", "=value"})
	if out != nil {
		t.Fatalf("expected nil output after removing blanks, got %v", out)
	}
}
