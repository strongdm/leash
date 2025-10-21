package runner

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/configstore"
)

func TestParseArgsVolumeFlag(t *testing.T) {
	t.Parallel()

	args := []string{
		"-v", "/host/path:/container/path",
		"-v", "/data/cache:/cache:ro",
		"--volume", "/tmp/work:/tmp/work",
	}

	opts, err := parseArgs(args)
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if opts.verbose {
		t.Fatal("expected verbose to be false when only volume flags are provided")
	}

	want := []string{
		"/host/path:/container/path",
		"/data/cache:/cache:ro",
		"/tmp/work:/tmp/work",
	}
	if len(opts.volumes) != len(want) {
		t.Fatalf("expected %d volumes, got %d", len(want), len(opts.volumes))
	}
	for i := range want {
		if opts.volumes[i] != want[i] {
			t.Fatalf("volume %d mismatch: want %q got %q", i, want[i], opts.volumes[i])
		}
	}
}

func TestParseArgsVolumeEquals(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"-v=/host:/container"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if len(opts.volumes) != 1 || opts.volumes[0] != "/host:/container" {
		t.Fatalf("unexpected volumes: %+v", opts.volumes)
	}
}

func TestParseArgsVerboseShort(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"-v", "cmd"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if !opts.verbose {
		t.Fatal("expected verbose to be set when -v appears without volume argument")
	}
	if len(opts.command) != 1 || opts.command[0] != "cmd" {
		t.Fatalf("unexpected command slice: %+v", opts.command)
	}
	if opts.subcommand != "cmd" {
		t.Fatalf("expected subcommand 'cmd', got %q", opts.subcommand)
	}
}

func TestParseArgsInvalidVolume(t *testing.T) {
	t.Parallel()

	if _, err := parseArgs([]string{"--volume", "/invalid"}); err == nil {
		t.Fatal("expected error for volume flag without colon component")
	}
}

func TestParseArgsSubcommandAfterDoubleDash(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"--", "codex", "shell"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if opts.subcommand != "codex" {
		t.Fatalf("expected subcommand codex, got %q", opts.subcommand)
	}
	if len(opts.command) != 2 || opts.command[0] != "codex" {
		t.Fatalf("unexpected command slice: %+v", opts.command)
	}
}

func TestParseArgsEnvironmentFlags(t *testing.T) {
	t.Parallel()

	args := []string{
		"-e", "FOO=bar",
		"--env", "BAR",
		"-e=BAZ=buzz",
		"--env=QUX=",
	}

	opts, err := parseArgs(args)
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	want := []string{"FOO=bar", "BAR", "BAZ=buzz", "QUX="}
	if len(opts.envVars) != len(want) {
		t.Fatalf("unexpected env var count: got %d want %d", len(opts.envVars), len(want))
	}
	for i := range want {
		if opts.envVars[i] != want[i] {
			t.Fatalf("env var %d mismatch: got %q want %q", i, opts.envVars[i], want[i])
		}
	}
}

func TestParseArgsOpenFlag(t *testing.T) {
	t.Parallel()

	opts, err := parseArgs([]string{"-o", "--"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if !opts.openUI {
		t.Fatal("expected openUI to be set with -o")
	}

	opts, err = parseArgs([]string{"--open", "--"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if !opts.openUI {
		t.Fatal("expected openUI to be set with --open")
	}

	if _, err := parseArgs([]string{"--open=value"}); err == nil {
		t.Fatal("expected error when providing value to --open")
	}

	if _, err := parseArgs([]string{"-o=value"}); err == nil {
		t.Fatal("expected error when providing value to -o")
	}
}

func TestParseArgsEnvironmentMissingValue(t *testing.T) {
	t.Parallel()

	if _, err := parseArgs([]string{"-e"}); err == nil {
		t.Fatal("expected error for -e without value")
	}

	if _, err := parseArgs([]string{"--env", "--other"}); err == nil {
		t.Fatal("expected error when env flag value starts with dash")
	}

	if _, err := parseArgs([]string{"--env="}); err == nil {
		t.Fatal("expected error for empty env specification")
	}
}

func TestParseArgsAutoEnvClaude(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	setEnv(t, "ANTHROPIC_API_KEY", "anthropic-secret")
	setEnv(t, "OPENAI_API_KEY", "ignored")
	clearEnv(t, "IS_SANDBOX")

	opts, err := parseArgs([]string{"--", "claude"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	final := resolveEnvVars(opts.envVars, nil, opts.subcommand)
	if !containsEnv(final, "ANTHROPIC_API_KEY=anthropic-secret") {
		t.Fatalf("expected ANTHROPIC_API_KEY to be injected, got %v", final)
	}
}

// Claudes's sandbox flag is a bespoke passthrough; keep this test until the
// ad-hoc handling in autoEnvLayer is removed.
func TestParseArgsClaudeSandboxEnv(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	clearEnv(t, "ANTHROPIC_API_KEY")
	setEnv(t, "IS_SANDBOX", "1")

	opts, err := parseArgs([]string{"--", "claude"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	final := resolveEnvVars(opts.envVars, nil, opts.subcommand)
	if !containsEnv(final, "IS_SANDBOX=1") {
		t.Fatalf("expected IS_SANDBOX to be forwarded, got %v", final)
	}
}

// Mirrors the special-case override path for claude's sandbox flag; once the
// flag goes away these expectations should disappear too.
func TestParseArgsClaudeSandboxEnvOverride(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	setEnv(t, "IS_SANDBOX", "1")

	opts, err := parseArgs([]string{
		"-e", "IS_SANDBOX=0",
		"--", "claude",
	})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if !containsEnv(opts.envVars, "IS_SANDBOX=0") {
		t.Fatalf("expected CLI-provided IS_SANDBOX to remain, got %v", opts.envVars)
	}
	final := resolveEnvVars(opts.envVars, nil, opts.subcommand)
	if !containsEnv(final, "IS_SANDBOX=0") {
		t.Fatalf("expected resolved env to include CLI override, got %v", final)
	}
	if containsEnv(final, "IS_SANDBOX=1") {
		t.Fatalf("expected resolved env to skip host IS_SANDBOX, got %v", final)
	}
}

func TestParseArgsAutoEnvCodex(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	clearEnv(t, "ANTHROPIC_API_KEY")
	setEnv(t, "OPENAI_API_KEY", "openai-secret")

	opts, err := parseArgs([]string{"codex"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	final := resolveEnvVars(opts.envVars, nil, opts.subcommand)
	if !containsEnv(final, "OPENAI_API_KEY=openai-secret") {
		t.Fatalf("expected OPENAI_API_KEY to be injected, got %v", final)
	}
}

func TestParseArgsAutoEnvSkipsWhenProvided(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	setEnv(t, "ANTHROPIC_API_KEY", "anthropic-secret")

	opts, err := parseArgs([]string{
		"-e", "ANTHROPIC_API_KEY=custom",
		"--", "claude",
	})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if !containsEnv(opts.envVars, "ANTHROPIC_API_KEY=custom") {
		t.Fatalf("expected user-specified env to remain, got %v", opts.envVars)
	}
	if len(opts.envVars) != 1 {
		t.Fatalf("expected host ANTHROPIC_API_KEY to be ignored due to override, got %v", opts.envVars)
	}
	final := resolveEnvVars(opts.envVars, nil, opts.subcommand)
	if !containsEnv(final, "ANTHROPIC_API_KEY=custom") {
		t.Fatalf("expected resolved env to include custom key, got %v", final)
	}
	if containsEnv(final, "ANTHROPIC_API_KEY=anthropic-secret") {
		t.Fatalf("expected resolved env to exclude host key, got %v", final)
	}
}

func TestParseArgsAutoEnvQwen(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	setEnv(t, "DASHSCOPE_API_KEY", "dash-secret")

	opts, err := parseArgs([]string{"--", "qwen"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	final := resolveEnvVars(opts.envVars, nil, opts.subcommand)
	if !containsEnv(final, "DASHSCOPE_API_KEY=dash-secret") {
		t.Fatalf("expected DASHSCOPE_API_KEY to be injected, got %v", final)
	}
}

func TestParseArgsAutoEnvGemini(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	setEnv(t, "GEMINI_API_KEY", "gemini-secret")

	opts, err := parseArgs([]string{"--", "gemini"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	final := resolveEnvVars(opts.envVars, nil, opts.subcommand)
	if !containsEnv(final, "GEMINI_API_KEY=gemini-secret") {
		t.Fatalf("expected GEMINI_API_KEY to be injected, got %v", final)
	}
}

func TestParseArgsAutoEnvOpenCode(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	setEnv(t, "ANTHROPIC_API_KEY", "anthropic-secret")
	clearEnv(t, "OPENAI_API_KEY")
	setEnv(t, "GEMINI_API_KEY", "gemini-secret")
	clearEnv(t, "DASHSCOPE_API_KEY")

	opts, err := parseArgs([]string{"--", "opencode"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	final := resolveEnvVars(opts.envVars, nil, opts.subcommand)
	if !containsEnv(final, "ANTHROPIC_API_KEY=anthropic-secret") {
		t.Fatalf("expected ANTHROPIC_API_KEY to be injected, got %v", final)
	}
	if !containsEnv(final, "GEMINI_API_KEY=gemini-secret") {
		t.Fatalf("expected GEMINI_API_KEY to be injected, got %v", final)
	}
	if containsEnvWithKey(final, "OPENAI_API_KEY") {
		t.Fatalf("did not expect OPENAI_API_KEY to be injected, got %v", final)
	}
	if containsEnvWithKey(final, "DASHSCOPE_API_KEY") {
		t.Fatalf("did not expect absent env vars to be injected, got %v", final)
	}
}

func TestParseArgsOpenCodeRespectsOverrides(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	setEnv(t, "OPENAI_API_KEY", "host-secret")

	opts, err := parseArgs([]string{
		"-e", "OPENAI_API_KEY=custom",
		"--", "opencode",
	})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if !containsEnv(opts.envVars, "OPENAI_API_KEY=custom") {
		t.Fatalf("expected custom OPENAI_API_KEY to remain, got %v", opts.envVars)
	}
	if containsEnv(opts.envVars, "OPENAI_API_KEY=host-secret") {
		t.Fatalf("expected host OPENAI_API_KEY to be ignored due to override, got %v", opts.envVars)
	}
	if countEnvWithKey(opts.envVars, "OPENAI_API_KEY") != 1 {
		t.Fatalf("expected exactly one OPENAI_API_KEY entry, got %v", opts.envVars)
	}
	final := resolveEnvVars(opts.envVars, nil, opts.subcommand)
	if !containsEnv(final, "OPENAI_API_KEY=custom") {
		t.Fatalf("expected resolved env to include custom OPENAI, got %v", final)
	}
	if containsEnv(final, "OPENAI_API_KEY=host-secret") {
		t.Fatalf("expected resolved env to exclude host override, got %v", final)
	}
}

func TestResolveEnvVarsPrecedence(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	setEnv(t, "OPENAI_API_KEY", "autop-openai")

	args := []string{
		"-e", "BOO=cli-override",
		"-e", "CLI_ONLY=1",
		"--", "codex",
	}
	opts, err := parseArgs(args)
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	configEnv := map[string]configstore.EnvVarValue{
		"BOO":         {Value: "config-global", Scope: configstore.ScopeGlobal},
		"BAR":         {Value: "project-value", Scope: configstore.ScopeProject},
		"GLOBAL_ONLY": {Value: "global-only", Scope: configstore.ScopeGlobal},
	}

	final := resolveEnvVars(opts.envVars, configEnv, opts.subcommand)

	expected := []string{
		"OPENAI_API_KEY=autop-openai",
		"GLOBAL_ONLY=global-only",
		"BAR=project-value",
		"BOO=cli-override",
		"CLI_ONLY=1",
	}

	if len(final) != len(expected) {
		t.Fatalf("unexpected env length: got %d want %d (%v)", len(final), len(expected), final)
	}
	for i, want := range expected {
		if final[i] != want {
			t.Fatalf("env %d mismatch: got %q want %q (full: %v)", i, final[i], want, final)
		}
	}

	if containsEnv(final, "BOO=config-global") {
		t.Fatalf("expected CLI override to win for BOO, got %v", final)
	}
}

func containsEnv(envs []string, target string) bool {
	for _, env := range envs {
		if env == target {
			return true
		}
	}
	return false
}

func containsEnvWithKey(envs []string, key string) bool {
	prefix := key + "="
	for _, env := range envs {
		if env == key || strings.HasPrefix(env, prefix) {
			return true
		}
	}
	return false
}

func countEnvWithKey(envs []string, key string) int {
	prefix := key + "="
	count := 0
	for _, env := range envs {
		if env == key || strings.HasPrefix(env, prefix) {
			count++
		}
	}
	return count
}
