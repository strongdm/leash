package darwind

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExecRequiresCommand(t *testing.T) {
	t.Parallel()

	if err := runExec(nil); err == nil {
		t.Fatalf("expected error when command missing")
	}
}

func TestParseExecCLIArgs_Default(t *testing.T) {
	t.Parallel()

	path, args, err := parseExecCLIArgs([]string{"--", "echo", "hello"})
	if err != nil {
		t.Fatalf("parseExecCLIArgs returned error: %v", err)
	}
	if path != defaultLeashCLIPath {
		t.Fatalf("expected default path %q, got %q", defaultLeashCLIPath, path)
	}
	if len(args) != 3 || args[0] != "--" {
		t.Fatalf("unexpected passthrough args: %#v", args)
	}
}

func TestParseExecCLIArgsOverride(t *testing.T) {
	t.Parallel()

	path, args, err := parseExecCLIArgs([]string{"--leash-cli-path", "/tmp/custom", "-v"})
	if err != nil {
		t.Fatalf("parseExecCLIArgs returned error: %v", err)
	}
	if path != "/tmp/custom" {
		t.Fatalf("expected override path /tmp/custom, got %q", path)
	}
	if len(args) != 1 || args[0] != "-v" {
		t.Fatalf("unexpected passthrough args: %#v", args)
	}
}

func TestParseExecCLIArgsOverrideEquals(t *testing.T) {
	t.Parallel()

	path, args, err := parseExecCLIArgs([]string{"--leash-cli-path=/usr/local/bin/leashcli", "status"})
	if err != nil {
		t.Fatalf("parseExecCLIArgs returned error: %v", err)
	}
	if path != "/usr/local/bin/leashcli" {
		t.Fatalf("expected override path, got %q", path)
	}
	if len(args) != 1 || args[0] != "status" {
		t.Fatalf("unexpected passthrough args: %#v", args)
	}
}

func TestParseExecCLIArgsMissingValue(t *testing.T) {
	t.Parallel()

	if _, _, err := parseExecCLIArgs([]string{"--leash-cli-path"}); err == nil {
		t.Fatalf("expected error for missing override value")
	}
	if _, _, err := parseExecCLIArgs([]string{"--leash-cli-path="}); err == nil {
		t.Fatalf("expected error for empty override value")
	}
}

func TestIsExecHelpRequest(t *testing.T) {
	t.Parallel()

	if !isExecHelpRequest([]string{"--help"}) {
		t.Fatalf("expected --help to be recognized")
	}
	if !isExecHelpRequest([]string{"-h"}) {
		t.Fatalf("expected -h to be recognized")
	}
	if !isExecHelpRequest([]string{"--", "help"}) {
		t.Fatalf("expected help after -- to be recognized")
	}
	if isExecHelpRequest([]string{"status"}) {
		t.Fatalf("unexpected help detection for normal command")
	}
}

func TestPreFlightSetsDefaultPrivateDir(t *testing.T) {
	// t.Parallel avoided: this test mutates process-wide environment variables and
	// log sinks; running in parallel would race with other tests that rely on the
	// same globals.
	origPublic, hadPublic := os.LookupEnv("LEASH_DIR")
	origPrivate, hadPrivate := os.LookupEnv("LEASH_PRIVATE_DIR")
	shareDir := t.TempDir()
	if err := os.Setenv("LEASH_DIR", shareDir); err != nil {
		t.Fatalf("set LEASH_DIR: %v", err)
	}
	if err := os.Unsetenv("LEASH_PRIVATE_DIR"); err != nil && !os.IsNotExist(err) {
		t.Fatalf("unset LEASH_PRIVATE_DIR: %v", err)
	}
	t.Cleanup(func() {
		if hadPublic {
			_ = os.Setenv("LEASH_DIR", origPublic)
		} else {
			_ = os.Unsetenv("LEASH_DIR")
		}
		if hadPrivate {
			_ = os.Setenv("LEASH_PRIVATE_DIR", origPrivate)
		} else {
			_ = os.Unsetenv("LEASH_PRIVATE_DIR")
		}
	})

	cfg := &runtimeConfig{
		PolicyPath: filepath.Join(t.TempDir(), "policy.cedar"),
		SkipCgroup: true,
		ProxyPort:  defaultProxyPort,
	}

	if err := preFlight(cfg); err != nil {
		t.Fatalf("preFlight returned error: %v", err)
	}

	privateEnv := os.Getenv("LEASH_PRIVATE_DIR")
	expected := filepath.Join(shareDir, "private")
	if privateEnv != expected {
		t.Fatalf("LEASH_PRIVATE_DIR = %q, want %q", privateEnv, expected)
	}
	info, err := os.Stat(privateEnv)
	if err != nil {
		t.Fatalf("stat private dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected private dir to exist")
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("private dir permissions = %04o, want 0700", perm)
	}
}

func TestPreFlightRepairsPrivateDirPermissions(t *testing.T) {
	// t.Parallel avoided: relies on shared environment variables and redirects the
	// global logger, both of which are process-wide state.
	origPublic, hadPublic := os.LookupEnv("LEASH_DIR")
	origPrivate, hadPrivate := os.LookupEnv("LEASH_PRIVATE_DIR")
	shareDir := t.TempDir()
	privateDir := filepath.Join(shareDir, "private")
	if err := os.MkdirAll(privateDir, 0o755); err != nil {
		t.Fatalf("mkdir private dir: %v", err)
	}
	if err := os.Setenv("LEASH_DIR", shareDir); err != nil {
		t.Fatalf("set LEASH_DIR: %v", err)
	}
	if err := os.Setenv("LEASH_PRIVATE_DIR", privateDir); err != nil {
		t.Fatalf("set LEASH_PRIVATE_DIR: %v", err)
	}

	origWriter := log.Writer()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(origWriter)
	})

	t.Cleanup(func() {
		if hadPublic {
			_ = os.Setenv("LEASH_DIR", origPublic)
		} else {
			_ = os.Unsetenv("LEASH_DIR")
		}
		if hadPrivate {
			_ = os.Setenv("LEASH_PRIVATE_DIR", origPrivate)
		} else {
			_ = os.Unsetenv("LEASH_PRIVATE_DIR")
		}
	})

	cfg := &runtimeConfig{
		PolicyPath: filepath.Join(t.TempDir(), "policy.cedar"),
		SkipCgroup: true,
		ProxyPort:  defaultProxyPort,
	}

	if err := preFlight(cfg); err != nil {
		t.Fatalf("preFlight returned error: %v", err)
	}

	info, err := os.Stat(privateDir)
	if err != nil {
		t.Fatalf("stat private dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("private dir permissions = %04o after preFlight, want 0700", perm)
	}
	output := buf.String()
	if !strings.Contains(output, "event=darwin.private-dir.permissions.adjust") {
		t.Fatalf("expected private dir adjustment log, got %q", output)
	}
	if !strings.Contains(output, "new=0700") {
		t.Fatalf("expected new=0700 in log, got %q", output)
	}
}

func TestPreFlightRepairsPrivateKeyPermissions(t *testing.T) {
	// t.Parallel avoided: manipulates global env vars and logger output.
	origPublic, hadPublic := os.LookupEnv("LEASH_DIR")
	origPrivate, hadPrivate := os.LookupEnv("LEASH_PRIVATE_DIR")
	shareDir := t.TempDir()
	privateDir := filepath.Join(shareDir, "private")
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		t.Fatalf("mkdir private dir: %v", err)
	}
	keyPath := filepath.Join(privateDir, "ca-key.pem")
	if err := os.WriteFile(keyPath, []byte("key"), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Setenv("LEASH_DIR", shareDir); err != nil {
		t.Fatalf("set LEASH_DIR: %v", err)
	}
	if err := os.Setenv("LEASH_PRIVATE_DIR", privateDir); err != nil {
		t.Fatalf("set LEASH_PRIVATE_DIR: %v", err)
	}

	origWriter := log.Writer()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(origWriter)
	})

	t.Cleanup(func() {
		if hadPublic {
			_ = os.Setenv("LEASH_DIR", origPublic)
		} else {
			_ = os.Unsetenv("LEASH_DIR")
		}
		if hadPrivate {
			_ = os.Setenv("LEASH_PRIVATE_DIR", origPrivate)
		} else {
			_ = os.Unsetenv("LEASH_PRIVATE_DIR")
		}
	})

	cfg := &runtimeConfig{
		PolicyPath: filepath.Join(t.TempDir(), "policy.cedar"),
		SkipCgroup: true,
		ProxyPort:  defaultProxyPort,
	}

	if err := preFlight(cfg); err != nil {
		t.Fatalf("preFlight returned error: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key permissions = %04o after preFlight, want 0600", perm)
	}
	output := buf.String()
	if !strings.Contains(output, "event=darwin.private-key.permissions.adjust") {
		t.Fatalf("expected private key adjustment log, got %q", output)
	}
	if !strings.Contains(output, "new=0600") {
		t.Fatalf("expected new=0600 in log, got %q", output)
	}
}
