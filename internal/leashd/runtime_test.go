package leashd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/strongdm/leash/internal/policy"
)

const sampleCedarPolicy = `permit (
    principal,
    action == Action::"FileOpen",
    resource
)
when {
    resource in [ Dir::"/tmp" ]
};`

var iptablesOverrideMu sync.Mutex

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.cedar")
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}
	return path
}

func createCgroupStub(t *testing.T, withControllers bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cgroup")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to create cgroup dir: %v", err)
	}
	if withControllers {
		controllerFile := filepath.Join(dir, "cgroup.controllers")
		if err := os.WriteFile(controllerFile, []byte(""), 0o644); err != nil {
			t.Fatalf("failed to create cgroup.controllers: %v", err)
		}
	}
	return dir
}

func TestPreFlightNilConfig(t *testing.T) {
	t.Parallel()
	if err := preFlight(nil); err == nil || err.Error() != "runtime configuration required" {
		t.Fatalf("expected runtime configuration error, got %v", err)
	}
}

func TestPreFlightMissingPolicy(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "missing.cedar")
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err != nil {
		t.Fatalf("expected preFlight to create default policy, got %v", err)
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("expected default policy file to be created: %v", err)
	}
	got := strings.TrimSpace(string(data))
	want := strings.TrimSpace(policy.DefaultCedar())
	if got != want {
		t.Fatalf("default Cedar contents unexpected: got %q want %q", got, want)
	}
}

func TestPreFlightInvalidCedar(t *testing.T) {
	t.Parallel()
	badCedar := "permit (principal"
	policyPath := writePolicyFile(t, badCedar)
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "invalid Cedar policy") {
		t.Fatalf("expected invalid Cedar error, got %v", err)
	}
}

func TestPreFlightUnreadablePolicy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.cedar")
	if err := os.Mkdir(policyPath, 0o755); err != nil {
		t.Fatalf("failed to create directory placeholder: %v", err)
	}
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "invalid Cedar policy") {
		t.Fatalf("expected invalid Cedar error due to unreadable file, got %v", err)
	}
}

func TestEnsureDefaultCedarFileCreatesBaselineWhenMissing(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cedarPath := filepath.Join(tempDir, "leash.cedar")

	if err := policy.EnsureDefaultCedarFile(cedarPath); err != nil {
		t.Fatalf("EnsureDefaultCedarFile returned error: %v", err)
	}

	data, err := os.ReadFile(cedarPath)
	if err != nil {
		t.Fatalf("expected cedar file to be created: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || !strings.Contains(trimmed, `Action::"NetworkConnect"`) {
		t.Fatalf("expected default cedar content, got %q", trimmed)
	}
}

func TestPreFlightValidConfig(t *testing.T) {
	t.Parallel()
	policyPath := writePolicyFile(t, sampleCedarPolicy)
	tempRoot := t.TempDir()
	logPath := filepath.Join(tempRoot, "logs", "events.log")
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		LogPath:    logPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err != nil {
		t.Fatalf("expected valid preFlight, got %v", err)
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("expected log file to be created, got %v", err)
	}
}

func TestPreFlightInvalidCgroup(t *testing.T) {
	t.Parallel()
	policyPath := writePolicyFile(t, sampleCedarPolicy)
	cgroupDir := createCgroupStub(t, false)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupDir,
	}
	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "cgroup path") {
		t.Fatalf("expected invalid cgroup error, got %v", err)
	}
}

func TestPreFlightInvalidProxyPort(t *testing.T) {
	t.Parallel()
	policyPath := writePolicyFile(t, sampleCedarPolicy)
	cgroupPath := createCgroupStub(t, true)
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		ProxyPort:  "not-a-port",
		CgroupPath: cgroupPath,
	}
	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "invalid proxy port") {
		t.Fatalf("expected proxy port error, got %v", err)
	}
}

func TestParseConfigListenEnvDisable(t *testing.T) {
	t.Setenv("LEASH_LISTEN", "")
	cfg, err := parseConfig([]string{"leashd"})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if !cfg.WebDisabled {
		t.Fatalf("expected control UI disabled when LEASH_LISTEN is empty")
	}
	if cfg.WebBind != "" {
		t.Fatalf("expected empty WebBind, got %q", cfg.WebBind)
	}
}

func TestParseConfigListenEnvValue(t *testing.T) {
	t.Setenv("LEASH_LISTEN", ":19003")
	cfg, err := parseConfig([]string{"leashd"})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if cfg.WebBind != ":19003" {
		t.Fatalf("expected WebBind :19003, got %q", cfg.WebBind)
	}
	if cfg.WebDisabled {
		t.Fatalf("expected control UI enabled")
	}
}

func TestParseConfigListenFlagOverridesEnv(t *testing.T) {
	t.Setenv("LEASH_LISTEN", ":19001")
	cfg, err := parseConfig([]string{"leashd", "--listen", "127.0.0.1:19002"})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if cfg.WebBind != "127.0.0.1:19002" {
		t.Fatalf("expected WebBind 127.0.0.1:19002, got %q", cfg.WebBind)
	}
	if cfg.WebDisabled {
		t.Fatalf("expected control UI enabled")
	}
}

func TestPreFlightMissingIptables(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("iptables dependency only enforced on linux")
	}
	policyPath := writePolicyFile(t, sampleCedarPolicy)
	tempRoot := t.TempDir()
	logPath := filepath.Join(tempRoot, "events.log")
	cgroupPath := createCgroupStub(t, true)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	mountPath := filepath.Join(binDir, "mount")
	if err := os.WriteFile(mountPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to create mount stub: %v", err)
	}
	originalPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", binDir); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("PATH", originalPath)
	})
	cfg := &runtimeConfig{
		PolicyPath: policyPath,
		LogPath:    logPath,
		ProxyPort:  "18000",
		CgroupPath: cgroupPath,
	}

	iptablesOverrideMu.Lock()
	restoreName := iptablesBinaryName
	iptablesBinaryName = "iptables_missing_for_test"
	t.Cleanup(func() {
		iptablesBinaryName = restoreName
		iptablesOverrideMu.Unlock()
	})

	if err := preFlight(cfg); err == nil || !strings.Contains(err.Error(), "iptables") {
		t.Fatalf("expected iptables error, got %v", err)
	}
}
