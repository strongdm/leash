package leashd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreFlightAllowsValidPrivateDir(t *testing.T) {
	t.Parallel()
	cfg, cleanup := setupRuntimeEnv(t, false)
	t.Cleanup(cleanup)

	if err := preFlight(cfg); err != nil {
		t.Fatalf("preFlight unexpectedly failed: %v", err)
	}
}

func TestPreFlightFailsOnKeyPermission(t *testing.T) {
	t.Parallel()
	cfg, cleanup := setupRuntimeEnv(t, true)
	t.Cleanup(cleanup)

	err := preFlight(cfg)
	if err == nil || !containsAll(err.Error(), "CA key", "0600") {
		t.Fatalf("expected key permission error, got %v", err)
	}
	tmpDir := t.TempDir()
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	outputPath := filepath.Join(tmpDir, "leashd-permission-errors.txt")
	if writeErr := os.WriteFile(outputPath, []byte("key-permission-error: "+err.Error()+"\n"), 0o644); writeErr != nil {
		t.Fatalf("write permission error snapshot: %v", writeErr)
	}
}

func TestPreFlightFailsWhenPrivateDirMissing(t *testing.T) {
	t.Parallel()

	privateDirMu.Lock()
	origPrivate, privateSet := os.LookupEnv("LEASH_PRIVATE_DIR")
	origPublic, publicSet := os.LookupEnv("LEASH_DIR")
	base := t.TempDir()
	t.Cleanup(func() {
		if privateSet {
			_ = os.Setenv("LEASH_PRIVATE_DIR", origPrivate)
		} else {
			_ = os.Unsetenv("LEASH_PRIVATE_DIR")
		}
		if publicSet {
			_ = os.Setenv("LEASH_DIR", origPublic)
		} else {
			_ = os.Unsetenv("LEASH_DIR")
		}
		privateDirMu.Unlock()
	})
	cgroupDir := filepath.Join(base, "cgroup")
	if err := os.MkdirAll(cgroupDir, 0o755); err != nil {
		t.Fatalf("create cgroup dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupDir, "cgroup.controllers"), nil, 0o644); err != nil {
		t.Fatalf("seed cgroup controllers: %v", err)
	}
	publicDir := filepath.Join(base, "public")
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		t.Fatalf("create public dir: %v", err)
	}
	if err := os.Setenv("LEASH_DIR", publicDir); err != nil {
		t.Fatalf("set LEASH_DIR: %v", err)
	}
	missingPrivate := filepath.Join(base, "missing-private")
	if err := os.Setenv("LEASH_PRIVATE_DIR", missingPrivate); err != nil {
		t.Fatalf("set missing LEASH_PRIVATE_DIR: %v", err)
	}
	cfg := &runtimeConfig{
		PolicyPath: filepath.Join(base, "policy.cedar"),
		ProxyPort:  defaultProxyPort,
		CgroupPath: cgroupDir,
	}
	if err := preFlight(cfg); err == nil || !containsAll(err.Error(), "LEASH_PRIVATE_DIR") {
		t.Fatalf("expected missing private dir error, got %v", err)
	}
}

func setupRuntimeEnv(t *testing.T, includeBadKey bool) (*runtimeConfig, func()) {
	t.Helper()

	privateDirMu.Lock()
	base := t.TempDir()
	origPrivate, privateSet := os.LookupEnv("LEASH_PRIVATE_DIR")
	origPublic, publicSet := os.LookupEnv("LEASH_DIR")
	privateDir := filepath.Join(base, "private")
	if err := os.MkdirAll(privateDir, 0o755); err != nil {
		t.Fatalf("create private dir: %v", err)
	}
	if err := os.Chmod(privateDir, 0o700); err != nil {
		t.Fatalf("chmod private dir: %v", err)
	}
	if err := os.Setenv("LEASH_PRIVATE_DIR", privateDir); err != nil {
		t.Fatalf("set LEASH_PRIVATE_DIR: %v", err)
	}
	if err := os.Setenv("LEASH_DIR", filepath.Join(base, "public")); err != nil {
		t.Fatalf("set LEASH_DIR: %v", err)
	}
	if includeBadKey {
		keyPath := filepath.Join(privateDir, "ca-key.pem")
		if err := os.WriteFile(keyPath, []byte("dummy"), 0o644); err != nil {
			t.Fatalf("seed bad key file: %v", err)
		}
		if info, statErr := os.Stat(keyPath); statErr != nil {
			t.Fatalf("stat key file: %v", statErr)
		} else if info.Mode().Perm() != 0o644 {
			t.Fatalf("expected key perm 0644, got %o", info.Mode().Perm())
		}
	}
	cgroupDir := filepath.Join(base, "cgroup")
	if err := os.MkdirAll(cgroupDir, 0o755); err != nil {
		t.Fatalf("create cgroup dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupDir, "cgroup.controllers"), nil, 0o644); err != nil {
		t.Fatalf("seed cgroup controllers: %v", err)
	}

	cfg := &runtimeConfig{
		PolicyPath: filepath.Join(base, "policy.cedar"),
		ProxyPort:  defaultProxyPort,
		CgroupPath: cgroupDir,
	}

	cleanup := func() {
		if privateSet {
			_ = os.Setenv("LEASH_PRIVATE_DIR", origPrivate)
		} else {
			_ = os.Unsetenv("LEASH_PRIVATE_DIR")
		}
		if publicSet {
			_ = os.Setenv("LEASH_DIR", origPublic)
		} else {
			_ = os.Unsetenv("LEASH_DIR")
		}
		if err := os.RemoveAll(base); err != nil {
			t.Fatalf("cleanup runtime env: %v", err)
		}
		privateDirMu.Unlock()
	}
	return cfg, cleanup
}

func containsAll(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if needle == "" || !strings.Contains(haystack, needle) {
			return false
		}
	}
	return true
}
