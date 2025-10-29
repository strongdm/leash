package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureShareDirCreates0755(t *testing.T) {
	t.Parallel()

	workDir := t.TempDir()

	r := &runner{
		cfg: config{
			workDir: workDir,
		},
	}

	if err := r.ensureShareDir(); err != nil {
		t.Fatalf("ensureShareDir returned error: %v", err)
	}

	info, err := os.Stat(r.cfg.shareDir)
	if err != nil {
		t.Fatalf("stat share dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected share dir %q to be a directory", r.cfg.shareDir)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Fatalf("share dir permissions = %04o, want 0755", perm)
	}
	if !r.shareDirCreated {
		t.Fatalf("expected shareDirCreated to be true")
	}
}

func TestEnsureShareDirFixesEnvPermissions(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	custom := filepath.Join(root, "custom")
	if err := os.Mkdir(custom, 0o700); err != nil {
		t.Fatalf("mkdir custom share dir: %v", err)
	}

	r := &runner{
		cfg: config{
			shareDir:        custom,
			shareDirFromEnv: true,
		},
	}

	if err := r.ensureShareDir(); err != nil {
		t.Fatalf("ensureShareDir returned error: %v", err)
	}

	info, err := os.Stat(r.cfg.shareDir)
	if err != nil {
		t.Fatalf("stat share dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected share dir %q to remain a directory", r.cfg.shareDir)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Fatalf("share dir permissions = %04o, want 0755", perm)
	}
	if r.shareDirCreated {
		t.Fatalf("expected shareDirCreated to be false for env override")
	}
}

func TestEnsureShareDirRejectsFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	filePath := filepath.Join(root, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("data"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	r := &runner{
		cfg: config{
			shareDir:        filePath,
			shareDirFromEnv: true,
		},
	}

	if err := r.ensureShareDir(); err == nil {
		t.Fatalf("expected error when share dir path is a file")
	}
}
