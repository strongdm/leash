package runner

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsurePrivateDirCreatesRestrictedDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	privatePath := filepath.Join(root, "private")

	r := &runner{
		cfg: config{
			privateDir: privatePath,
		},
	}

	if err := r.ensurePrivateDir(); err != nil {
		t.Fatalf("ensurePrivateDir returned error: %v", err)
	}

	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatalf("stat private dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected private path to be directory, got %v", info.Mode())
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("private dir mode = %04o, want 0700", info.Mode().Perm())
	}
	if !r.cfg.privateDirCreated {
		t.Fatalf("expected privateDirCreated to be true after creation")
	}
}

func TestEnsurePrivateDirResetsPermissionsForExistingPath(t *testing.T) {
	t.Parallel()

	privateDir := t.TempDir()
	if err := os.Chmod(privateDir, 0o755); err != nil {
		t.Fatalf("chmod private dir: %v", err)
	}

	r := &runner{
		cfg: config{
			privateDir: privateDir,
		},
	}

	if err := r.ensurePrivateDir(); err != nil {
		t.Fatalf("ensurePrivateDir returned error: %v", err)
	}

	info, err := os.Stat(privateDir)
	if err != nil {
		t.Fatalf("stat private dir: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("private dir mode = %04o after ensure, want 0700", info.Mode().Perm())
	}
	if r.cfg.privateDirCreated {
		t.Fatalf("expected privateDirCreated to be false when directory already existed")
	}
}

func TestEnsurePrivateDirLogsPermissionAdjustment(t *testing.T) {
	t.Parallel()

	privateDir := t.TempDir()
	if err := os.Chmod(privateDir, 0o755); err != nil {
		t.Fatalf("chmod private dir: %v", err)
	}

	var buf bytes.Buffer
	r := &runner{
		logger: log.New(&buf, "", 0),
		cfg: config{
			privateDir: privateDir,
		},
	}
	r.verbose = true

	if err := r.ensurePrivateDir(); err != nil {
		t.Fatalf("ensurePrivateDir returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "event=runner.private-dir.permissions.adjust") {
		t.Fatalf("expected permissions adjust event, got %q", output)
	}
	for _, fragment := range []string{"previous=\"0755\"", "new=\"0700\"", "source=\"existing\""} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected log to contain %s, got %q", fragment, output)
		}
	}
	if !strings.Contains(output, "event=runner.private-dir.ready") {
		t.Fatalf("expected ready event in log, got %q", output)
	}
	if !strings.Contains(output, "path=\"") {
		t.Fatalf("expected ready event to include path, got %q", output)
	}
}

func TestEnsurePrivateDirRejectsEmptyPath(t *testing.T) {
	t.Parallel()

	r := &runner{cfg: config{privateDir: ""}}

	if err := r.ensurePrivateDir(); err == nil {
		t.Fatalf("expected error when private dir path is empty")
	}
}

func TestEnsurePrivateDirRejectsFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	filePath := filepath.Join(root, "private-file")
	if err := os.WriteFile(filePath, []byte("data"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	r := &runner{
		cfg: config{
			privateDir: filePath,
		},
	}

	if err := r.ensurePrivateDir(); err == nil {
		t.Fatalf("expected error when private dir path is a file")
	} else if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected not-a-directory error, got %v", err)
	}
}
