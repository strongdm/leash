package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveWorkspaceCandidateAcceptsExistingDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	got, err := resolveWorkspaceCandidate(dir)
	if err != nil {
		t.Fatalf("resolveWorkspaceCandidate(%q) returned error: %v", dir, err)
	}
	if got != dir {
		t.Fatalf("expected %q, got %q", dir, got)
	}
}

func TestResolveWorkspaceCandidateAllowsRelativePaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sub := filepath.Join(dir, "child")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", sub, err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	rel, err := filepath.Rel(wd, sub)
	if err != nil {
		t.Fatalf("rel path: %v", err)
	}

	got, err := resolveWorkspaceCandidate(rel)
	if err != nil {
		t.Fatalf("resolveWorkspaceCandidate(%q) returned error: %v", rel, err)
	}
	if got != sub {
		t.Fatalf("expected %q, got %q", sub, got)
	}
}

func TestResolveWorkspaceCandidateRejectsMissingDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")

	if _, err := resolveWorkspaceCandidate(missing); err == nil {
		t.Fatalf("expected error when resolving %q", missing)
	}
}

func TestResolveWorkspaceCandidateRejectsFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("content"), 0o644); err != nil {
		t.Fatalf("write file %q: %v", file, err)
	}

	if _, err := resolveWorkspaceCandidate(file); err == nil {
		t.Fatalf("expected error when resolving file %q", file)
	}
}

func TestWorkspaceDirUsesWorkingDirectory(t *testing.T) {
	t.Parallel()

	lockEnv(t)
	clearEnv(t, "LEASH_WORKSPACE")

	tmp := t.TempDir()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir %q: %v", tmp, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	expected, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd after chdir: %v", err)
	}

	root, err := workspaceDir()
	if err != nil {
		t.Fatalf("workspaceDir returned error: %v", err)
	}
	evalExpected, err := filepath.EvalSymlinks(expected)
	if err != nil {
		t.Fatalf("eval expected: %v", err)
	}
	evalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("eval root: %v", err)
	}
	if evalRoot != evalExpected {
		t.Fatalf("expected %q, got %q", evalExpected, evalRoot)
	}
}

func TestWorkspaceDirHonorsEnvOverride(t *testing.T) {
	t.Parallel()

	lockEnv(t)

	override := t.TempDir()
	setEnv(t, "LEASH_WORKSPACE", override)
	expected, err := filepath.Abs(override)
	if err != nil {
		t.Fatalf("abs override: %v", err)
	}

	root, err := workspaceDir()
	if err != nil {
		t.Fatalf("workspaceDir returned error: %v", err)
	}
	if root != expected {
		t.Fatalf("expected %q, got %q", expected, root)
	}
}
