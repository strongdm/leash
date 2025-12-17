package configstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeExtraMountsForReturnsMount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	host := filepath.Join(dir, ".codex")
	if err := os.MkdirAll(host, 0o755); err != nil {
		t.Fatalf("mkdir host dir: %v", err)
	}

	outcome := PromptOutcome{
		Mount:     true,
		Scope:     ScopeGlobal,
		Persisted: true,
		HostDir:   host,
	}

	mounts, err := ComputeExtraMountsFor("codex", outcome, nil)
	if err != nil {
		t.Fatalf("ComputeExtraMountsFor returned error: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	mount := mounts[0]
	if mount.Host != host {
		t.Fatalf("unexpected host: %s", mount.Host)
	}
	if mount.Container != "/root/.codex" {
		t.Fatalf("unexpected container: %s", mount.Container)
	}
	if mount.Mode != "rw" {
		t.Fatalf("expected read-write mode, got %s", mount.Mode)
	}
	if !mount.Persisted {
		t.Fatalf("expected persisted to be true")
	}
	if mount.Kind != MountKindDirectory {
		t.Fatalf("expected directory mount, got kind %d", mount.Kind)
	}
}

func TestComputeExtraMountsForMissingHost(t *testing.T) {
	t.Parallel()
	outcome := PromptOutcome{Mount: true, HostDir: filepath.Join(t.TempDir(), "missing")}
	mounts, err := ComputeExtraMountsFor("codex", outcome, nil)
	if err != nil {
		t.Fatalf("ComputeExtraMountsFor returned error: %v", err)
	}
	if len(mounts) != 0 {
		t.Fatalf("expected no mounts when host missing, got %d", len(mounts))
	}
}

func TestComputeExtraMountsForUnsupportedCommand(t *testing.T) {
	t.Parallel()
	outcome := PromptOutcome{Mount: true, HostDir: t.TempDir()}
	if _, err := ComputeExtraMountsFor("notreal", outcome, nil); err == nil {
		t.Fatal("expected error for unsupported command")
	}
}

func TestComputeExtraMountsForSkippingWhenDisabled(t *testing.T) {
	t.Parallel()
	outcome := PromptOutcome{Mount: false, HostDir: t.TempDir()}
	mounts, err := ComputeExtraMountsFor("codex", outcome, nil)
	if err != nil {
		t.Fatalf("ComputeExtraMountsFor returned error: %v", err)
	}
	if len(mounts) != 0 {
		t.Fatalf("expected no mounts when outcome disabled")
	}
}

func TestComputeExtraMountsForClaudeIncludesConfigFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	host := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(host, 0o755); err != nil {
		t.Fatalf("mkdir host dir: %v", err)
	}
	configFile := filepath.Join(dir, ".claude.json")
	if err := os.WriteFile(configFile, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	outcome := PromptOutcome{
		Mount:     true,
		Scope:     ScopeGlobal,
		Persisted: true,
		HostDir:   host,
	}

	mounts, err := ComputeExtraMountsFor("claude", outcome, nil)
	if err != nil {
		t.Fatalf("ComputeExtraMountsFor returned error: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}

	dirMount := mounts[0]
	fileMount := mounts[1]

	if dirMount.Kind != MountKindDirectory {
		t.Fatalf("expected first mount to be directory, got %d", dirMount.Kind)
	}
	if fileMount.Kind != MountKindFile {
		t.Fatalf("expected second mount to be file, got %d", fileMount.Kind)
	}
	if fileMount.Host != configFile {
		t.Fatalf("unexpected file host: %s", fileMount.Host)
	}
	if fileMount.Container != "/root/.claude.json" {
		t.Fatalf("unexpected file container: %s", fileMount.Container)
	}
}

// This test rewires HOME/XDG vars; keep serial to avoid leaking environment.
func TestComputeExtraMountsForOpencodePrefersXDGPaths(t *testing.T) {
	home := t.TempDir()
	testSetEnv(t, "HOME", home)
	testSetEnv(t, "XDG_CONFIG_HOME", "")
	testSetEnv(t, "XDG_STATE_HOME", "")
	testSetEnv(t, "XDG_DATA_HOME", "")

	configDir := filepath.Join(home, ".config", "opencode")
	stateDir := filepath.Join(home, ".local", "state", "opencode")
	dataDir := filepath.Join(home, ".local", "share", "opencode")

	for _, dir := range []string{configDir, stateDir, filepath.Join(dataDir, "log"), filepath.Join(dataDir, "snapshot"), filepath.Join(dataDir, "storage")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	authPath := filepath.Join(dataDir, "auth.json")
	if err := os.WriteFile(authPath, []byte(`{"token":"abc"}`), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	outcome := PromptOutcome{
		Mount:     true,
		Scope:     ScopeGlobal,
		Persisted: true,
		HostDir:   configDir,
	}

	mounts, err := ComputeExtraMountsFor("opencode", outcome, nil)
	if err != nil {
		t.Fatalf("ComputeExtraMountsFor returned error: %v", err)
	}

	if len(mounts) != 6 {
		t.Fatalf("expected 6 mounts, got %d", len(mounts))
	}

	want := map[string]struct {
		host string
		kind MountKind
	}{
		"/root/.config/opencode":                {host: configDir, kind: MountKindDirectory},
		"/root/.local/state/opencode":           {host: stateDir, kind: MountKindDirectory},
		"/root/.local/share/opencode/auth.json": {host: authPath, kind: MountKindFile},
		"/root/.local/share/opencode/log":       {host: filepath.Join(dataDir, "log"), kind: MountKindDirectory},
		"/root/.local/share/opencode/snapshot":  {host: filepath.Join(dataDir, "snapshot"), kind: MountKindDirectory},
		"/root/.local/share/opencode/storage":   {host: filepath.Join(dataDir, "storage"), kind: MountKindDirectory},
	}

	for _, mount := range mounts {
		entry, ok := want[mount.Container]
		if !ok {
			t.Fatalf("unexpected mount target %s", mount.Container)
		}
		if mount.Host != entry.host {
			t.Fatalf("mount %s host = %s, want %s", mount.Container, mount.Host, entry.host)
		}
		if mount.Kind != entry.kind {
			t.Fatalf("mount %s kind = %d, want %d", mount.Container, mount.Kind, entry.kind)
		}
	}
}

func TestComputeExtraMountsForOpencodeIncludesLegacyDir(t *testing.T) {
	home := t.TempDir()
	testSetEnv(t, "HOME", home)
	testSetEnv(t, "XDG_CONFIG_HOME", "")
	testSetEnv(t, "XDG_STATE_HOME", "")
	testSetEnv(t, "XDG_DATA_HOME", "")

	legacyDir := filepath.Join(home, ".opencode")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatalf("mkdir legacyDir: %v", err)
	}

	outcome := PromptOutcome{
		Mount:     true,
		Scope:     ScopeGlobal,
		Persisted: true,
		HostDir:   legacyDir,
	}

	mounts, err := ComputeExtraMountsFor("opencode", outcome, nil)
	if err != nil {
		t.Fatalf("ComputeExtraMountsFor returned error: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	m := mounts[0]
	if m.Host != legacyDir {
		t.Fatalf("unexpected host: %s", m.Host)
	}
	if m.Container != "/root/.opencode" {
		t.Fatalf("unexpected container: %s", m.Container)
	}
	if m.Kind != MountKindDirectory {
		t.Fatalf("expected directory mount, got %d", m.Kind)
	}
}

// This test sets HOME so the tilde resolver sees a predictable directory; keep
// it serial to avoid leaking temporary paths to parallel tests.
func TestResolveCustomVolumesGlobal(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HOME", base)

	cfg := New()
	cfg.CustomVolumes["~/data"] = "/workspace/data:ro"

	mounts, err := cfg.ResolveCustomVolumes("", base)
	if err != nil {
		t.Fatalf("ResolveCustomVolumes returned error: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	m := mounts[0]
	if m.Name != "~/data" {
		t.Fatalf("expected mount name '~/data', got %q", m.Name)
	}
	expectedHost := filepath.Join(base, "data")
	if m.Host != expectedHost {
		t.Fatalf("expected host %q, got %q", expectedHost, m.Host)
	}
	if m.Container != "/workspace/data" {
		t.Fatalf("unexpected container %q", m.Container)
	}
	if m.Mode != "ro" {
		t.Fatalf("unexpected mode %q", m.Mode)
	}
	if m.Scope != ScopeGlobal {
		t.Fatalf("expected scope global, got %s", m.Scope)
	}
	if m.Kind != MountKindUnknown {
		t.Fatalf("expected unknown kind, got %d", m.Kind)
	}
}

func TestResolveCustomVolumesProjectOverride(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	project := filepath.Join(base, "app")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}

	cfg := New()
	cfg.CustomVolumes["/opt/shared"] = "/opt/shared:rw"

	key, err := normalizeProjectKey(project)
	if err != nil {
		t.Fatalf("normalizeProjectKey: %v", err)
	}
	cfg.ProjectCustomVolumes[key] = map[string]string{
		"/opt/shared": "/workspace/override:ro",
	}

	mounts, err := cfg.ResolveCustomVolumes(project, project)
	if err != nil {
		t.Fatalf("ResolveCustomVolumes returned error: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	m := mounts[0]
	if m.Scope != ScopeProject {
		t.Fatalf("expected project scope, got %s", m.Scope)
	}
	if m.Mode != "ro" {
		t.Fatalf("expected mode ro, got %q", m.Mode)
	}
	if m.Host != "/opt/shared" {
		t.Fatalf("expected host /opt/shared, got %q", m.Host)
	}
	if m.Container != "/workspace/override" {
		t.Fatalf("unexpected container %q", m.Container)
	}
}

// This test rewrites HOME to validate project volume disabling; run it serially.
func TestResolveCustomVolumesProjectDisable(t *testing.T) {
	project := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := New()
	cfg.CustomVolumes["~/scratch"] = "/workspace/.scratch:rw"

	key, err := normalizeProjectKey(project)
	if err != nil {
		t.Fatalf("normalizeProjectKey: %v", err)
	}
	cfg.ProjectVolumeDisables[key] = map[string]bool{"${HOME}/scratch": true}

	mounts, err := cfg.ResolveCustomVolumes(project, project)
	if err != nil {
		t.Fatalf("ResolveCustomVolumes returned error: %v", err)
	}
	if len(mounts) != 0 {
		t.Fatalf("expected volume to be disabled, got %d entries", len(mounts))
	}
}
