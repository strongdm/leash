package configstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// This test mutates HOME and persists config state; keep it serial to avoid
// leaking temporary directories to other tests.
func TestMaybePromptInteractiveGlobalPersist(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	home := t.TempDir()
	setHome(t, home)
	mustMkdir(t, filepath.Join(home, ".codex"))
	project := filepath.Join(home, "proj")

	cfg := New()
	var saved Config
	controller := &PromptController{
		Config: &cfg,
		Prompter: &fakePrompter{
			confirm: true,
			scope:   ScopeChoiceGlobal,
		},
		SaveFunc: func(in Config) error {
			saved = in
			return nil
		},
	}

	outcome, err := controller.MaybePrompt(context.Background(), "codex", project, true)
	if err != nil {
		t.Fatalf("MaybePrompt returned error: %v", err)
	}
	if !outcome.Mount || outcome.Scope != ScopeGlobal || !outcome.Persisted {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	decision, err := controller.Config.GetEffectiveVolume("codex", "")
	if err != nil {
		t.Fatalf("effective mount: %v", err)
	}
	if !decision.Enabled || decision.Scope != ScopeGlobal {
		t.Fatalf("expected persisted global, got %+v", decision)
	}
	loadedDecision, err := saved.GetEffectiveVolume("codex", "")
	if err != nil {
		t.Fatalf("saved effective mount: %v", err)
	}
	if !loadedDecision.Enabled {
		t.Fatalf("expected saved config to persist decision: %+v", loadedDecision)
	}
}

// This test alters HOME and project directories; run serially to protect shared
// environment variables.
func TestMaybePromptInteractiveProjectPersist(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	home := t.TempDir()
	setHome(t, home)
	mustMkdir(t, filepath.Join(home, ".claude"))
	project := filepath.Join(home, "proj")
	mustMkdir(t, project)

	cfg := New()
	controller := &PromptController{
		Config: &cfg,
		Prompter: &fakePrompter{
			confirm: true,
			scope:   ScopeChoiceProject,
		},
		SaveFunc: func(Config) error { return nil },
	}

	outcome, err := controller.MaybePrompt(context.Background(), "claude", project, true)
	if err != nil {
		t.Fatalf("MaybePrompt returned error: %v", err)
	}
	if !outcome.Mount || outcome.Scope != ScopeProject || !outcome.Persisted {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	decision, err := controller.Config.GetEffectiveVolume("claude", project)
	if err != nil {
		t.Fatalf("effective mount: %v", err)
	}
	if !decision.Enabled || decision.Scope != ScopeProject {
		t.Fatalf("expected project scope, got %+v", decision)
	}
}

// This test rewrites HOME while exercising ephemeral decisions; keep it serial.
func TestMaybePromptInteractiveEphemeral(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	home := t.TempDir()
	setHome(t, home)
	mustMkdir(t, filepath.Join(home, ".gemini"))

	cfg := New()
	controller := &PromptController{
		Config: &cfg,
		Prompter: &fakePrompter{
			confirm: true,
			scope:   ScopeChoiceOnce,
		},
		SaveFunc: func(Config) error { t.Fatal("save should not be called for ephemeral"); return nil },
	}

	outcome, err := controller.MaybePrompt(context.Background(), "gemini", filepath.Join(home, "proj"), true)
	if err != nil {
		t.Fatalf("MaybePrompt returned error: %v", err)
	}
	if !outcome.Mount || outcome.Scope != ScopeEphemeral || outcome.Persisted {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	decision, err := controller.Config.GetEffectiveVolume("gemini", filepath.Join(home, "proj"))
	if err != nil {
		t.Fatalf("effective mount: %v", err)
	}
	if decision.Enabled {
		t.Fatalf("expected ephemeral decision to leave config untouched: %+v", decision)
	}
}

// This test rewires HOME to check non-interactive behavior; run serially.
func TestMaybePromptNonInteractiveSkipsPrompt(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	home := t.TempDir()
	setHome(t, home)
	mustMkdir(t, filepath.Join(home, ".qwen"))

	cfg := New()
	controller := &PromptController{Config: &cfg}

	outcome, err := controller.MaybePrompt(context.Background(), "qwen", filepath.Join(home, "proj"), false)
	if err != nil {
		t.Fatalf("MaybePrompt returned error: %v", err)
	}
	if outcome.Mount {
		t.Fatalf("expected no mount in non-interactive flow, got %+v", outcome)
	}
}

// This test writes config under a temporary HOME and must be serial.
func TestMaybePromptSaveFailureFallsBackToEphemeral(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	home := t.TempDir()
	setHome(t, home)
	mustMkdir(t, filepath.Join(home, ".opencode"))

	cfg := New()
	saveErr := errors.New("boom")
	controller := &PromptController{
		Config: &cfg,
		Prompter: &fakePrompter{
			confirm: true,
			scope:   ScopeChoiceGlobal,
		},
		SaveFunc: func(Config) error { return saveErr },
	}

	outcome, err := controller.MaybePrompt(context.Background(), "opencode", filepath.Join(home, "proj"), true)
	if err != nil {
		t.Fatalf("MaybePrompt returned error: %v", err)
	}
	if !outcome.Mount || outcome.Scope != ScopeEphemeral || outcome.Persisted {
		t.Fatalf("expected ephemeral fallback: %+v", outcome)
	}
	if !errors.Is(outcome.SaveError, saveErr) {
		t.Fatalf("expected outcome.SaveError to be %v, got %v", saveErr, outcome.SaveError)
	}
	decision, err := controller.Config.GetEffectiveVolume("opencode", "")
	if err != nil {
		t.Fatalf("effective mount: %v", err)
	}
	if decision.Enabled {
		t.Fatalf("config should revert after save failure: %+v", decision)
	}
}

// This test mutates HOME and expects persisted decisions; keep it serial.
func TestMaybePromptRespectsExistingDecision(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	home := t.TempDir()
	setHome(t, home)
	mustMkdir(t, filepath.Join(home, ".codex"))

	cfg := New()
	if err := cfg.SetGlobalVolume("codex", true); err != nil {
		t.Fatalf("SetGlobalVolume: %v", err)
	}

	controller := &PromptController{Config: &cfg, Prompter: &failingPrompter{t}}

	outcome, err := controller.MaybePrompt(context.Background(), "codex", filepath.Join(home, "proj"), true)
	if err != nil {
		t.Fatalf("MaybePrompt returned error: %v", err)
	}
	if !outcome.Mount || outcome.Scope != ScopeGlobal {
		t.Fatalf("expected persisted decision to apply: %+v", outcome)
	}
}

// This test relies on HOME to detect missing host directories; run serially.
func TestMaybePromptMissingHostDirSkips(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	home := t.TempDir()
	setHome(t, home)
	// deliberately do not create ~/.claude

	cfg := New()
	controller := &PromptController{Config: &cfg, Prompter: &failingPrompter{t}}

	outcome, err := controller.MaybePrompt(context.Background(), "claude", filepath.Join(home, "proj"), true)
	if err != nil {
		t.Fatalf("MaybePrompt returned error: %v", err)
	}
	if outcome.Mount {
		t.Fatalf("expected no mount when host dir missing: %+v", outcome)
	}
}

type fakePrompter struct {
	confirm    bool
	confirmErr error
	scope      ScopeChoice
	scopeErr   error
}

func (f *fakePrompter) ConfirmMount(ctx context.Context, cmd, hostDir string) (bool, error) {
	return f.confirm, f.confirmErr
}

func (f *fakePrompter) ChooseScope(ctx context.Context, cmd, cwd string) (ScopeChoice, error) {
	return f.scope, f.scopeErr
}

type failingPrompter struct {
	t *testing.T
}

func (f *failingPrompter) ConfirmMount(context.Context, string, string) (bool, error) {
	f.t.Fatal("ConfirmMount should not be called")
	return false, nil
}

func (f *failingPrompter) ChooseScope(context.Context, string, string) (ScopeChoice, error) {
	f.t.Fatal("ChooseScope should not be called")
	return ScopeChoiceOnce, nil
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}
