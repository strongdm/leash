package configstore

import (
	"testing"
)

func TestMergeEmptyOverlayReturnsBase(t *testing.T) {
	t.Parallel()
	base := New()
	base.TargetImage = "base-image"
	base.EnvVars["KEY"] = "base-val"
	base.CommandVolumes["codex"] = boolPtr(true)
	base.CustomVolumes["~/data"] = "/workspace/data:ro"

	result := Merge(base, New())

	if result.TargetImage != "base-image" {
		t.Fatalf("TargetImage = %q, want %q", result.TargetImage, "base-image")
	}
	if result.EnvVars["KEY"] != "base-val" {
		t.Fatalf("EnvVars[KEY] = %q, want %q", result.EnvVars["KEY"], "base-val")
	}
	if result.CommandVolumes["codex"] == nil || !*result.CommandVolumes["codex"] {
		t.Fatal("expected codex volume to be true")
	}
	if result.CustomVolumes["~/data"] != "/workspace/data:ro" {
		t.Fatal("expected custom volume preserved")
	}
}

func TestMergeOverlayOverridesScalars(t *testing.T) {
	t.Parallel()
	base := New()
	base.TargetImage = "base-image"

	overlay := New()
	overlay.TargetImage = "overlay-image"

	result := Merge(base, overlay)

	if result.TargetImage != "overlay-image" {
		t.Fatalf("TargetImage = %q, want %q", result.TargetImage, "overlay-image")
	}
}

func TestMergeEnvVarsMerged(t *testing.T) {
	t.Parallel()
	base := New()
	base.EnvVars["SHARED"] = "base"
	base.EnvVars["BASE_ONLY"] = "from-base"

	overlay := New()
	overlay.EnvVars["SHARED"] = "overlay"
	overlay.EnvVars["OVERLAY_ONLY"] = "from-overlay"

	result := Merge(base, overlay)

	if result.EnvVars["SHARED"] != "overlay" {
		t.Fatalf("SHARED = %q, want %q", result.EnvVars["SHARED"], "overlay")
	}
	if result.EnvVars["BASE_ONLY"] != "from-base" {
		t.Fatalf("BASE_ONLY = %q, want %q", result.EnvVars["BASE_ONLY"], "from-base")
	}
	if result.EnvVars["OVERLAY_ONLY"] != "from-overlay" {
		t.Fatalf("OVERLAY_ONLY = %q, want %q", result.EnvVars["OVERLAY_ONLY"], "from-overlay")
	}
}

func TestMergeCommandVolumesOverridden(t *testing.T) {
	t.Parallel()
	base := New()
	base.CommandVolumes["codex"] = boolPtr(true)
	base.CommandVolumes["claude"] = boolPtr(true)

	overlay := New()
	overlay.CommandVolumes["codex"] = boolPtr(false)

	result := Merge(base, overlay)

	if result.CommandVolumes["codex"] == nil || *result.CommandVolumes["codex"] {
		t.Fatal("expected codex volume to be false from overlay")
	}
	if result.CommandVolumes["claude"] == nil || !*result.CommandVolumes["claude"] {
		t.Fatal("expected claude volume preserved from base")
	}
}

func TestMergeProjectEnvVarsMerged(t *testing.T) {
	t.Parallel()
	base := New()
	base.ProjectEnvVars["/proj"] = map[string]string{
		"BASE_KEY": "base-val",
		"SHARED":   "base",
	}

	overlay := New()
	overlay.ProjectEnvVars["/proj"] = map[string]string{
		"SHARED":      "overlay",
		"OVERLAY_KEY": "overlay-val",
	}

	result := Merge(base, overlay)

	envs := result.ProjectEnvVars["/proj"]
	if envs["BASE_KEY"] != "base-val" {
		t.Fatalf("BASE_KEY = %q, want %q", envs["BASE_KEY"], "base-val")
	}
	if envs["SHARED"] != "overlay" {
		t.Fatalf("SHARED = %q, want %q", envs["SHARED"], "overlay")
	}
	if envs["OVERLAY_KEY"] != "overlay-val" {
		t.Fatalf("OVERLAY_KEY = %q, want %q", envs["OVERLAY_KEY"], "overlay-val")
	}
}

func TestMergeDoesNotMutateBase(t *testing.T) {
	t.Parallel()
	base := New()
	base.EnvVars["KEY"] = "original"

	overlay := New()
	overlay.EnvVars["KEY"] = "changed"

	_ = Merge(base, overlay)

	if base.EnvVars["KEY"] != "original" {
		t.Fatalf("base was mutated: EnvVars[KEY] = %q", base.EnvVars["KEY"])
	}
}

func TestMergeEmptyOverlayTargetImagePreservesBase(t *testing.T) {
	t.Parallel()
	base := New()
	base.TargetImage = "keep-me"

	overlay := New()
	// overlay.TargetImage is empty — should not override

	result := Merge(base, overlay)
	if result.TargetImage != "keep-me" {
		t.Fatalf("TargetImage = %q, want %q", result.TargetImage, "keep-me")
	}
}
