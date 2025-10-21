package configstore

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.CommandVolumes) != 0 {
		t.Fatalf("expected empty mounts, got %v", cfg.CommandVolumes)
	}
	if len(cfg.ProjectCommandVolumes) != 0 {
		t.Fatalf("expected no projects, got %v", cfg.ProjectCommandVolumes)
	}
	if cfg.TargetImage != "" {
		t.Fatalf("expected empty target image, got %q", cfg.TargetImage)
	}
	if len(cfg.ProjectTargetImages) != 0 {
		t.Fatalf("expected no project target images, got %v", cfg.ProjectTargetImages)
	}
	if len(cfg.EnvVars) != 0 {
		t.Fatalf("expected no global env vars, got %v", cfg.EnvVars)
	}
	if len(cfg.ProjectEnvVars) != 0 {
		t.Fatalf("expected no project env vars, got %v", cfg.ProjectEnvVars)
	}
}

func TestSaveRoundTripPersistsGlobalAndProject(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	cfg := New()
	if err := cfg.SetGlobalVolume("codex", true); err != nil {
		t.Fatalf("SetGlobalVolume: %v", err)
	}
	projectPath := filepath.Join(base, "proj")
	if err := cfg.SetProjectVolume(projectPath, "claude", true); err != nil {
		t.Fatalf("SetProjectVolume: %v", err)
	}
	if err := cfg.SetGlobalEnvVar("GLOBAL_KEY", "global-value"); err != nil {
		t.Fatalf("SetGlobalEnvVar: %v", err)
	}
	if err := cfg.SetProjectEnvVar(projectPath, "PROJECT_KEY", "project-value"); err != nil {
		t.Fatalf("SetProjectEnvVar: %v", err)
	}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, file, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(data, []byte(".mounts]")) {
		t.Fatalf("expected new config format without nested mounts table, got:\n%s", data)
	}
	if !bytes.Contains(data, []byte("[leash.envvars]\nGLOBAL_KEY = 'global-value'")) {
		t.Fatalf("expected global env vars in config, got:\n%s", data)
	}
	if !bytes.Contains(data, []byte("PROJECT_KEY = 'project-value'")) {
		t.Fatalf("expected project env vars in config, got:\n%s", data)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	decision, err := loaded.GetEffectiveVolume("codex", "")
	if err != nil {
		t.Fatalf("GetEffectiveVolume: %v", err)
	}
	if !decision.Enabled || decision.Scope != ScopeGlobal {
		t.Fatalf("expected global true, got %+v", decision)
	}
	decision, err = loaded.GetEffectiveVolume("claude", projectPath)
	if err != nil {
		t.Fatalf("GetEffectiveVolume project: %v", err)
	}
	if !decision.Enabled || decision.Scope != ScopeProject {
		t.Fatalf("expected project true, got %+v", decision)
	}

	resolved, err := loaded.ResolveEnvVars(projectPath)
	if err != nil {
		t.Fatalf("ResolveEnvVars: %v", err)
	}
	if got := resolved["GLOBAL_KEY"]; got.Value != "global-value" || got.Scope != ScopeGlobal {
		t.Fatalf("expected GLOBAL_KEY from global scope, got %+v", got)
	}
	if got := resolved["PROJECT_KEY"]; got.Value != "project-value" || got.Scope != ScopeProject {
		t.Fatalf("expected PROJECT_KEY from project scope, got %+v", got)
	}
}

func TestTargetImageConfigPrecedence(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	project := filepath.Join(base, "proj")
	cfg := New()
	cfg.SetGlobalTargetImage("ghcr.io/example/global:1")
	if err := cfg.SetProjectTargetImage(project, "ghcr.io/example/project:2"); err != nil {
		t.Fatalf("SetProjectTargetImage: %v", err)
	}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	img, scope, err := loaded.GetTargetImage(project)
	if err != nil {
		t.Fatalf("GetTargetImage(project): %v", err)
	}
	if img != "ghcr.io/example/project:2" || scope != ScopeProject {
		t.Fatalf("expected project target image, got img=%q scope=%s", img, scope)
	}

	otherImg, otherScope, err := loaded.GetTargetImage(filepath.Join(base, "other"))
	if err != nil {
		t.Fatalf("GetTargetImage(other): %v", err)
	}
	if otherImg != "ghcr.io/example/global:1" || otherScope != ScopeGlobal {
		t.Fatalf("expected global target image, got img=%q scope=%s", otherImg, otherScope)
	}

	_, file, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	contents := string(data)
	if !strings.Contains(contents, "target_image = 'ghcr.io/example/global:1'") {
		t.Fatalf("expected global target image in config, got:\n%s", contents)
	}
	if !strings.Contains(contents, "target_image = 'ghcr.io/example/project:2'") {
		t.Fatalf("expected project target image in config, got:\n%s", contents)
	}
}

func TestEnvVarConfigPrecedenceAndParsing(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	project := filepath.Join(base, "proj")
	otherProject := filepath.Join(base, "other")

	content := fmt.Sprintf(`
[leash.envvars]
A = "B"
BOO = "MOO"

[projects.'%s'.envvars]
SKR = "UMP"
A = "DUMP"

[projects.'%s'.envvars]
ZED = "ZAP"
`, project, otherProject)

	dir, file, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(file, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := cfg.EnvVars["A"]; got != "B" {
		t.Fatalf("global env A mismatch: got %q want %q", got, "B")
	}
	if got := cfg.EnvVars["BOO"]; got != "MOO" {
		t.Fatalf("global env BOO mismatch: got %q want %q", got, "MOO")
	}

	projectEnv := cfg.ProjectEnvVars[project]
	if projectEnv == nil {
		t.Fatalf("expected project env map for %s", project)
	}
	if got := projectEnv["A"]; got != "DUMP" {
		t.Fatalf("project env A mismatch: got %q want %q", got, "DUMP")
	}
	if got := projectEnv["SKR"]; got != "UMP" {
		t.Fatalf("project env SKR mismatch: got %q want %q", got, "UMP")
	}

	otherEnv := cfg.ProjectEnvVars[otherProject]
	if otherEnv == nil {
		t.Fatalf("expected env map for %s", otherProject)
	}
	if got := otherEnv["ZED"]; got != "ZAP" {
		t.Fatalf("project env ZED mismatch: got %q want %q", got, "ZAP")
	}

	resolvedProject, err := cfg.ResolveEnvVars(project)
	if err != nil {
		t.Fatalf("ResolveEnvVars(project): %v", err)
	}
	if got := resolvedProject["A"]; got.Value != "DUMP" || got.Scope != ScopeProject {
		t.Fatalf("expected project override for A, got %+v", got)
	}
	if got := resolvedProject["SKR"]; got.Value != "UMP" || got.Scope != ScopeProject {
		t.Fatalf("expected project SKR, got %+v", got)
	}
	if got := resolvedProject["BOO"]; got.Value != "MOO" || got.Scope != ScopeGlobal {
		t.Fatalf("expected global BOO, got %+v", got)
	}

	resolvedOther, err := cfg.ResolveEnvVars(otherProject)
	if err != nil {
		t.Fatalf("ResolveEnvVars(other): %v", err)
	}
	if got := resolvedOther["A"]; got.Value != "B" || got.Scope != ScopeGlobal {
		t.Fatalf("expected global A for other project, got %+v", got)
	}
	if got := resolvedOther["ZED"]; got.Value != "ZAP" || got.Scope != ScopeProject {
		t.Fatalf("expected project ZED, got %+v", got)
	}

	globalOnly, err := cfg.ResolveEnvVars("")
	if err != nil {
		t.Fatalf("ResolveEnvVars(global): %v", err)
	}
	if got := globalOnly["A"]; got.Value != "B" || got.Scope != ScopeGlobal {
		t.Fatalf("expected global A with empty project, got %+v", got)
	}
	if _, ok := globalOnly["ZED"]; ok {
		t.Fatalf("did not expect ZED in global-only resolution, got %+v", globalOnly)
	}
}

func TestLoadProjectKeysWithExpansions(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	homeDir := filepath.Join(base, "home")
	setHome(t, homeDir)

	srcProject := filepath.Join(homeDir, "src", "project")
	if err := os.MkdirAll(srcProject, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}

	workRoot := filepath.Join(base, "workroot")
	if err := os.MkdirAll(workRoot, 0o755); err != nil {
		t.Fatalf("mkdir workroot: %v", err)
	}
	testSetEnv(t, "WORKROOT", workRoot)

	serviceProject := filepath.Join(workRoot, "service")
	if err := os.MkdirAll(serviceProject, 0o755); err != nil {
		t.Fatalf("mkdir service: %v", err)
	}

	content := `
[projects."~/src/project".envvars]
TOKEN = "abc"

[projects."${WORKROOT}/service".volumes]
codex = true
`

	dir, file, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(file, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	normalizedHome, err := normalizeProjectKey(srcProject)
	if err != nil {
		t.Fatalf("normalizeProjectKey home: %v", err)
	}
	envs := cfg.ProjectEnvVars[normalizedHome]
	if envs == nil || envs["TOKEN"] != "abc" {
		t.Fatalf("expected env vars for %s, got %v", normalizedHome, envs)
	}

	normalizedService, err := normalizeProjectKey(serviceProject)
	if err != nil {
		t.Fatalf("normalizeProjectKey service: %v", err)
	}
	volumes := cfg.ProjectCommandVolumes[normalizedService]
	if volumes == nil {
		t.Fatalf("expected project volumes for %s", normalizedService)
	}
	entry, ok := volumes["codex"]
	if !ok || entry == nil || !*entry {
		t.Fatalf("expected codex=true for %s, got %v", normalizedService, volumes)
	}
}

func TestLoadTargetImageCombinations(t *testing.T) {
	t.Parallel()

	type projectExpectation struct {
		relPath       string
		expectTarget  string
		expectVolumes map[string]bool
	}

	cases := []struct {
		name                string
		configTemplate      string
		projects            []projectExpectation
		expectGlobal        string
		expectGlobalVolumes map[string]bool
	}{
		{
			name: "GlobalOnly",
			configTemplate: `
[leash]
target_image = "ghcr.io/example/global:latest"
`,
			expectGlobal:        "ghcr.io/example/global:latest",
			expectGlobalVolumes: nil,
		},
		{
			name: "ProjectOnly",
			configTemplate: `
[projects.'%s']
target_image = "ghcr.io/example/project:v1"
`,
			projects: []projectExpectation{
				{
					relPath:      "proj",
					expectTarget: "ghcr.io/example/project:v1",
				},
			},
			expectGlobalVolumes: nil,
		},
		{
			name: "ProjectVolumeOverrides",
			configTemplate: `
[volumes]
claude = true

[projects.'%[1]s']
target_image = "ghcr.io/example/project:v2"
gemini = true

[projects.'%[1]s'.volumes]
codex = true
qwen = false

[projects.'%[2]s']
target_image = "ghcr.io/example/second:v3"

[leash]
target_image = "ghcr.io/example/global:v2"
`,
			projects: []projectExpectation{
				{
					relPath:      "workspace/a",
					expectTarget: "ghcr.io/example/project:v2",
					expectVolumes: map[string]bool{
						"gemini": true,
						"codex":  true,
						"qwen":   false,
					},
				},
				{
					relPath:       "workspace/b",
					expectTarget:  "ghcr.io/example/second:v3",
					expectVolumes: map[string]bool{},
				},
			},
			expectGlobal: "ghcr.io/example/global:v2",
			expectGlobalVolumes: map[string]bool{
				"claude": true,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lockEnv(t)
			testSetEnv(t, "LEASH_HOME", "")
			base := t.TempDir()
			testSetEnv(t, "XDG_CONFIG_HOME", base)
			setHome(t, filepath.Join(base, "home"))

			args := make([]any, len(tc.projects))
			projectKeys := make([]string, len(tc.projects))
			for i, spec := range tc.projects {
				abs := filepath.Join(base, spec.relPath)
				if err := os.MkdirAll(abs, 0o755); err != nil {
					t.Fatalf("mkdir project %q: %v", abs, err)
				}
				key, err := normalizeProjectKey(abs)
				if err != nil {
					t.Fatalf("normalize project key: %v", err)
				}
				projectKeys[i] = key
				args[i] = key
			}

			content := tc.configTemplate
			if len(args) > 0 {
				content = fmt.Sprintf(tc.configTemplate, args...)
			}

			dir, file, err := GetConfigPath()
			if err != nil {
				t.Fatalf("GetConfigPath: %v", err)
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatalf("mkdir config dir: %v", err)
			}
			if err := os.WriteFile(file, []byte(strings.TrimPrefix(strings.TrimSpace(content)+"\n", "\n")), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			if got := cfg.TargetImage; got != tc.expectGlobal {
				t.Fatalf("global target image: got %q want %q", got, tc.expectGlobal)
			}

			expectedGlobalVolumes := tc.expectGlobalVolumes
			if expectedGlobalVolumes == nil {
				expectedGlobalVolumes = map[string]bool{}
			}
			if len(cfg.CommandVolumes) != len(expectedGlobalVolumes) {
				t.Fatalf("global volumes length: got %d want %d", len(cfg.CommandVolumes), len(expectedGlobalVolumes))
			}
			for cmd, want := range expectedGlobalVolumes {
				ptr, ok := cfg.CommandVolumes[cmd]
				if !ok || ptr == nil {
					t.Fatalf("missing global volume toggle %q", cmd)
				}
				if got := *ptr; got != want {
					t.Fatalf("volume toggle %q: got %v want %v", cmd, got, want)
				}
			}

			expectedProjectTargets := make(map[string]string)
			for i, spec := range tc.projects {
				if strings.TrimSpace(spec.expectTarget) != "" {
					expectedProjectTargets[projectKeys[i]] = strings.TrimSpace(spec.expectTarget)
				}
			}
			if len(cfg.ProjectTargetImages) != len(expectedProjectTargets) {
				t.Fatalf("project target images length: got %d want %d", len(cfg.ProjectTargetImages), len(expectedProjectTargets))
			}
			for key, want := range expectedProjectTargets {
				got, ok := cfg.ProjectTargetImages[key]
				if !ok {
					t.Fatalf("missing project target image for %s", key)
				}
				if got != want {
					t.Fatalf("project %s target image: got %q want %q", key, got, want)
				}
			}

			expectedProjectVolumes := make(map[string]map[string]bool)
			for i, spec := range tc.projects {
				if spec.expectVolumes != nil {
					expectedProjectVolumes[projectKeys[i]] = spec.expectVolumes
				}
			}

			for key, volumes := range expectedProjectVolumes {
				raw := cfg.ProjectCommandVolumes[key]
				if raw == nil {
					t.Fatalf("expected project volumes for %s", key)
				}
				if len(raw) != len(volumes) {
					t.Fatalf("project %s volumes length: got %d want %d", key, len(raw), len(volumes))
				}
				for cmd, want := range volumes {
					ptr, ok := raw[cmd]
					if !ok || ptr == nil {
						t.Fatalf("project %s missing volume toggle %q", key, cmd)
					}
					if got := *ptr; got != want {
						t.Fatalf("project %s volume %q: got %v want %v", key, cmd, got, want)
					}
				}
			}

			for key := range cfg.ProjectTargetImages {
				if _, ok := expectedProjectTargets[key]; !ok {
					t.Fatalf("unexpected project target image for %s", key)
				}
			}
		})
	}
}

func TestLoadCustomVolumeSpecs(t *testing.T) {
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	project := filepath.Join(base, "proj")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}

	config := fmt.Sprintf(`
[volumes]
"~/workspace" = "/workspace:ro"

[projects."%s"]
codex = true

[projects."%s".volumes]
"./dev" = "/workspace:rw"
"~/workspace" = false
"${HOME}/workspace" = false
`, project, project)

	_, file, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(file, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if got := cfg.CustomVolumes["~/workspace"]; strings.TrimSpace(got) != "/workspace:ro" {
		t.Fatalf("unexpected global custom volume: %q", got)
	}

	key, err := normalizeProjectKey(project)
	if err != nil {
		t.Fatalf("normalizeProjectKey: %v", err)
	}
	projMount := cfg.ProjectCustomVolumes[key]["./dev"]
	if strings.TrimSpace(projMount) != "/workspace:rw" {
		t.Fatalf("unexpected project custom volume: %q", projMount)
	}
	if disabled, ok := cfg.ProjectVolumeDisables[key]["~/workspace"]; !ok || !disabled {
		t.Fatalf("expected ~/workspace to be disabled for project, got %v (present=%v)", disabled, ok)
	}
}

func TestEffectiveVolumePrefersProject(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	cfg := New()
	if err := cfg.SetGlobalVolume("gemini", false); err != nil {
		t.Fatalf("SetGlobalVolume: %v", err)
	}
	if err := cfg.SetProjectVolume(filepath.Join(base, "proj"), "gemini", true); err != nil {
		t.Fatalf("SetProjectVolume: %v", err)
	}

	decision, err := cfg.GetEffectiveVolume("gemini", filepath.Join(base, "proj"))
	if err != nil {
		t.Fatalf("GetEffectiveVolume: %v", err)
	}
	if !decision.Enabled || decision.Scope != ScopeProject {
		t.Fatalf("expected project override, got %+v", decision)
	}
}

func TestLoadCorruptTomlReturnsTypedError(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	dir, file, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(file, []byte("[mounts\ncodex = true"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = Load()
	var parseErr *ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected ParseError, got %v", err)
	}
	if parseErr.Path == "" {
		t.Fatal("ParseError.Path empty")
	}
}

func TestSaveUnwritableDirectoryFailsWithoutPartialFile(t *testing.T) {
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	dir, file, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if err := os.MkdirAll(dir, 0o500); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	cfg := New()
	if err := cfg.SetGlobalVolume("codex", true); err != nil {
		t.Fatalf("SetGlobalVolume: %v", err)
	}
	err = Save(cfg)
	if err == nil {
		t.Fatal("expected error when directory is unwritable")
	}

	matches, globErr := filepath.Glob(filepath.Join(dir, "config-*.tmp"))
	if globErr != nil {
		t.Fatalf("glob: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no temp files, found %v", matches)
	}
	if _, statErr := os.Stat(file); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("config file should not exist, stat err=%v", statErr)
	}
}

func TestSetProjectVolumeNormalizesPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	t.Parallel()
	lockEnv(t)
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))

	project := filepath.Join(base, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(project, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cfg := New()
	if err := cfg.SetProjectVolume(project, "qwen", true); err != nil {
		t.Fatalf("SetProjectVolume project: %v", err)
	}
	if err := cfg.SetProjectVolume(link, "qwen", false); err != nil {
		t.Fatalf("SetProjectVolume link: %v", err)
	}

	if len(cfg.ProjectCommandVolumes) != 1 {
		t.Fatalf("expected single project entry, got %d", len(cfg.ProjectCommandVolumes))
	}
	expectedKey, err := normalizeProjectKey(project)
	if err != nil {
		t.Fatalf("normalizeProjectKey: %v", err)
	}
	for key := range cfg.ProjectCommandVolumes {
		if key != expectedKey {
			t.Fatalf("expected canonical key %q, got %q", expectedKey, key)
		}
	}
	decision, err := cfg.GetEffectiveVolume("qwen", project)
	if err != nil {
		t.Fatalf("GetEffectiveVolume: %v", err)
	}
	if decision.Enabled {
		t.Fatalf("expected last value false, got %+v", decision)
	}
}
