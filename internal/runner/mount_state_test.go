package runner

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/strongdm/leash/internal/configstore"
	"github.com/strongdm/leash/internal/leashd/listen"
)

var mountStateTestMu sync.Mutex

func TestLaunchTargetContainerAppendsAutoMount(t *testing.T) {
	t.Parallel()
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	callerDir := t.TempDir()
	shareDir := t.TempDir()

	var captured []string
	restoreRun := runCommand
	runCommand = func(_ context.Context, name string, args ...string) error {
		captured = append([]string{name}, args...)
		return nil
	}
	defer func() { runCommand = restoreRun }()

	restoreOutput := commandOutput
	commandOutput = func(context.Context, string, ...string) (string, error) {
		return "amd64\n", nil
	}
	defer func() { commandOutput = restoreOutput }()

	var logBuf bytes.Buffer
	r := &runner{
		opts: options{},
		cfg: config{
			callerDir:          callerDir,
			shareDir:           shareDir,
			targetContainer:    "target",
			targetImage:        "target-image",
			listenCfg:          listen.Config{Disable: true},
			policyPath:         "",
			workspaceDir:       filepath.Join(t.TempDir(), "workspace"),
			cfgDir:             filepath.Join(t.TempDir(), "cfg"),
			logDir:             filepath.Join(t.TempDir(), "log"),
			cgroupPathOverride: "",
		},
		logger: log.New(&logBuf, "", 0),
	}
	hostRoot := t.TempDir()
	hostDir := filepath.Join(hostRoot, ".codex")
	if err := os.Mkdir(hostDir, 0o755); err != nil {
		t.Fatalf("mkdir host dir: %v", err)
	}
	r.mountState = &mountState{
		command: "codex",
		mounts: []configstore.Mount{
			{Host: hostDir, Container: "/root/.codex", Mode: "rw", Scope: configstore.ScopeGlobal},
		},
	}

	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatalf("launchTargetContainer returned error: %v", err)
	}
	if len(captured) == 0 {
		t.Fatal("expected docker command to be invoked")
	}

	args := captured[1:]
	auto := fmt.Sprintf("%s:%s:%s", r.mountState.mounts[0].Host, r.mountState.mounts[0].Container, r.mountState.mounts[0].Mode)
	if countArgOccurrences(args, auto) != 1 {
		t.Fatalf("expected exactly one auto mount argument %q, args=%v", auto, args)
	}

	if !strings.Contains(logBuf.String(), "Auto-mounted") {
		t.Fatalf("expected log output to mention auto-mount, got %q", logBuf.String())
	}
}

func TestLaunchTargetContainerAppendsFileMount(t *testing.T) {
	t.Parallel()
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	callerDir := t.TempDir()
	shareDir := t.TempDir()

	var captured []string
	restoreRun := runCommand
	runCommand = func(_ context.Context, name string, args ...string) error {
		captured = append([]string{name}, args...)
		return nil
	}
	defer func() { runCommand = restoreRun }()

	restoreOutput := commandOutput
	commandOutput = func(context.Context, string, ...string) (string, error) {
		return "amd64\n", nil
	}
	defer func() { commandOutput = restoreOutput }()

	r := &runner{
		opts: options{},
		cfg: config{
			callerDir:       callerDir,
			shareDir:        shareDir,
			targetContainer: "target",
			targetImage:     "target-image",
			listenCfg:       listen.Config{Disable: true},
			workspaceDir:    filepath.Join(t.TempDir(), "workspace"),
			cfgDir:          filepath.Join(t.TempDir(), "cfg"),
			logDir:          filepath.Join(t.TempDir(), "log"),
		},
		logger: log.New(ioDiscard{}, "", 0),
	}
	hostRoot := t.TempDir()
	hostDir := filepath.Join(hostRoot, ".claude")
	if err := os.Mkdir(hostDir, 0o755); err != nil {
		t.Fatalf("mkdir host dir: %v", err)
	}
	configFile := filepath.Join(hostRoot, ".claude.json")
	if err := os.WriteFile(configFile, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	dirMount := configstore.Mount{
		Host:      hostDir,
		Container: "/root/.claude",
		Mode:      "rw",
		Scope:     configstore.ScopeGlobal,
		Kind:      configstore.MountKindDirectory,
	}
	fileMount := configstore.Mount{
		Host:      configFile,
		Container: "/root/.claude.json",
		Mode:      "rw",
		Scope:     configstore.ScopeGlobal,
		Kind:      configstore.MountKindFile,
	}

	r.mountState = &mountState{
		command: "claude",
		mounts:  []configstore.Mount{dirMount, fileMount},
	}

	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatalf("launchTargetContainer returned error: %v", err)
	}
	if len(captured) == 0 {
		t.Fatal("expected docker command to be invoked")
	}

	args := captured[1:]
	dirSpec := fmt.Sprintf("%s:%s:%s", dirMount.Host, dirMount.Container, dirMount.Mode)
	if countArgOccurrences(args, dirSpec) != 1 {
		t.Fatalf("expected directory mount argument %q once, args=%v", dirSpec, args)
	}
	fileSpec := fmt.Sprintf("%s:%s:%s", fileMount.Host, fileMount.Container, fileMount.Mode)
	if countArgOccurrences(args, fileSpec) != 1 {
		t.Fatalf("expected file mount argument %q once, args=%v", fileSpec, args)
	}
}

func TestLaunchTargetContainerSkipsDuplicateMount(t *testing.T) {
	t.Parallel()
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	callerDir := t.TempDir()
	shareDir := t.TempDir()
	duplicate := "/root/.qwen"

	var captured []string
	restoreRun := runCommand
	runCommand = func(_ context.Context, name string, args ...string) error {
		captured = append([]string{name}, args...)
		return nil
	}
	defer func() { runCommand = restoreRun }()

	restoreOutput := commandOutput
	commandOutput = func(context.Context, string, ...string) (string, error) {
		return "amd64\n", nil
	}
	defer func() { commandOutput = restoreOutput }()

	hostRoot := t.TempDir()
	hostDir := filepath.Join(hostRoot, ".qwen")
	if err := os.Mkdir(hostDir, 0o755); err != nil {
		t.Fatalf("mkdir host dir: %v", err)
	}

	r := &runner{
		opts: options{volumes: []string{fmt.Sprintf("%s:%s:rw", filepath.Join(t.TempDir(), "host"), duplicate)}},
		cfg: config{
			callerDir:       callerDir,
			shareDir:        shareDir,
			targetContainer: "target",
			targetImage:     "target-image",
			listenCfg:       listen.Config{Disable: true},
			workspaceDir:    filepath.Join(t.TempDir(), "workspace"),
			cfgDir:          filepath.Join(t.TempDir(), "cfg"),
			logDir:          filepath.Join(t.TempDir(), "log"),
		},
		verbose: true,
		logger:  log.New(ioDiscard{}, "", 0),
	}
	r.mountState = &mountState{
		command: "qwen",
		mounts: []configstore.Mount{
			{Host: hostDir, Container: duplicate, Mode: "rw", Scope: configstore.ScopeGlobal},
		},
	}

	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatalf("launchTargetContainer returned error: %v", err)
	}

	args := captured[1:]
	auto := fmt.Sprintf("%s:%s:%s", r.mountState.mounts[0].Host, duplicate, "rw")
	if countArgOccurrences(args, auto) != 0 {
		t.Fatalf("expected auto mount to be skipped, args=%v", args)
	}
}

func TestInitMountStateUnsupportedCommand(t *testing.T) {
	t.Parallel()

	r := &runner{
		opts:   options{subcommand: "notreal"},
		logger: log.New(ioDiscard{}, "", 0),
	}

	if err := r.initMountState(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("initMountState returned error: %v", err)
	}
	if r.mountState != nil {
		t.Fatalf("expected mountState to remain nil for unsupported command")
	}
}

// This test rewrites HOME and XDG_CONFIG_HOME; keep it serial so concurrent tests
// can't observe temporary directories.
func TestInitMountStateWarnsWhenPersistedHostMissing(t *testing.T) {
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	home := t.TempDir()
	configHome := t.TempDir()
	setTestEnv(t, "HOME", home)
	setTestEnv(t, "XDG_CONFIG_HOME", configHome)

	cfg := configstore.New()
	if err := cfg.SetGlobalVolume("codex", true); err != nil {
		t.Fatalf("SetGlobalVolume: %v", err)
	}
	if err := configstore.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var logBuf bytes.Buffer
	r := &runner{
		opts:   options{subcommand: "codex"},
		logger: log.New(&logBuf, "", 0),
	}

	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}

	if err := r.initMountState(context.Background(), cwd); err != nil {
		t.Fatalf("initMountState returned error: %v", err)
	}
	if r.mountState != nil {
		t.Fatalf("expected mountState to remain nil when host dir missing")
	}
	if !strings.Contains(logBuf.String(), "does not exist") {
		t.Fatalf("expected missing host warning, got %q", logBuf.String())
	}
}

// This test mutates HOME and XDG_CONFIG_HOME and must run before any parallel
// tests so shared process environment stays coherent.
func TestInitMountStateCreatesClaudeMountStateWithoutHostDir(t *testing.T) {
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	home := t.TempDir()
	configHome := t.TempDir()
	setTestEnv(t, "HOME", home)
	setTestEnv(t, "XDG_CONFIG_HOME", configHome)

	cwd := filepath.Join(home, "workspace")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}

	r := &runner{
		opts:   options{subcommand: "claude"},
		logger: log.New(ioDiscard{}, "", 0),
	}

	if err := r.initMountState(context.Background(), cwd); err != nil {
		t.Fatalf("initMountState returned error: %v", err)
	}
	if r.mountState == nil {
		t.Fatalf("expected mountState to be initialized for claude when host dir missing")
	}
	expectedHostDir := filepath.Join(home, ".claude")
	if r.mountState.outcome.HostDir != expectedHostDir {
		t.Fatalf("unexpected host dir: got %s want %s", r.mountState.outcome.HostDir, expectedHostDir)
	}
	if len(r.mountState.mounts) != 0 {
		t.Fatalf("expected no mounts to be configured when host dir is absent")
	}
}

func TestLaunchTargetContainerLogsDuplicateSkip(t *testing.T) {
	t.Parallel()
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	callerDir := t.TempDir()
	shareDir := t.TempDir()
	hostRoot := t.TempDir()
	hostDir := filepath.Join(hostRoot, ".codex")
	if err := os.Mkdir(hostDir, 0o755); err != nil {
		t.Fatalf("mkdir host dir: %v", err)
	}

	container := "/root/.codex"
	cliVolume := fmt.Sprintf("%s:%s:rw", hostDir, container)

	var captured []string
	restoreRun := runCommand
	runCommand = func(_ context.Context, name string, args ...string) error {
		captured = append([]string{name}, args...)
		return nil
	}
	t.Cleanup(func() { runCommand = restoreRun })

	restoreOutput := commandOutput
	commandOutput = func(context.Context, string, ...string) (string, error) {
		return "amd64\n", nil
	}
	t.Cleanup(func() { commandOutput = restoreOutput })

	var logBuf bytes.Buffer
	r := &runner{
		opts: options{
			volumes: []string{cliVolume},
		},
		cfg: config{
			callerDir:       callerDir,
			shareDir:        shareDir,
			targetContainer: "target",
			targetImage:     "target-image",
			listenCfg:       listen.Config{Disable: true},
		},
		logger: log.New(&logBuf, "", 0),
	}
	r.mountState = &mountState{
		command: "codex",
		mounts: []configstore.Mount{
			{Host: hostDir, Container: container, Mode: "rw", Scope: configstore.ScopeGlobal},
		},
	}

	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatalf("launchTargetContainer returned error: %v", err)
	}

	if len(captured) == 0 {
		t.Fatal("expected docker command to be invoked")
	}

	if !strings.Contains(logBuf.String(), "already configured; skipping duplicate") {
		t.Fatalf("expected duplicate warning, got %q", logBuf.String())
	}

	auto := fmt.Sprintf("%s:%s:%s", hostDir, container, "rw")
	if countArgOccurrences(captured[1:], auto) != 1 {
		t.Fatalf("expected cli volume to remain once, args=%v", captured)
	}
}

func TestLaunchTargetContainerWarnsWhenHostNotDirectory(t *testing.T) {
	t.Parallel()
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	callerDir := t.TempDir()
	shareDir := t.TempDir()
	hostRoot := t.TempDir()
	hostFile := filepath.Join(hostRoot, ".codex")
	if err := os.WriteFile(hostFile, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	var captured []string
	restoreRun := runCommand
	runCommand = func(_ context.Context, name string, args ...string) error {
		captured = append([]string{name}, args...)
		return nil
	}
	t.Cleanup(func() { runCommand = restoreRun })

	restoreOutput := commandOutput
	commandOutput = func(context.Context, string, ...string) (string, error) {
		return "amd64\n", nil
	}
	t.Cleanup(func() { commandOutput = restoreOutput })

	var logBuf bytes.Buffer
	r := &runner{
		opts: options{},
		cfg: config{
			callerDir:       callerDir,
			shareDir:        shareDir,
			targetContainer: "target",
			targetImage:     "target-image",
			listenCfg:       listen.Config{Disable: true},
		},
		logger: log.New(&logBuf, "", 0),
	}
	r.mountState = &mountState{
		command: "codex",
		mounts: []configstore.Mount{
			{Host: hostFile, Container: "/root/.codex", Mode: "rw", Scope: configstore.ScopeGlobal},
		},
	}

	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatalf("launchTargetContainer returned error: %v", err)
	}

	if len(captured) == 0 {
		t.Fatal("expected docker command to be invoked")
	}

	if !strings.Contains(logBuf.String(), "expected") {
		t.Fatalf("expected non-directory warning, got %q", logBuf.String())
	}

	auto := fmt.Sprintf("%s:%s:%s", hostFile, "/root/.codex", "rw")
	if countArgOccurrences(captured[1:], auto) != 0 {
		t.Fatalf("expected non-directory auto mount to be skipped, args=%v", captured)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func indexOfArg(args []string, needle string) int {
	for i, arg := range args {
		if arg == needle {
			return i
		}
	}
	return -1
}

func countArgOccurrences(args []string, needle string) int {
	count := 0
	for _, arg := range args {
		if arg == needle {
			count++
		}
	}
	return count
}

func setTestEnv(t *testing.T, key, value string) {
	t.Helper()
	prev, existed := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("set env %s: %v", key, err)
	}
	t.Cleanup(func() {
		if !existed {
			if err := os.Unsetenv(key); err != nil {
				t.Fatalf("unset env %s: %v", key, err)
			}
			return
		}
		if err := os.Setenv(key, prev); err != nil {
			t.Fatalf("restore env %s: %v", key, err)
		}
	})
}

func TestMaybeAddClaudeKeychainMountSkipsWhenCredentialsExist(t *testing.T) {
	t.Parallel()

	hostDir := t.TempDir()
	credentialsPath := filepath.Join(hostDir, ".credentials.json")
	if err := os.WriteFile(credentialsPath, []byte(`{"existing":"creds"}`), 0o600); err != nil {
		t.Fatalf("write existing credentials: %v", err)
	}

	var logBuf bytes.Buffer
	r := &runner{
		logger:  log.New(&logBuf, "", 0),
		verbose: true,
	}
	r.mountState = &mountState{
		outcome: configstore.PromptOutcome{HostDir: hostDir},
		mounts:  []configstore.Mount{},
	}

	if err := r.maybeAddClaudeKeychainMount(); err != nil {
		t.Fatalf("maybeAddClaudeKeychainMount returned error: %v", err)
	}

	if len(r.mountState.mounts) != 0 {
		t.Fatalf("expected no mounts to be added when credentials exist")
	}

	if len(r.mountState.tempFiles) != 0 {
		t.Fatalf("expected no temp files when credentials exist")
	}

	if !strings.Contains(logBuf.String(), "already exists") {
		t.Logf("log output: %s", logBuf.String())
	}
}

func TestMaybeAddClaudeKeychainMountHandlesKeychainGracefully(t *testing.T) {
	t.Parallel()

	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	hostDir := t.TempDir()

	prevFetch := fetchClaudeCredentials
	fetchClaudeCredentials = func() (string, error) {
		return "", fmt.Errorf("simulated keychain failure")
	}
	t.Cleanup(func() { fetchClaudeCredentials = prevFetch })

	var logBuf bytes.Buffer
	r := &runner{
		logger:  log.New(&logBuf, "", 0),
		verbose: true,
	}
	r.mountState = &mountState{
		outcome: configstore.PromptOutcome{HostDir: hostDir},
		mounts:  []configstore.Mount{},
	}

	if err := r.maybeAddClaudeKeychainMount(); err != nil {
		t.Fatalf("maybeAddClaudeKeychainMount should not error: %v", err)
	}

	if len(r.mountState.mounts) != 0 {
		t.Fatalf("expected no extra mounts when keychain missing, got %d", len(r.mountState.mounts))
	}
	if len(r.mountState.tempFiles) != 0 {
		t.Fatalf("expected no temp files when keychain missing, got %d", len(r.mountState.tempFiles))
	}
}

func TestMaybeAddClaudeKeychainMountReplacesEmptyFile(t *testing.T) {
	t.Parallel()

	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	hostDir := t.TempDir()
	credentialsPath := filepath.Join(hostDir, ".credentials.json")
	if err := os.WriteFile(credentialsPath, []byte{}, 0o600); err != nil {
		t.Fatalf("create empty credentials: %v", err)
	}

	prevFetch := fetchClaudeCredentials
	fetchClaudeCredentials = func() (string, error) {
		return `{"token":"secret"}`, nil
	}
	t.Cleanup(func() { fetchClaudeCredentials = prevFetch })

	var logBuf bytes.Buffer
	r := &runner{
		logger:  log.New(&logBuf, "", 0),
		verbose: true,
	}
	r.mountState = &mountState{
		outcome: configstore.PromptOutcome{HostDir: hostDir},
		mounts:  []configstore.Mount{},
	}

	if err := r.maybeAddClaudeKeychainMount(); err != nil {
		t.Fatalf("maybeAddClaudeKeychainMount returned error: %v", err)
	}

	if len(r.mountState.mounts) != 0 {
		t.Fatalf("expected no mounts to be added when credentials refreshed")
	}
	if len(r.mountState.tempFiles) != 0 {
		t.Fatalf("expected no temp files to be tracked when credentials refreshed, got %d", len(r.mountState.tempFiles))
	}
	data, err := os.ReadFile(credentialsPath)
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if string(data) != `{"token":"secret"}` {
		t.Fatalf("credentials content mismatch: %q", string(data))
	}
	info, err := os.Stat(credentialsPath)
	if err != nil {
		t.Fatalf("stat credentials: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("expected 0400 permissions, got %o", info.Mode().Perm())
	}
	os.Remove(credentialsPath)
}

func TestMaybeAddClaudeKeychainMountCreatesCredentialsFromKeychain(t *testing.T) {
	t.Parallel()

	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	hostDir := t.TempDir()

	prevFetch := fetchClaudeCredentials
	fetchClaudeCredentials = func() (string, error) {
		return `{"token":"secret"}`, nil
	}
	t.Cleanup(func() { fetchClaudeCredentials = prevFetch })

	var logBuf bytes.Buffer
	r := &runner{
		logger:  log.New(&logBuf, "", 0),
		verbose: true,
	}
	r.mountState = &mountState{
		outcome: configstore.PromptOutcome{HostDir: hostDir},
		mounts:  []configstore.Mount{},
	}

	if err := r.maybeAddClaudeKeychainMount(); err != nil {
		t.Fatalf("maybeAddClaudeKeychainMount returned error: %v", err)
	}

	if len(r.mountState.mounts) != 0 {
		t.Fatalf("expected no extra mounts when keychain provides credentials, got %d", len(r.mountState.mounts))
	}
	if len(r.mountState.tempFiles) != 0 {
		t.Fatalf("expected no temp files to be tracked when keychain provides credentials, got %d", len(r.mountState.tempFiles))
	}
	credentialsPath := filepath.Join(hostDir, ".credentials.json")
	data, err := os.ReadFile(credentialsPath)
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if string(data) != `{"token":"secret"}` {
		t.Fatalf("credentials content mismatch: %q", string(data))
	}
	info, err := os.Stat(credentialsPath)
	if err != nil {
		t.Fatalf("stat credentials: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("expected 0400 permissions, got %o", info.Mode().Perm())
	}
	os.Remove(credentialsPath)
}
