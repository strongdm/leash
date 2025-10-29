package runner

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/leashd/listen"
)

func TestLaunchCommandsUseSplitMounts(t *testing.T) {
	t.Parallel()

	shareDir := t.TempDir()
	privateDir := filepath.Join(shareDir, "private")
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		t.Fatalf("failed to create private dir: %v", err)
	}
	logDir := filepath.Join(shareDir, "log")
	cfgDir := filepath.Join(shareDir, "cfg")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("failed to create log dir: %v", err)
	}
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("failed to create cfg dir: %v", err)
	}

	type recorded struct {
		name string
		args []string
	}
	var (
		mu          sync.Mutex
		commands    []recorded
		origRun     = runCommand
		origCommand = commandOutput
		logBuffer   strings.Builder
	)
	runCommand = func(_ context.Context, name string, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		copied := make([]string, len(args))
		copy(copied, args)
		commands = append(commands, recorded{name: name, args: copied})
		return nil
	}
	t.Cleanup(func() {
		runCommand = origRun
		commandOutput = origCommand
	})

	commandOutput = func(_ context.Context, name string, args ...string) (string, error) {
		switch {
		case name == "docker" && len(args) >= 3 && args[0] == "inspect" && args[1] == "--format" && strings.Contains(args[2], "{{.Architecture}}"):
			return "amd64\n", nil
		case name == "docker" && len(args) >= 3 && args[0] == "inspect" && args[1] == "--format" && strings.Contains(args[2], "{{json .Config.ExposedPorts}}"):
			return "{}\n", nil
		case name == "docker" && len(args) >= 2 && args[0] == "inspect":
			return "running 0\n", nil
		case name == "docker" && len(args) >= 2 && args[0] == "logs":
			return "mock log output\n", nil
		default:
			return "", fmt.Errorf("unexpected commandOutput call: %s %s", name, strings.Join(args, " "))
		}
	}

	r := &runner{
		logger: log.New(&logBuffer, "", 0),
		cfg: config{
			shareDir:         shareDir,
			privateDir:       privateDir,
			logDir:           logDir,
			cfgDir:           cfgDir,
			targetImage:      "example/target:latest",
			leashImage:       "example/leash:latest",
			targetContainer:  "leash-target-123",
			leashContainer:   "leash-manager-123",
			callerDir:        shareDir,
			proxyPort:        "18000",
			bootstrapTimeout: 30 * time.Second,
			listenCfg:        listen.Default(),
		},
		opts: options{
			command: []string{"bash"},
		},
		sessionID:     "session-123",
		workspaceHash: "hash-abc",
	}
	r.verbose = true

	if err := r.launchTargetContainer(context.Background(), "SIGTERM"); err != nil {
		t.Fatalf("target launch failed: %v", err)
	}
	if err := r.launchLeashContainer(context.Background(), "/sys/fs/cgroup/unified"); err != nil {
		t.Fatalf("leash launch failed: %v", err)
	}

	mu.Lock()
	if len(commands) != 2 {
		t.Fatalf("expected 2 docker runs, got %d", len(commands))
	}
	targetArgs := commands[0].args
	leashArgs := commands[1].args
	mu.Unlock()

	privateMount := fmt.Sprintf("%s:/leash-private", privateDir)
	publicMount := fmt.Sprintf("%s:/leash", shareDir)

	if containsArg(targetArgs, privateMount) {
		t.Fatalf("target container unexpectedly received private mount %q", privateMount)
	}
	if !containsArg(targetArgs, publicMount) {
		t.Fatalf("target container missing public mount %q", publicMount)
	}
	if !containsArg(leashArgs, privateMount) {
		t.Fatalf("leash container missing private mount %q", privateMount)
	}
	if !containsArg(leashArgs, publicMount) {
		t.Fatalf("leash container missing public mount %q", publicMount)
	}
	if !containsArg(leashArgs, "LEASH_PRIVATE_DIR=/leash-private") {
		t.Fatalf("leash container missing LEASH_PRIVATE_DIR environment export")
	}

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	tmpDir := t.TempDir()
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	outputPath := filepath.Join(tmpDir, "verify_mounts.txt")
	snapshot := fmt.Sprintf("timestamp: %s\ntarget: docker %s\nleash: docker %s\nlogs:\n%s", timestamp, strings.Join(targetArgs, " "), strings.Join(leashArgs, " "), logBuffer.String())
	if err := os.WriteFile(outputPath, []byte(snapshot), 0o644); err != nil {
		t.Fatalf("failed to write snapshot: %v", err)
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
