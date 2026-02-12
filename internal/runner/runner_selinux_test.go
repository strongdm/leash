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

	"github.com/strongdm/leash/internal/configstore"
	"github.com/strongdm/leash/internal/leashd/listen"
)

func TestWithSELinuxRelabelMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: "z"},
		{name: "rw", in: "rw", want: "rw,z"},
		{name: "ro with other options", in: "ro,delegated", want: "ro,delegated,z"},
		{name: "already z", in: "rw,z", want: "rw,z"},
		{name: "already Z", in: "ro,Z", want: "ro,Z"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := withSELinuxRelabelMode(tc.in); got != tc.want {
				t.Fatalf("withSELinuxRelabelMode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestInternalBindMountSpecUsesSELinuxRelabel(t *testing.T) {
	t.Parallel()

	r := &runner{
		cfg: config{
			hostOS:  "linux",
			workDir: "/tmp/leash-work",
		},
	}
	r.selinuxChecked = true
	r.selinuxRelabel = true

	if got, want := r.internalBindMountSpec("/tmp/leash-work/share", "/leash", ""), "/tmp/leash-work/share:/leash:z"; got != want {
		t.Fatalf("internalBindMountSpec without mode = %q, want %q", got, want)
	}
	if got, want := r.internalBindMountSpec("/tmp/leash-work/share", "/leash", "rw"), "/tmp/leash-work/share:/leash:rw,z"; got != want {
		t.Fatalf("internalBindMountSpec with mode = %q, want %q", got, want)
	}
	if got, want := r.internalBindMountSpec("/home/user/project", "/workspace", "rw"), "/home/user/project:/workspace:rw"; got != want {
		t.Fatalf("internalBindMountSpec outside workdir = %q, want %q", got, want)
	}
}

func TestLaunchContainersAddSELinuxRelabelToInternalMounts(t *testing.T) {
	t.Parallel()
	mountStateTestMu.Lock()
	t.Cleanup(mountStateTestMu.Unlock)

	workDir := t.TempDir()
	shareDir := filepath.Join(workDir, "share")
	privateDir := filepath.Join(workDir, "private")
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		t.Fatalf("failed to create private dir: %v", err)
	}
	logDir := filepath.Join(workDir, "log")
	cfgDir := filepath.Join(workDir, "cfg")
	callerDir := t.TempDir()
	if err := os.MkdirAll(shareDir, 0o755); err != nil {
		t.Fatalf("failed to create share dir: %v", err)
	}
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
	)
	runCommand = func(_ context.Context, name string, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		copied := make([]string, len(args))
		copy(copied, args)
		commands = append(commands, recorded{name: name, args: copied})
		return nil
	}
	commandOutput = func(_ context.Context, name string, args ...string) (string, error) {
		switch {
		case name == "docker" && len(args) >= 3 && args[0] == "inspect" && args[1] == "--format" && strings.Contains(args[2], "{{.Architecture}}"):
			return "amd64\n", nil
		default:
			return "", fmt.Errorf("unexpected commandOutput call: %s %s", name, strings.Join(args, " "))
		}
	}
	t.Cleanup(func() {
		runCommand = origRun
		commandOutput = origCommand
	})

	hostRoot := t.TempDir()
	autoHost := filepath.Join(hostRoot, ".codex")
	if err := os.Mkdir(autoHost, 0o755); err != nil {
		t.Fatalf("mkdir auto host dir: %v", err)
	}

	r := &runner{
		logger: log.New(ioDiscard{}, "", 0),
		cfg: config{
			hostOS:           "linux",
			workDir:          workDir,
			shareDir:         shareDir,
			privateDir:       privateDir,
			logDir:           logDir,
			cfgDir:           cfgDir,
			callerDir:        callerDir,
			targetImage:      "example/target:latest",
			leashImage:       "example/leash:latest",
			targetContainer:  "leash-target-123",
			leashContainer:   "leash-manager-123",
			proxyPort:        "18000",
			bootstrapTimeout: 30 * time.Second,
			listenCfg:        listen.Default(),
		},
		opts: options{
			command: []string{"bash"},
		},
		mountState: &mountState{
			command: "codex",
			mounts: []configstore.Mount{
				{Host: autoHost, Container: "/root/.codex", Mode: "rw", Scope: configstore.ScopeGlobal},
			},
		},
	}
	r.verbose = true
	r.selinuxChecked = true
	r.selinuxRelabel = true

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

	if !containsArg(targetArgs, fmt.Sprintf("%s:%s:z", shareDir, leashPublicMount)) {
		t.Fatalf("target container missing relabeled share mount, args=%v", targetArgs)
	}
	if !containsArg(targetArgs, fmt.Sprintf("%s:%s", callerDir, callerDir)) {
		t.Fatalf("target container missing caller mount, args=%v", targetArgs)
	}
	if !containsArg(targetArgs, fmt.Sprintf("%s:%s:rw", autoHost, "/root/.codex")) {
		t.Fatalf("target container unexpectedly relabeled auto mount, args=%v", targetArgs)
	}
	if !containsArg(leashArgs, fmt.Sprintf("%s:%s:z", logDir, "/log")) {
		t.Fatalf("leash container missing relabeled log mount, args=%v", leashArgs)
	}
	if !containsArg(leashArgs, fmt.Sprintf("%s:%s:z", cfgDir, "/cfg")) {
		t.Fatalf("leash container missing relabeled cfg mount, args=%v", leashArgs)
	}
	if !containsArg(leashArgs, fmt.Sprintf("%s:%s:z", shareDir, leashPublicMount)) {
		t.Fatalf("leash container missing relabeled share mount, args=%v", leashArgs)
	}
	if !containsArg(leashArgs, fmt.Sprintf("%s:%s:z", privateDir, leashPrivateMount)) {
		t.Fatalf("leash container missing relabeled private mount, args=%v", leashArgs)
	}
	if !containsArg(leashArgs, "/sys/fs/cgroup:/sys/fs/cgroup:ro") {
		t.Fatalf("leash container unexpectedly changed /sys/fs/cgroup mount, args=%v", leashArgs)
	}
}
