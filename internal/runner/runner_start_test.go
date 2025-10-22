package runner

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/strongdm/leash/internal/leashd/listen"
)

var commandOverrideMu sync.Mutex

func TestAssignContainerNamesAddsSuffix(t *testing.T) {
	t.Parallel()

	commandOverrideMu.Lock()
	restoreOutput := commandOutput
	existing := map[string]bool{
		"target":       true,
		"target-leash": true,
	}
	commandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		t.Helper()
		if name == "docker" && len(args) > 0 && args[0] == "inspect" {
			target := args[len(args)-1]
			if existing[target] {
				return "/" + target, nil
			}
			return "", fmt.Errorf("Error: No such object: %s", target)
		}
		return "", fmt.Errorf("unexpected command: %s %v", name, args)
	}
	t.Cleanup(func() {
		commandOutput = restoreOutput
		commandOverrideMu.Unlock()
	})

	r := &runner{
		cfg: config{
			targetContainer:     "target",
			leashContainer:      "target-leash",
			targetContainerBase: "target",
			leashContainerBase:  "target-leash",
		},
		logger: log.New(io.Discard, "", 0),
	}

	if err := r.assignContainerNames(context.Background()); err != nil {
		t.Fatalf("assignContainerNames returned error: %v", err)
	}

	if got, want := r.cfg.targetContainer, "target1"; got != want {
		t.Fatalf("target container mismatch: got %q want %q", got, want)
	}
	if got, want := r.cfg.leashContainer, "target1-leash"; got != want {
		t.Fatalf("leash container mismatch: got %q want %q", got, want)
	}
}

func TestAssignContainerNamesKeepsBase(t *testing.T) {
	t.Parallel()

	commandOverrideMu.Lock()
	restoreOutput := commandOutput
	commandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		t.Helper()
		if name == "docker" && len(args) > 0 && args[0] == "inspect" {
			target := args[len(args)-1]
			return "", fmt.Errorf("Error: No such object: %s", target)
		}
		return "", fmt.Errorf("unexpected command: %s %v", name, args)
	}
	t.Cleanup(func() {
		commandOutput = restoreOutput
		commandOverrideMu.Unlock()
	})

	r := &runner{
		cfg: config{
			targetContainer:     "target",
			leashContainer:      "target-leash",
			targetContainerBase: "target",
			leashContainerBase:  "target-leash",
		},
		logger: log.New(io.Discard, "", 0),
	}

	if err := r.assignContainerNames(context.Background()); err != nil {
		t.Fatalf("assignContainerNames returned error: %v", err)
	}

	if got, want := r.cfg.targetContainer, "target"; got != want {
		t.Fatalf("target container mismatch: got %q want %q", got, want)
	}
	if got, want := r.cfg.leashContainer, "target-leash"; got != want {
		t.Fatalf("leash container mismatch: got %q want %q", got, want)
	}
}

func TestAllocateListenPortAutoIncrement(t *testing.T) {
	t.Parallel()

	commandOverrideMu.Lock()
	restoreOutput := commandOutput
	var psCalls int
	commandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		t.Helper()
		if name == "docker" && len(args) > 0 && args[0] == "ps" {
			psCalls++
			if psCalls == 1 {
				return "foo 0.0.0.0:18080->18080/tcp", nil
			}
			return "", nil
		}
		return "", fmt.Errorf("unexpected command: %s %v", name, args)
	}
	t.Cleanup(func() {
		commandOutput = restoreOutput
		commandOverrideMu.Unlock()
	})

	r := &runner{
		cfg: config{
			listenCfg:      listen.Config{Host: "", Port: "18080"},
			listenExplicit: false,
		},
		logger: log.New(io.Discard, "", 0),
	}

	if err := r.allocateListenPort(context.Background()); err != nil {
		t.Fatalf("allocateListenPort returned error: %v", err)
	}

	if got, want := r.cfg.listenCfg.Port, "18081"; got != want {
		t.Fatalf("listen port mismatch: got %q want %q", got, want)
	}
}

func TestAllocateListenPortExplicitFailure(t *testing.T) {
	t.Parallel()

	commandOverrideMu.Lock()
	restoreOutput := commandOutput
	commandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		t.Helper()
		if name == "docker" && len(args) > 0 && args[0] == "ps" {
			return "foo 127.0.0.1:19000->19000/tcp", nil
		}
		return "", fmt.Errorf("unexpected command: %s %v", name, args)
	}
	t.Cleanup(func() {
		commandOutput = restoreOutput
		commandOverrideMu.Unlock()
	})

	r := &runner{
		cfg: config{
			listenCfg:      listen.Config{Host: "", Port: "19000"},
			listenExplicit: true,
		},
		logger: log.New(io.Discard, "", 0),
	}

	err := r.allocateListenPort(context.Background())
	if err == nil {
		t.Fatal("expected error when explicit listen port is busy")
	}
	if !strings.Contains(err.Error(), "--listen") {
		t.Fatalf("expected error mentioning --listen, got %v", err)
	}
	if got, want := r.cfg.listenCfg.Port, "19000"; got != want {
		t.Fatalf("explicit listen port should remain unchanged: got %q want %q", got, want)
	}
}
