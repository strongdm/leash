package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestTerminationSignalsIncludeInterruptAndTerminate(t *testing.T) {
	want := map[os.Signal]bool{os.Interrupt: false, syscall.SIGTERM: false}
	for _, sig := range terminationSignals() {
		if _, ok := want[sig]; ok {
			want[sig] = true
		}
	}
	for sig, found := range want {
		if !found {
			t.Errorf("termination signal %v is not registered", sig)
		}
	}
}

func TestStopContainersReapsTargetCreatedAfterCanceledLaunch(t *testing.T) {
	commandOverrideMu.Lock()
	restoreOutput := commandOutput
	restoreDelay := canceledLaunchCleanupDelay
	canceledLaunchCleanupDelay = time.Millisecond

	targetExists := false
	inspectCalls := 0
	removeCalls := 0
	commandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		t.Helper()
		if name != "docker" || len(args) == 0 {
			return "", fmt.Errorf("unexpected command: %s %v", name, args)
		}
		switch args[0] {
		case "rm":
			if args[len(args)-1] == "target" && targetExists {
				targetExists = false
				removeCalls++
				return "target\n", nil
			}
			return "", fmt.Errorf("No such container: %s", args[len(args)-1])
		case "inspect":
			if args[len(args)-1] != "target" {
				return "", fmt.Errorf("No such object: %s", args[len(args)-1])
			}
			inspectCalls++
			if inspectCalls == 75 {
				targetExists = true
			}
			if targetExists {
				return "/target\n", nil
			}
			return "", fmt.Errorf("No such object: target")
		default:
			return "", fmt.Errorf("unexpected docker command: %v", args)
		}
	}
	t.Cleanup(func() {
		commandOutput = restoreOutput
		canceledLaunchCleanupDelay = restoreDelay
		commandOverrideMu.Unlock()
	})

	r := &runner{
		cfg: config{
			targetContainer: "target",
			leashContainer:  "target-leash",
		},
		logger:                log.New(io.Discard, "", 0),
		targetLaunchUncertain: true,
	}

	if err := r.stopContainers(context.Background()); err != nil {
		t.Fatalf("stopContainers returned error: %v", err)
	}
	if targetExists {
		t.Fatal("late-created target container was not removed")
	}
	if removeCalls != 1 {
		t.Fatalf("late-created target removal calls: got %d want 1", removeCalls)
	}
	if inspectCalls != 102 {
		t.Fatalf("cleanup did not observe the full reconciliation window: got %d checks want 102", inspectCalls)
	}
}

func TestStopContainersReturnsDockerRemovalError(t *testing.T) {
	commandOverrideMu.Lock()
	restoreOutput := commandOutput
	commandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		return "", fmt.Errorf("docker unavailable")
	}
	t.Cleanup(func() {
		commandOutput = restoreOutput
		commandOverrideMu.Unlock()
	})

	r := &runner{
		cfg:    config{targetContainer: "target", leashContainer: "target-leash"},
		logger: log.New(io.Discard, "", 0),
	}
	if err := r.stopContainers(context.Background()); err == nil {
		t.Fatal("expected Docker removal error")
	}
}

func TestFinalizeSessionReturnsCleanupErrorAfterSuccessfulCommand(t *testing.T) {
	r := &runner{logger: log.New(io.Discard, "", 0)}
	cleanupErr := fmt.Errorf("remove target: docker unavailable")

	err := r.finalizeSession(cleanupErr, 0)
	if err == nil {
		t.Fatal("expected cleanup error after successful command")
	}
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("cleanup error was not preserved: %v", err)
	}
}
