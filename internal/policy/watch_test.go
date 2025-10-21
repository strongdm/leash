package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cedarutil "github.com/strongdm/leash/internal/cedar"
)

const watcherTimeout = 10 * time.Second

func TestWatchCedarHandlesUpdatesAndErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.cedar")

	initial := `permit (
    principal,
    action == Action::"FileOpen",
    resource == Dir::"/tmp"
);`
	writeCedar(t, path, initial)

	updateCh := make(chan *Config, 4)
	errorCh := make(chan *cedarutil.ErrorDetail, 2)

	cancel, err := WatchCedar(path, 20*time.Millisecond, func(cfg *Config) {
		updateCh <- cfg
	}, func(detail *cedarutil.ErrorDetail) {
		errorCh <- detail
	})
	if err != nil {
		t.Fatalf("WatchCedar returned error: %v", err)
	}
	defer cancel()

	validUpdate := `permit (
    principal,
    action == Action::"FileOpen",
    resource == Dir::"/var"
);`
	writeCedar(t, path, validUpdate)

	cfg := expectConfig(t, updateCh, "watcher update after valid policy change")
	if cfg.LSMPolicies == nil || len(cfg.LSMPolicies.Open) == 0 {
		t.Fatal("expected open rules after valid update")
	}

	invalidUpdate := "permit (principal"
	writeCedar(t, path, invalidUpdate)

	detail := expectError(t, errorCh, "watcher error after invalid policy")
	if detail.Code != "CEDAR_PARSE" {
		t.Fatalf("expected Cedar parse error, got %#v", detail)
	}

	recovery := `permit (
    principal,
    action == Action::"FileOpen",
    resource == Dir::"/home"
);`
	writeCedar(t, path, recovery)

	cfg = expectConfig(t, updateCh, "watcher recovery update")
	if cfg.LSMPolicies == nil || len(cfg.LSMPolicies.Open) == 0 {
		t.Fatal("expected open rules after recovery update")
	}
}

func writeCedar(t *testing.T, path, cedar string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.TrimSpace(cedar)+"\n"), 0o644); err != nil {
		t.Fatalf("failed to write Cedar file %s: %v", path, err)
	}
	// Ensure the file modification time advances beyond the last successful read; some filesystems
	// only tick mtime in coarse increments, which can cause WatchCedar to miss rapid successive writes.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		// Fallback: wait long enough for the underlying filesystem timestamp resolution.
		time.Sleep(1500 * time.Millisecond)
	}
}

func expectConfig(t *testing.T, ch <-chan *Config, context string) *Config {
	t.Helper()
	select {
	case cfg := <-ch:
		if cfg == nil {
			t.Fatalf("received nil config for %s", context)
		}
		return cfg
	case <-time.After(watcherTimeout):
		t.Fatalf("timed out waiting for %s", context)
		return nil
	}
}

func expectError(t *testing.T, ch <-chan *cedarutil.ErrorDetail, context string) *cedarutil.ErrorDetail {
	t.Helper()
	select {
	case detail := <-ch:
		if detail == nil {
			t.Fatalf("received nil error detail for %s", context)
		}
		return detail
	case <-time.After(watcherTimeout):
		t.Fatalf("timed out waiting for %s", context)
		return nil
	}
}
