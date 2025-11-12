package e2e

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	readinessTimeout      = 10 * time.Second
	readinessPollInterval = 50 * time.Millisecond
)

var errReadinessTimeout = errors.New("readiness timeout")

func waitForReadiness(t *testing.T, resource string, readinessCheck func() bool) {
	t.Helper()
	if err := pollReadiness(context.Background(), readinessTimeout, readinessCheck); err != nil {
		t.Fatalf("timed out waiting for %s after %s", resource, readinessTimeout)
	}
}

func waitForReadinessWithin(t *testing.T, resource string, timeout time.Duration, readinessCheck func() bool) {
	t.Helper()
	if err := pollReadiness(context.Background(), timeout, readinessCheck); err != nil {
		t.Fatalf("timed out waiting for %s after %s", resource, timeout)
	}
}

func pollReadiness(ctx context.Context, timeout time.Duration, readinessCheck func() bool) error {
	if timeout <= 0 {
		timeout = readinessTimeout
	}
	timeoutTimer := time.NewTimer(timeout)
	ticker := time.NewTicker(readinessPollInterval)
	defer timeoutTimer.Stop()
	defer ticker.Stop()

	for {
		if readinessCheck() {
			return nil
		}
		select {
		case <-timeoutTimer.C:
			return errReadinessTimeout
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
