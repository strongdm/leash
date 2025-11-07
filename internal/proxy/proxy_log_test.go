package proxy

import (
	"errors"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

type captureBroadcaster struct {
	entries []string
}

func (c *captureBroadcaster) BroadcastLog(entry string) {
	c.entries = append(c.entries, entry)
}

func TestLogRequestDecisionUsesStatusWhenAvailable(t *testing.T) {
	t.Parallel()

	logger, err := lsm.NewSharedLogger("")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer logger.Close()

	capture := &captureBroadcaster{}
	logger.SetBroadcaster(capture)

	proxy := &MITMProxy{sharedLogger: logger}

	proxy.logRequest("http", "host", "80", "/ok", "", "", 200, errors.New("client closed"), []string{"alpha"}, "allowed")

	if len(capture.entries) == 0 {
		t.Fatalf("expected log entry to be captured")
	}
	entry := capture.entries[0]
	if !strings.Contains(entry, "decision=allowed") {
		t.Fatalf("expected decision=allowed, got %q", entry)
	}
	if !strings.Contains(entry, `secret_hits="alpha"`) {
		t.Fatalf("expected secret hits annotation, got %q", entry)
	}
}

func TestLogRequestDecisionFallsBackToErrorWhenNoStatus(t *testing.T) {
	t.Parallel()

	logger, err := lsm.NewSharedLogger("")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer logger.Close()

	capture := &captureBroadcaster{}
	logger.SetBroadcaster(capture)

	proxy := &MITMProxy{sharedLogger: logger}

	proxy.logRequest("http", "host", "80", "/oops", "", "", 0, errors.New("forward failed"), nil, "allowed")

	if len(capture.entries) == 0 {
		t.Fatalf("expected log entry to be captured")
	}
	entry := capture.entries[0]
	if !strings.Contains(entry, "decision=allowed") {
		t.Fatalf("expected decision=allowed, got %q", entry)
	}
	if !strings.Contains(entry, "error=\"forward failed\"") {
		t.Fatalf("expected error field, got %q", entry)
	}
}

func TestLogRequestDecisionUsesStatusForDenials(t *testing.T) {
	t.Parallel()

	logger, err := lsm.NewSharedLogger("")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer logger.Close()

	capture := &captureBroadcaster{}
	logger.SetBroadcaster(capture)

	proxy := &MITMProxy{sharedLogger: logger}

	proxy.logRequest("http", "host", "80", "/forbidden", "", "", 403, nil, nil, "denied")

	if len(capture.entries) == 0 {
		t.Fatalf("expected log entry to be captured")
	}
	entry := capture.entries[0]
	if !strings.Contains(entry, "decision=denied") {
		t.Fatalf("expected decision=denied, got %q", entry)
	}
}
