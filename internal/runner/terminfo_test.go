package runner

import (
	"os"
	"testing"
)

func TestNormalizeTERMForBubbleTeaGhostty(t *testing.T) {
	t.Parallel()

	prev, existed := os.LookupEnv("TERM")
	if err := os.Setenv("TERM", "xterm-ghostty"); err != nil {
		t.Fatalf("set TERM: %v", err)
	}
	t.Cleanup(func() {
		if !existed {
			_ = os.Unsetenv("TERM")
			return
		}
		_ = os.Setenv("TERM", prev)
	})

	restore := normalizeTERMForBubbleTea()
	defer restore()

	if got := os.Getenv("TERM"); got != "xterm-256color" {
		t.Fatalf("TERM = %q, want xterm-256color", got)
	}
}

func TestNormalizeTERMForBubbleTeaPassthrough(t *testing.T) {
	t.Parallel()

	original := "xterm-256color"
	prev, existed := os.LookupEnv("TERM")
	if err := os.Setenv("TERM", original); err != nil {
		t.Fatalf("set TERM: %v", err)
	}
	t.Cleanup(func() {
		if !existed {
			_ = os.Unsetenv("TERM")
			return
		}
		_ = os.Setenv("TERM", prev)
	})

	restore := normalizeTERMForBubbleTea()
	defer restore()

	if got := os.Getenv("TERM"); got != original {
		t.Fatalf("TERM changed to %q, want %q", got, original)
	}
}
