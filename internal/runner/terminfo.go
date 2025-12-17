package runner

import (
	"os"
	"strings"
)

// normalizeTERMForBubbleTea maps compatible but uncommon TERM values (e.g.
// xterm-ghostty) to widely supported entries so Bubble Tea can rely on terminfo
// for key handling and styling. It returns a restore function to put TERM back.
func normalizeTERMForBubbleTea() func() {
	const ghosttyTERM = "xterm-ghostty"

	term := strings.TrimSpace(os.Getenv("TERM"))
	if term == "" || strings.EqualFold(term, "xterm-256color") {
		return func() {}
	}
	if !strings.EqualFold(term, ghosttyTERM) {
		return func() {}
	}

	prev, existed := os.LookupEnv("TERM")
	_ = os.Setenv("TERM", "xterm-256color")

	return func() {
		if !existed {
			_ = os.Unsetenv("TERM")
			return
		}
		_ = os.Setenv("TERM", prev)
	}
}
