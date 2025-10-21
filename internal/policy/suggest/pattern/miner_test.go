package pattern

import (
	"testing"
	"time"
)

func TestMineReturnsTargetedPatterns(t *testing.T) {
	base := time.Now()
	trace := func(actions ...string) []Event {
		out := make([]Event, len(actions))
		for i, a := range actions {
			out[i] = Event{
				Timestamp:     base.Add(time.Duration(i) * time.Second),
				PrincipalID:   "user1",
				ActionFamily:  familyFor(a),
				ActionName:    a,
				ResourceClass: resourceFor(a),
				ResourceFacet: facetFor(a),
				Outcome:       "permit",
			}
		}
		return out
	}

	seqs := []Sequence{
		{SessionID: "session-1", Principal: "user1", Events: trace("open", "read", "connect")},
		{SessionID: "session-2", Principal: "user1", Events: trace("open", "read", "connect")},
		{SessionID: "session-3", Principal: "user2", Events: trace("open", "write", "connect")},
		{SessionID: "session-4", Principal: "user3", Events: trace("exec", "open", "connect")},
	}

	cfg := DefaultConfig()
	cfg.MinSupport = 2
	cfg.TargetActions = []string{"connect"}
	cfg.MaxSpan = 2
	cfg.MaxGap = 2
	cfg.MaxLength = 3

	patterns := Mine(seqs, cfg)
	if len(patterns) == 0 {
		t.Fatalf("expected patterns, got none")
	}

	foundThreeStep := false
	for _, p := range patterns {
		if len(p.Tokens) != 3 {
			continue
		}
		if p.Tokens[0] == "filesystem:open:unix.file:/etc" && p.Tokens[1] == "filesystem:read:unix.file:/etc" && p.Tokens[2] == "network:connect:net.host:example.com" {
			foundThreeStep = true
			if p.Support != 2 {
				t.Fatalf("expected support 2, got %d", p.Support)
			}
		}
	}
	if !foundThreeStep {
		t.Fatalf("did not find expected open->read->connect pattern")
	}
}

func familyFor(action string) string {
	switch action {
	case "connect":
		return "network"
	case "exec":
		return "process"
	default:
		return "filesystem"
	}
}

func resourceFor(action string) string {
	switch action {
	case "connect":
		return "net.host"
	case "exec":
		return "process.binary"
	default:
		return "unix.file"
	}
}

func facetFor(action string) string {
	switch action {
	case "connect":
		return "example.com"
	case "exec":
		return "/usr/bin/vim"
	case "write":
		return "/etc"
	default:
		return "/etc"
	}
}
