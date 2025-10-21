package suggest

import (
	"sort"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/policy/suggest/pattern"
	"github.com/strongdm/leash/internal/websocket"
)

// BuildSequencesFromLogs groups recent runtime log entries into per-principal
// sequences, splitting a principal's stream whenever the time gap between
// events exceeds the provided window. The logs are expected in chronological
// order (oldest first); if not, they are ordered before grouping.
func BuildSequencesFromLogs(logs []websocket.LogEntry, window time.Duration) []pattern.Sequence {
	if window <= 0 {
		window = 5 * time.Minute
	}
	// Defensive copy + sort by time
	items := make([]websocket.LogEntry, 0, len(logs))
	items = append(items, logs...)
	sort.Slice(items, func(i, j int) bool {
		ti := parseTime(items[i].Time)
		tj := parseTime(items[j].Time)
		if ti.Equal(tj) {
			// stable-ish fallback
			return i < j
		}
		return ti.Before(tj)
	})

	type cursor struct {
		last time.Time
		seq  pattern.Sequence
	}
	byPrincipal := make(map[string]*cursor)
	out := make([]pattern.Sequence, 0)

	for _, e := range items {
		ts := parseTime(e.Time)
		principal := principalOf(e)
		if principal == "" {
			// Skip unprincipaled events for suggestions
			continue
		}
		cur := byPrincipal[principal]
		if cur == nil || (cur.last.Add(window).Before(ts)) {
			// Flush previous, start new sequence
			if cur != nil && len(cur.seq.Events) > 0 {
				out = append(out, cur.seq)
			}
			cur = &cursor{
				last: ts,
				seq: pattern.Sequence{
					SessionID: principal + "@" + ts.UTC().Format(time.RFC3339Nano),
					Principal: principal,
					Events:    make([]pattern.Event, 0, 8),
				},
			}
			byPrincipal[principal] = cur
		}
		cur.last = ts
		cur.seq.Events = append(cur.seq.Events, toPatternEvent(e, ts))
	}

	// Drain any active cursors
	for _, cur := range byPrincipal {
		if len(cur.seq.Events) > 0 {
			out = append(out, cur.seq)
		}
	}
	return out
}

func parseTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return time.Time{}
}

func principalOf(e websocket.LogEntry) string {
	// Prefer explicit tool for HTTP; fall back to exe for system events.
	p := strings.TrimSpace(e.Tool)
	if p != "" {
		return p
	}
	p = strings.TrimSpace(e.Exe)
	return p
}

func toPatternEvent(e websocket.LogEntry, ts time.Time) pattern.Event {
	family, action, rclass, rfacet := classify(e)
	outcome := strings.ToLower(strings.TrimSpace(e.Decision))
	if outcome == "" {
		outcome = "unknown"
	}
	return pattern.Event{
		Timestamp:     ts,
		PrincipalID:   principalOf(e),
		ActionFamily:  family,
		ActionName:    action,
		ResourceClass: rclass,
		ResourceFacet: rfacet,
		Outcome:       outcome,
	}
}

func classify(e websocket.LogEntry) (family, action, rclass, facet string) {
	ev := strings.ToLower(strings.TrimSpace(e.Event))
	switch ev {
	case "file.open":
		return "file", "open", "unix.file", strings.TrimSpace(e.Path)
	case "file.open:ro":
		return "file", "open:ro", "unix.file", strings.TrimSpace(e.Path)
	case "file.open:rw":
		return "file", "open:rw", "unix.file", strings.TrimSpace(e.Path)
	case "proc.exec":
		// Not currently emitted through this path, but keep for symmetry.
		return "process", "exec", "unix.process", strings.TrimSpace(e.Exe)
	case "http.request":
		host := strings.TrimSpace(e.Addr)
		if host == "" {
			host = strings.TrimSpace(e.Server)
		}
		return "http", "request", "http.host", host
	default:
		// Best-effort mapping
		parts := strings.SplitN(ev, ".", 2)
		if len(parts) == 2 {
			return parts[0], parts[1], "resource", ""
		}
		return ev, "event", "resource", ""
	}
}
