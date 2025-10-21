package pattern

import (
	"sort"
	"strings"
	"time"
)

// Event represents a single action within an agent session after feature
// enrichment. Only the fields required for prototype mining are included.
type Event struct {
	Timestamp     time.Time
	PrincipalID   string
	ActionFamily  string
	ActionName    string
	ResourceClass string
	ResourceFacet string
	Outcome       string
}

// Sequence is an ordered list of events belonging to the same logical session
// or workflow.
type Sequence struct {
	SessionID string
	Principal string
	Events    []Event
}

// MinerConfig controls the targeted sequential mining pass.
type MinerConfig struct {
	TargetActions []string
	MinSupport    int
	MaxSpan       int // maximum number of preceding events considered
	MaxGap        int // maximum index gap between consecutive tokens
	MaxLength     int // maximum length of mined pattern (including target)
}

// Pattern captures a mined workflow motif.
type Pattern struct {
	Tokens       []string
	Support      int
	Sessions     []string
	TargetAction string
}

// DefaultConfig returns conservative parameters suitable for early experiments.
func DefaultConfig() MinerConfig {
	return MinerConfig{
		TargetActions: []string{"connect"},
		MinSupport:    2,
		MaxSpan:       5,
		MaxGap:        2,
		MaxLength:     3,
	}
}

// Mine discovers frequent sequences that terminate in any target action.
// Sequences are returned sorted by descending support.
func Mine(seqs []Sequence, cfg MinerConfig) []Pattern {
	if cfg.MinSupport <= 0 {
		cfg.MinSupport = 2
	}
	if cfg.MaxSpan <= 0 {
		cfg.MaxSpan = 5
	}
	if cfg.MaxGap <= 0 {
		cfg.MaxGap = cfg.MaxSpan
	}
	if cfg.MaxLength <= 0 {
		cfg.MaxLength = 3
	}
	if len(cfg.TargetActions) == 0 {
		cfg.TargetActions = []string{"connect"}
	}

	targetSet := make(map[string]struct{}, len(cfg.TargetActions))
	for _, t := range cfg.TargetActions {
		targetSet[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}

	type stats struct {
		count    int
		sessions map[string]struct{}
		target   string
	}
	patterns := make(map[string]*stats)

	for _, seq := range seqs {
		if len(seq.Events) == 0 {
			continue
		}
		tokens := canonicalTokens(seq.Events)
		indexedTargets := targetIndexes(seq.Events, targetSet)
		if len(indexedTargets) == 0 {
			continue
		}
		seenInSession := make(map[string]struct{})

		for _, ti := range indexedTargets {
			targetToken := tokens[ti]
			candidates := candidateIndexes(ti, len(tokens), cfg)
			path := make([]int, 0, cfg.MaxLength-1)
			emit := func(idxs []int) {
				full := append([]int{}, idxs...)
				full = append(full, ti)
				if len(full) == 0 || len(full) > cfg.MaxLength {
					return
				}
				if ti-full[0] > cfg.MaxSpan {
					return
				}
				for i := 1; i < len(full); i++ {
					if full[i]-full[i-1] > cfg.MaxGap {
						return
					}
				}
				patternTokens := make([]string, len(full))
				for i, idx := range full {
					patternTokens[i] = tokens[idx]
				}
				key := strings.Join(patternTokens, " -> ")
				if _, exists := seenInSession[key]; exists {
					return
				}
				seenInSession[key] = struct{}{}
				rec := patterns[key]
				if rec == nil {
					rec = &stats{
						sessions: make(map[string]struct{}),
						target:   targetToken,
					}
					patterns[key] = rec
				}
				rec.count++
				rec.sessions[seq.SessionID] = struct{}{}
			}

			emit(nil) // bare target
			backtrack(candidates, path, emit, cfg.MaxLength-1)
		}
	}

	out := make([]Pattern, 0, len(patterns))
	for key, stat := range patterns {
		if stat.count < cfg.MinSupport {
			continue
		}
		sessionIDs := make([]string, 0, len(stat.sessions))
		for id := range stat.sessions {
			sessionIDs = append(sessionIDs, id)
		}
		sort.Strings(sessionIDs)
		tokens := strings.Split(key, " -> ")
		out = append(out, Pattern{
			Tokens:       tokens,
			Support:      stat.count,
			Sessions:     sessionIDs,
			TargetAction: stat.target,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Support == out[j].Support {
			return strings.Join(out[i].Tokens, " -> ") < strings.Join(out[j].Tokens, " -> ")
		}
		return out[i].Support > out[j].Support
	})

	return out
}

func canonicalTokens(events []Event) []string {
	out := make([]string, len(events))
	for i, evt := range events {
		family := strings.ToLower(evt.ActionFamily)
		if family == "" {
			family = "unknown"
		}
		action := strings.ToLower(evt.ActionName)
		if action == "" {
			action = "unknown"
		}
		resource := strings.ToLower(evt.ResourceClass)
		if resource == "" {
			resource = "resource"
		}
		facet := strings.ToLower(evt.ResourceFacet)
		if facet == "" {
			facet = "*"
		}
		out[i] = strings.Join([]string{family, action, resource, facet}, ":")
	}
	return out
}

func targetIndexes(events []Event, targets map[string]struct{}) []int {
	indexes := make([]int, 0)
	for i, evt := range events {
		if _, ok := targets[strings.ToLower(evt.ActionName)]; ok {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

func candidateIndexes(targetIdx int, total int, cfg MinerConfig) []int {
	minIdx := targetIdx - cfg.MaxSpan
	if minIdx < 0 {
		minIdx = 0
	}
	candidates := make([]int, 0, cfg.MaxSpan)
	for i := minIdx; i < targetIdx; i++ {
		candidates = append(candidates, i)
	}
	return candidates
}

func backtrack(candidates []int, path []int, emit func([]int), depth int) {
	if depth == 0 {
		return
	}
	start := 0
	if len(path) > 0 {
		last := path[len(path)-1]
		for start < len(candidates) && candidates[start] <= last {
			start++
		}
	}
	for i := start; i < len(candidates); i++ {
		path = append(path, candidates[i])
		tmp := make([]int, len(path))
		copy(tmp, path)
		emit(tmp)
		backtrack(candidates, path, emit, depth-1)
		path = path[:len(path)-1]
	}
}
