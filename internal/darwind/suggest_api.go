//go:build darwin

package darwind

import (
	"net/http"
	"strconv"
	"time"

	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/policy/suggest"
	"github.com/strongdm/leash/internal/websocket"
)

type suggestAPI struct {
	mgr  *policy.Manager
	hub  *websocket.WebSocketHub
	opts suggest.Options
}

func newSuggestAPI(mgr *policy.Manager, hub *websocket.WebSocketHub) *suggestAPI {
	return &suggestAPI{
		mgr:  mgr,
		hub:  hub,
		opts: suggest.DefaultOptions(),
	}
}

func (api *suggestAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("/suggest", api.handleSuggest)
}

func (api *suggestAPI) handleSuggest(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	opts := api.opts

	if tailStr := r.URL.Query().Get("tail"); tailStr != "" {
		if v, err := strconv.Atoi(tailStr); err == nil {
			opts.TailLimit = v
		}
	}
	if winStr := r.URL.Query().Get("window"); winStr != "" {
		if dur, err := time.ParseDuration(winStr); err == nil {
			opts.SessionWindow = dur
		}
	}

	events := api.hub.RecentEvents(opts.TailLimit)
	sequences := suggest.BuildSequencesFromLogs(events, opts.SessionWindow)
	policies, httpRules := api.mgr.GetActiveRules()

	inputs := suggest.Inputs{
		LSMPolicies:    policies,
		HTTPRewrites:   httpRules,
		EventSequences: sequences,
	}
	result := suggest.Analyze(inputs, opts)

	response := struct {
		GeneratedAt   time.Time            `json:"generated_at"`
		EventCount    int                  `json:"event_count"`
		SequenceCount int                  `json:"sequence_count"`
		Suggestions   []suggest.Suggestion `json:"suggestions"`
	}{
		GeneratedAt:   time.Now().UTC(),
		EventCount:    len(events),
		SequenceCount: len(sequences),
		Suggestions:   result.Suggestions,
	}

	writeJSON(w, http.StatusOK, response)
}
