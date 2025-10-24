package statsig

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

func TestClientStartAndStop(t *testing.T) {
	resetForTest()
	Configure("1.2.3")

	var reqMu sync.Mutex
	var bodies [][]byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqMu.Lock()
		defer reqMu.Unlock()

		bodies = append(bodies, readBody(t, r))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	endpointURL = srv.URL

	ctx := context.Background()

	Start(ctx, StartPayload{
		Mode: "runner",
		CLIFlags: map[string]bool{
			"policy_flag_provided": true,
			"listen_flag_provided": false,
		},
		SubcommandPresent: true,
	})

	IncPolicyUpdate(false)
	IncPolicyUpdate(true)

	Stop(ctx)

	reqMu.Lock()
	defer reqMu.Unlock()

	if len(bodies) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(bodies))
	}

	var startPayload requestPayload
	if err := json.Unmarshal(bodies[0], &startPayload); err != nil {
		t.Fatalf("unmarshal start payload: %v", err)
	}
	if got := startPayload.Events[0].EventName; got != "leash.start" {
		t.Fatalf("unexpected start event name: %s", got)
	}
	if startPayload.Events[0].Metadata["mode"] != "runner" {
		t.Fatalf("missing mode metadata: %+v", startPayload.Events[0].Metadata)
	}
	if startPayload.Events[0].Metadata["version"] != "1.2.3" {
		t.Fatalf("unexpected version: %+v", startPayload.Events[0].Metadata)
	}
	flags, ok := startPayload.Events[0].Metadata["cli_flags"].(map[string]any)
	if !ok {
		t.Fatalf("cli flags missing or wrong type: %+v", startPayload.Events[0].Metadata)
	}
	if _, ok := flags["policy_flag_provided"]; !ok {
		t.Fatalf("policy flag missing: %+v", flags)
	}

	var stopPayload requestPayload
	if err := json.Unmarshal(bodies[1], &stopPayload); err != nil {
		t.Fatalf("unmarshal stop payload: %v", err)
	}
	if got := stopPayload.Events[0].EventName; got != "leash.session" {
		t.Fatalf("unexpected session event name: %s", got)
	}
	metadata := stopPayload.Events[0].Metadata
	if metadata["policy_updates_total"].(float64) != 2 {
		t.Fatalf("policy total mismatch: %+v", metadata)
	}
	if metadata["policy_update_errors_total"].(float64) != 1 {
		t.Fatalf("policy error total mismatch: %+v", metadata)
	}
}

func TestClientDisabled(t *testing.T) {
	resetForTest()
	if err := os.Setenv("LEASH_DISABLE_TELEMETRY", "1"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	defer os.Unsetenv("LEASH_DISABLE_TELEMETRY")

	Configure("9.9.9")

	called := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case called <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	endpointURL = srv.URL

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	Start(ctx, StartPayload{Mode: "runner"})
	Stop(ctx)

	select {
	case <-called:
		t.Fatal("expected no requests when telemetry disabled")
	case <-time.After(100 * time.Millisecond):
	}
}

func readBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r.Body.Close()
	return body
}

func resetForTest() {
	configureMu.Lock()
	defer configureMu.Unlock()

	configuredVer.Store("dev")
	globalClient = nil
	endpointURL = defaultEndpoint
	randSource.Store(0)
}
