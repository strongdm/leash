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

var testMu sync.Mutex

func TestClientStartAndStop(t *testing.T) {
	t.Parallel()
	testMu.Lock()
	defer testMu.Unlock()

	resetForTest()
	Configure("1.2.3")

	var reqMu sync.Mutex
	var bodies [][]byte
	var wg sync.WaitGroup
	wg.Add(2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()

		reqMu.Lock()
		defer reqMu.Unlock()

		bodies = append(bodies, readBody(t, r))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	endpointURL = srv.URL

	ctx := context.Background()

	const (
		sessionID   = "session-abc"
		workspaceID = "workspace-hash"
	)

	Start(ctx, StartPayload{
		Mode: "runner",
		CLIFlags: map[string]bool{
			"policy_flag_provided": true,
			"listen_flag_provided": false,
		},
		SubcommandPresent: true,
		SessionID:         sessionID,
		WorkspaceID:       workspaceID,
	})

	IncPolicyUpdate(false)
	IncPolicyUpdate(true)

	Stop(ctx)

	waitForRequests(t, &wg, 5*time.Second)

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
	if startPayload.Events[0].Metadata["workspace_id"] != workspaceID {
		t.Fatalf("missing workspace_id metadata: %+v", startPayload.Events[0].Metadata)
	}
	if startPayload.Events[0].Metadata["session_id"] != sessionID {
		t.Fatalf("missing session_id metadata: %+v", startPayload.Events[0].Metadata)
	}
	flags, ok := startPayload.Events[0].Metadata["cli_flags"].(map[string]any)
	if !ok {
		t.Fatalf("cli flags missing or wrong type: %+v", startPayload.Events[0].Metadata)
	}
	if _, ok := flags["policy_flag_provided"]; !ok {
		t.Fatalf("policy flag missing: %+v", flags)
	}
	user, ok := startPayload.Events[0].User.(map[string]any)
	if !ok {
		t.Fatalf("user missing or wrong type: %+v", startPayload.Events[0])
	}
	if user["userID"] != workspaceID {
		t.Fatalf("unexpected userID: %+v", user)
	}
	customIDs, ok := user["customIDs"].(map[string]any)
	if !ok {
		t.Fatalf("customIDs missing: %+v", user)
	}
	if customIDs["leash_session"] != sessionID {
		t.Fatalf("unexpected session custom ID: %+v", customIDs)
	}
	if startPayload.StatsigMetadata.SessionID != sessionID {
		t.Fatalf("unexpected metadata sessionID: %+v", startPayload.StatsigMetadata)
	}
	if startPayload.StatsigMetadata.WorkspaceID != workspaceID {
		t.Fatalf("unexpected metadata workspaceID: %+v", startPayload.StatsigMetadata)
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
	if metadata["workspace_id"] != workspaceID {
		t.Fatalf("missing workspace_id in session event: %+v", metadata)
	}
	if metadata["session_id"] != sessionID {
		t.Fatalf("missing session_id in session event: %+v", metadata)
	}
	userStop, ok := stopPayload.Events[0].User.(map[string]any)
	if !ok {
		t.Fatalf("session user missing or wrong type: %+v", stopPayload.Events[0])
	}
	if userStop["userID"] != workspaceID {
		t.Fatalf("session userID mismatch: %+v", userStop)
	}
	customIDsStop, ok := userStop["customIDs"].(map[string]any)
	if !ok {
		t.Fatalf("session customIDs missing: %+v", userStop)
	}
	if customIDsStop["leash_session"] != sessionID {
		t.Fatalf("session custom ID mismatch: %+v", customIDsStop)
	}
	if stopPayload.StatsigMetadata.SessionID != sessionID {
		t.Fatalf("session metadata sessionID mismatch: %+v", stopPayload.StatsigMetadata)
	}
	if stopPayload.StatsigMetadata.WorkspaceID != workspaceID {
		t.Fatalf("session metadata workspaceID mismatch: %+v", stopPayload.StatsigMetadata)
	}
}

func TestClientDisabled(t *testing.T) {
	t.Parallel()
	testMu.Lock()
	defer testMu.Unlock()

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

func waitForRequests(t *testing.T, wg *sync.WaitGroup, timeout time.Duration) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for telemetry requests")
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

	if globalClient != nil {
		globalClient.shutdown()
	}

	configuredVer.Store("dev")
	globalClient = nil
	endpointURL = defaultEndpoint
	randSource.Store(0)
}
