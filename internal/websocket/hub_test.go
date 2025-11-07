package websocket

// These tests were added after a production panic where slow or stalled websocket clients
// caused the hub to attempt a non-blocking send on a channel that had just been closed
// during client teardown. This reproduces the race condition to ensure enqueue doesn't
// panic and verifies the revised drop-oldest ring-buffer behavior which provides the
// resilience fix.

import "testing"

func TestHubEnqueueAfterClientClosureDoesNotPanic(t *testing.T) {
	t.Parallel()

	hub := NewWebSocketHub(nil, 1, 0, 0)
	client := &client{
		id:     "test-client",
		send:   make(chan []byte, 1),
		closed: make(chan struct{}),
		hub:    hub,
	}

	// Simulate the client being torn down before the hub finishes broadcasting.
	close(client.closed)
	close(client.send)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("enqueue panicked: %v", r)
		}
	}()

	hub.enqueue(client, []byte("payload"))
}

func TestHubEnqueueDropsOldestMessageWhenFull(t *testing.T) {
	t.Parallel()

	hub := NewWebSocketHub(nil, 1, 0, 0)
	client := &client{
		id:     "ring-client",
		send:   make(chan []byte, 2),
		closed: make(chan struct{}),
		hub:    hub,
	}

	client.closeMu.Lock()
	client.send <- []byte("older")
	client.send <- []byte("newer")
	client.closeMu.Unlock()

	hub.enqueue(client, []byte("latest"))

	first := <-client.send
	if string(first) != "newer" {
		t.Fatalf("expected 'newer' to remain, got %q", string(first))
	}

	second := <-client.send
	if string(second) != "latest" {
		t.Fatalf("expected 'latest' to be enqueued, got %q", string(second))
	}
}

func TestParseLogfmtToJSONCapturesSecretHits(t *testing.T) {
	t.Parallel()

	entry := parseLogfmtToJSON(`time=2025-05-01T12:00:00Z event=http.request secret_hits="alpha,beta,gamma"`)
	if entry.Event != "http.request" {
		t.Fatalf("expected event http.request, got %q", entry.Event)
	}
	if entry.SecretHits == nil {
		t.Fatalf("expected secret hits parsed")
	}
	want := []string{"alpha", "beta", "gamma"}
	if len(entry.SecretHits) != len(want) {
		t.Fatalf("expected %d secret hits, got %d", len(want), len(entry.SecretHits))
	}
	for i, hit := range want {
		if entry.SecretHits[i] != hit {
			t.Fatalf("expected secret hit %q at index %d, got %q", hit, i, entry.SecretHits[i])
		}
	}
}
