//go:build e2e

package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strongdm/leash/e2e/mcpserver"
	"github.com/strongdm/leash/internal/lsm"
)

type capturingBroadcaster struct {
	mu      sync.Mutex
	entries []string
}

func (c *capturingBroadcaster) BroadcastLog(entry string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, entry)
}

func (c *capturingBroadcaster) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.entries))
	copy(out, c.entries)
	return out
}

func TestMCPObserverCapturesJSONRPCAndSSE(t *testing.T) {
	// Some sandboxes disallow binding; skip if httptest server cannot start.
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("skipping integration test: cannot bind test server (%v)", r)
		}
	}()
	srv := mcpserver.New()
	defer srv.Close()

	logger, err := lsm.NewSharedLogger("")
	if err != nil {
		t.Fatalf("failed to create shared logger: %v", err)
	}
	capture := &capturingBroadcaster{}
	logger.SetBroadcaster(capture)

	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport}

	proxy := &MITMProxy{
		headerRewriter: NewHeaderRewriter(),
		httpClient:     client,
		sharedLogger:   logger,
		mcpObserver: newMCPObserver(MCPConfig{
			Mode:          MCPModeEnhanced,
			SniffLimit:    32 * 1024,
			SSEEventLimit: 10,
		}, logger),
	}
	proxy.SetPolicyChecker(stubPolicyChecker{allowConnect: true})

	sendThroughProxy := func(rawRequest string) string {
		originalDest := srv.Addr()
		reqBytes := []byte(rawRequest)
		split := len(reqBytes) / 2
		if split == 0 {
			split = len(reqBytes)
		}
		initialData := reqBytes[:split]
		remaining := reqBytes[split:]

		clientConn, serverConn := net.Pipe()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer serverConn.Close()
			proxy.handleTransparentHTTP(serverConn, originalDest, initialData)
		}()

		writeErr := make(chan error, 1)
		go func() {
			if len(remaining) == 0 {
				writeErr <- nil
				return
			}
			_, err := clientConn.Write(remaining)
			writeErr <- err
		}()

		var respBuf bytes.Buffer
		tmp := make([]byte, 1024)
		deadline := time.Now().Add(2 * time.Second)
		for {
			_ = clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := clientConn.Read(tmp)
			if n > 0 {
				respBuf.Write(tmp[:n])
			}
			if err == nil {
				continue
			}
			if err == io.EOF {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Now().After(deadline) {
					break
				}
				continue
			}
			break
		}

		_ = clientConn.Close()

		if err := <-writeErr; err != nil {
			t.Fatalf("failed to write request: %v", err)
		}
		wg.Wait()
		return respBuf.String()
	}

	listBody := `{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}`
	requestList := fmt.Sprintf(
		"POST /jsonrpc HTTP/1.1\r\nHost: mcp.test\r\nMCP-Protocol-Version: 1.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(listBody), listBody,
	)
	_ = sendThroughProxy(requestList)

	callBody := `{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"search"}}`
	requestCall := fmt.Sprintf(
		"POST /jsonrpc HTTP/1.1\r\nHost: mcp.test\r\nMCP-Protocol-Version: 1.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(callBody), callBody,
	)
	_ = sendThroughProxy(requestCall)

	var discover, notify, call string
	for _, entry := range capture.all() {
		if !strings.HasPrefix(entry, "event=mcp") {
			continue
		}
		switch {
		case strings.HasPrefix(entry, "event=mcp.discover"):
			discover = entry
		case strings.HasPrefix(entry, "event=mcp.notification"):
			notify = entry
		case strings.HasPrefix(entry, "event=mcp.call"):
			call = entry
		}
	}

	if discover == "" {
		t.Fatalf("missing mcp.discover event in logs: %+v", capture.all())
	}
	if !strings.Contains(discover, `method="tools/list"`) || !strings.Contains(discover, `transport="json"`) {
		t.Fatalf("unexpected discover log: %s", discover)
	}
	if !strings.Contains(discover, `session="feedface"`) {
		t.Fatalf("discover log missing truncated session: %s", discover)
	}

	if notify == "" {
		t.Fatalf("missing mcp.notification event in logs: %+v", capture.all())
	}
	if !strings.Contains(notify, `method="notifications/tools/list_changed"`) || !strings.Contains(notify, `transport="sse"`) {
		t.Fatalf("unexpected notify log: %s", notify)
	}
	if !strings.Contains(notify, `session="feedface"`) {
		t.Fatalf("notification log missing session: %s", notify)
	}

	if call == "" {
		t.Fatalf("missing mcp.call event in logs: %+v", capture.all())
	}
	if !strings.Contains(call, `tool="search"`) ||
		!strings.Contains(call, `outcome=error`) ||
		!strings.Contains(call, `error="boom"`) ||
		!strings.Contains(call, `decision=denied`) {
		t.Fatalf("unexpected call log: %s", call)
	}
	if !strings.Contains(call, `transport="sse"`) || !strings.Contains(call, `proto="1.1"`) {
		t.Fatalf("call log missing transport/proto: %s", call)
	}
	if !strings.Contains(call, `session="feedface"`) {
		t.Fatalf("call log missing session: %s", call)
	}
}

func TestMCPObserverCapturesSessionSSEStream(t *testing.T) {
	logger, err := lsm.NewSharedLogger("")
	if err != nil {
		t.Fatalf("failed to create shared logger: %v", err)
	}
	capture := &capturingBroadcaster{}
	logger.SetBroadcaster(capture)

	observer := newMCPObserver(MCPConfig{
		Mode:          MCPModeEnhanced,
		SniffLimit:    32 * 1024,
		SSEEventLimit: 10,
	}, logger)

	ctx := &mcpRequestContext{
		event:   "mcp.call",
		method:  "tools/call",
		server:  "mcp.test",
		proto:   "1.1",
		id:      "2",
		sampled: true,
		started: time.Now(),
	}
	observer.registerSession("feedfacecafedead", ctx)

	stream := strings.Join([]string{
		`data: {"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"get_library_docs"}}`,
		``,
		`data: {"jsonrpc":"2.0","method":"notifications/foo"}`,
		``,
	}, "\n") + "\n"

	body := io.NopCloser(strings.NewReader(stream))
	wrapped := observer.wrapSessionSSE("feedfacecafedead", "mcp.test", "1.1", body)
	if _, err := io.ReadAll(wrapped); err != nil {
		t.Fatalf("failed to read wrapped stream: %v", err)
	}
	_ = wrapped.Close()

	var streamCall, streamNotify string
	for _, entry := range capture.all() {
		switch {
		case strings.HasPrefix(entry, "event=mcp.call"):
			streamCall = entry
		case strings.HasPrefix(entry, "event=mcp.notification"):
			streamNotify = entry
		}
	}

	if streamCall == "" {
		t.Fatalf("missing stream call log: %+v", capture.all())
	}
	if !strings.Contains(streamCall, `tool="get_library_docs"`) ||
		!strings.Contains(streamCall, `id="abc"`) ||
		!strings.Contains(streamCall, `outcome=pending`) ||
		!strings.Contains(streamCall, `session="feedface"`) {
		t.Fatalf("unexpected stream call log: %s", streamCall)
	}

	if streamNotify == "" {
		t.Fatalf("missing stream notification log: %+v", capture.all())
	}
	if !strings.Contains(streamNotify, `method="notifications/foo"`) ||
		!strings.Contains(streamNotify, `session="feedface"`) {
		t.Fatalf("unexpected stream notification log: %s", streamNotify)
	}
}

func TestMCPObserverPolicyDenialShowsDeniedDecision(t *testing.T) {
	logger, err := lsm.NewSharedLogger("")
	if err != nil {
		t.Fatalf("failed to create shared logger: %v", err)
	}
	capture := &capturingBroadcaster{}
	logger.SetBroadcaster(capture)

	observer := newMCPObserver(MCPConfig{
		Mode:       MCPModeBasic,
		SniffLimit: 32 * 1024,
	}, logger)

	// Simulate a policy-denied MCP call (outcome=denied, status=403)
	ctx := &mcpRequestContext{
		event:           "mcp.call",
		method:          "tools/call",
		server:          "mcp.context7.com",
		tool:            "resolve-library-id",
		responseOutcome: "denied",
		responseError:   "policy_denied",
		started:         time.Now().Add(-10 * time.Millisecond),
	}

	observer.logHTTPRequest(ctx, 403, "", "", nil)

	var callLog string
	for _, entry := range capture.all() {
		if strings.HasPrefix(entry, "event=mcp.call") {
			callLog = entry
			break
		}
	}

	if callLog == "" {
		t.Fatalf("missing mcp.call event in logs: %+v", capture.all())
	}

	// Verify that both outcome and decision show "denied" for policy denials
	if !strings.Contains(callLog, `tool="resolve-library-id"`) {
		t.Errorf("call log missing tool: %s", callLog)
	}
	if !strings.Contains(callLog, `server="mcp.context7.com"`) {
		t.Errorf("call log missing server: %s", callLog)
	}
	if !strings.Contains(callLog, `status=403`) {
		t.Errorf("call log missing status 403: %s", callLog)
	}
	if !strings.Contains(callLog, `outcome=denied`) {
		t.Errorf("call log missing outcome=denied: %s", callLog)
	}
	if !strings.Contains(callLog, `decision=denied`) {
		t.Errorf("call log should show decision=denied for policy denials, got: %s", callLog)
	}
	if !strings.Contains(callLog, `error="policy_denied"`) {
		t.Errorf("call log missing error field: %s", callLog)
	}
}
