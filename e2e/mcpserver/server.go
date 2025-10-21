package mcpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"
)

// Server provides a lightweight MCP-compatible endpoint for tests.
// It implements a subset of JSON-RPC 2.0 methods and can emit SSE responses.
type Server struct {
	sessionID string
	counter   atomic.Uint64
	server    *httptest.Server
}

// New creates and starts the test MCP server.
func New() *Server {
	s := &Server{
		sessionID: "feedfacecafedead",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/jsonrpc", s.handleJSONRPC)
	s.server = httptest.NewServer(mux)
	return s
}

// Addr returns the host:port the server is listening on.
func (s *Server) Addr() string {
	return s.server.Listener.Addr().String()
}

// Close shuts down the server.
func (s *Server) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

// handleJSONRPC processes minimal JSON-RPC 2.0 requests and emits either
// structured JSON responses or SSE streams depending on the method.
func (s *Server) handleJSONRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	var req rpcRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.JSONRPC) != "2.0" || req.Method == "" {
		http.Error(w, "unsupported request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Mcp-Session-Id", s.sessionID)

	switch req.Method {
	case "tools/list":
		s.handleToolsList(w, req)
	case "tools/call":
		s.handleToolsCall(w, req)
	default:
		http.Error(w, fmt.Sprintf("unknown method %s", req.Method), http.StatusNotImplemented)
	}
}

func (s *Server) handleToolsList(w http.ResponseWriter, req rpcRequest) {
	resp := rpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"tools": []map[string]string{
				{"name": "search", "description": "demo tool"},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleToolsCall(w http.ResponseWriter, req rpcRequest) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)

	notification := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/tools/list_changed",
	}
	_ = writeSSE(w, notification)
	flusher.Flush()

	time.Sleep(50 * time.Millisecond) // ensure frames are distinct

	final := map[string]any{
		"jsonrpc": "2.0",
		"id":      rawOrString(req.ID, "2"),
		"error": map[string]any{
			"code":    42,
			"message": "boom",
		},
	}
	_ = writeSSE(w, final)
	flusher.Flush()
}

func writeSSE(w http.ResponseWriter, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	return nil
}

func rawOrString(raw json.RawMessage, fallback string) any {
	if len(raw) == 0 || string(raw) == "null" {
		return fallback
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 {
		return fallback
	}
	return json.RawMessage(trimmed)
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   any             `json:"error,omitempty"`
}
