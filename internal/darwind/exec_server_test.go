//go:build darwin

package darwind

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	gws "github.com/gorilla/websocket"
	"github.com/strongdm/leash/internal/messages"
)

func TestProbeDarwinWebsocketAck(t *testing.T) {
	addr, shutdown := startMockDarwinServer(t, true)
	defer shutdown()

	if !probeDarwinWebsocket(addr) {
		t.Fatalf("expected probeDarwinWebsocket to succeed")
	}
}

func TestProbeDarwinWebsocketNoAck(t *testing.T) {
	addr, shutdown := startMockDarwinServer(t, false)
	defer shutdown()

	if probeDarwinWebsocket(addr) {
		t.Fatalf("expected probeDarwinWebsocket to fail without ack")
	}
}

func startMockDarwinServer(t *testing.T, sendAck bool) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	upgrader := gws.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Send empty history payload to mirror production behavior.
		_ = conn.WriteMessage(gws.TextMessage, []byte("[]"))

		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}

		if sendAck {
			payload := messages.AckPayload{
				Cmd:    messages.TypeClientHello,
				Status: "ok",
			}
			env, err := messages.WrapPayload("", "", messages.TypeMacAck, 1, payload)
			if err != nil {
				return
			}
			data, err := json.Marshal(env)
			if err != nil {
				return
			}
			_ = conn.WriteMessage(gws.TextMessage, data)
		}

		time.Sleep(50 * time.Millisecond)
	})

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(ln)
	}()

	return ln.Addr().String(), func() {
		_ = server.Close()
		_ = ln.Close()
	}
}
