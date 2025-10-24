package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	gws "github.com/gorilla/websocket"
	"github.com/strongdm/leash/internal/lsm"
)

// LogEntry represents a structured log entry for JSON serialization
type LogEntry struct {
	Time             string          `json:"time"`
	Event            string          `json:"event"`
	PID              *int            `json:"pid,omitempty"`
	Cgroup           *int            `json:"cgroup,omitempty"`
	Exe              string          `json:"exe,omitempty"`
	Path             string          `json:"path,omitempty"`
	Decision         string          `json:"decision"`
	Protocol         string          `json:"protocol,omitempty"`
	Addr             string          `json:"addr,omitempty"`
	AddrIP           string          `json:"addr_ip,omitempty"`
	Port             string          `json:"port,omitempty"`
	Status           *int            `json:"status,omitempty"`
	Error            string          `json:"error,omitempty"`
	Reason           string          `json:"reason,omitempty"`
	Args             string          `json:"args,omitempty"`
	Argc             *int            `json:"argc,omitempty"`
	Hostname         string          `json:"hostname,omitempty"`
	HostnameResolved string          `json:"hostname_resolved,omitempty"`
	HostnameObserved string          `json:"hostname_observed,omitempty"`
	HostnameKind     string          `json:"hostname_kind,omitempty"`
	Domain           string          `json:"domain,omitempty"`
	Header           string          `json:"header,omitempty"`
	OldValue         string          `json:"old_value,omitempty"`
	NewValue         string          `json:"new_value,omitempty"`
	Family           string          `json:"family,omitempty"`
	Auth             string          `json:"auth,omitempty"`
	Rule             string          `json:"rule,omitempty"`
	Method           string          `json:"method,omitempty"`
	Server           string          `json:"server,omitempty"`
	Tool             string          `json:"tool,omitempty"`
	InstanceID       string          `json:"instance_id,omitempty"`
	Seq              uint64          `json:"seq,omitempty"`
	StartedAt        string          `json:"started_at,omitempty"`
	UptimeSec        *int64          `json:"uptime_s,omitempty"`
	LastSeq          *uint64         `json:"last_seq,omitempty"`
	Payload          json.RawMessage `json:"payload,omitempty"`
}

// EventRingBuffer maintains a fixed-size buffer of recent events
type EventRingBuffer struct {
	events []LogEntry   // Fixed-size slice of parsed events
	head   int          // Next write position
	tail   int          // Oldest event position
	size   int          // Buffer capacity
	count  int          // Current number of events
	mutex  sync.RWMutex // Thread safety
	full   bool         // Whether buffer has wrapped around
}

// NewEventRingBuffer creates a new ring buffer with the specified size
func NewEventRingBuffer(size int) *EventRingBuffer {
	if size <= 0 {
		size = 25000 // Default size
	}
	return &EventRingBuffer{
		events: make([]LogEntry, size),
		size:   size,
	}
}

// Add adds a new event to the ring buffer
func (rb *EventRingBuffer) Add(event LogEntry) {
	rb.mutex.Lock()
	defer rb.mutex.Unlock()

	rb.events[rb.head] = event
	rb.head = (rb.head + 1) % rb.size

	if rb.full {
		// Buffer is full, advance tail to maintain window
		rb.tail = (rb.tail + 1) % rb.size
	} else {
		rb.count++
		if rb.head == rb.tail && rb.count > 0 {
			rb.full = true
		}
	}
}

// GetAll returns all events in chronological order (oldest first)
func (rb *EventRingBuffer) GetAll() []LogEntry {
	rb.mutex.RLock()
	defer rb.mutex.RUnlock()

	if rb.count == 0 {
		return []LogEntry{}
	}

	result := make([]LogEntry, rb.count)

	if !rb.full {
		// Buffer not full, events are from 0 to head-1
		copy(result, rb.events[:rb.count])
	} else {
		// Buffer is full, events wrap around
		// Copy from tail to end of buffer
		tailToEnd := rb.size - rb.tail
		copy(result, rb.events[rb.tail:])
		// Copy from start of buffer to head
		copy(result[tailToEnd:], rb.events[:rb.head])
	}

	return result
}

// GetTail returns up to the last n events (chronological order).
func (rb *EventRingBuffer) GetTail(n int) []LogEntry {
	if n <= 0 {
		return []LogEntry{}
	}
	rb.mutex.RLock()
	defer rb.mutex.RUnlock()

	if rb.count == 0 {
		return []LogEntry{}
	}

	if !rb.full {
		if n >= rb.count {
			out := make([]LogEntry, rb.count)
			copy(out, rb.events[:rb.count])
			return out
		}
		out := make([]LogEntry, n)
		copy(out, rb.events[rb.count-n:rb.count])
		return out
	}

	// full ring: recent events end at head-1; tail is oldest
	toTake := n
	if toTake > rb.size {
		toTake = rb.size
	}
	if toTake > rb.count {
		toTake = rb.count
	}
	// start index for last toTake events in ring coordinates
	start := (rb.head - toTake + rb.size) % rb.size
	out := make([]LogEntry, toTake)
	if start < rb.head {
		// contiguous slice
		copy(out, rb.events[start:rb.head])
	} else {
		// wrapped around: copy start..end and 0..head
		first := rb.size - start
		copy(out, rb.events[start:])
		copy(out[first:], rb.events[:rb.head])
	}
	return out
}

// GetBulkNDJSON returns all events formatted as NDJSON for bulk transmission
func (rb *EventRingBuffer) GetBulkNDJSON() []byte {
	events := rb.GetAll()
	if len(events) == 0 {
		return []byte{}
	}

	var result strings.Builder
	for _, event := range events {
		if jsonData, err := json.Marshal(event); err == nil {
			result.Write(jsonData)
			result.WriteByte('\n')
		}
	}

	return []byte(result.String())
}

// encodeNDJSONLimited encodes events as NDJSON, ensuring the output
// does not exceed maxBytes. It preserves chronological order and returns
// the encoded bytes and the count of events included.
func encodeNDJSONLimited(events []LogEntry, maxBytes int) ([]byte, int) {
	if maxBytes <= 0 {
		// no byte limit
		var sb strings.Builder
		included := 0
		for _, e := range events {
			if jsonData, err := json.Marshal(e); err == nil {
				sb.Write(jsonData)
				sb.WriteByte('\n')
				included++
			}
		}
		return []byte(sb.String()), included
	}

	// We prefer most recent events, but must preserve order.
	// Walk from the end backward to select as many as fit, then encode forward.
	// Estimate by encoding until budget exceeded.
	// To avoid double-encoding, collect indices then encode once.
	// Worst-case an event may exceed maxBytes; include none in that case.

	// First pass: find how many from the end fit within maxBytes.
	budget := maxBytes
	startIdx := len(events) // exclusive
	for i := len(events) - 1; i >= 0; i-- {
		jsonData, err := json.Marshal(events[i])
		if err != nil {
			continue
		}
		cost := len(jsonData) + 1 // include newline
		if cost > budget {
			break
		}
		budget -= cost
		startIdx = i
	}

	if startIdx == len(events) {
		// nothing fit within budget
		return []byte{}, 0
	}

	// Second pass: encode from startIdx to end to preserve chronological order.
	var sb strings.Builder
	included := 0
	for i := startIdx; i < len(events); i++ {
		if jsonData, err := json.Marshal(events[i]); err == nil {
			sb.Write(jsonData)
			sb.WriteByte('\n')
			included++
		}
	}
	return []byte(sb.String()), included
}

// GetCount returns the current number of events in the buffer
func (rb *EventRingBuffer) GetCount() int {
	rb.mutex.RLock()
	defer rb.mutex.RUnlock()
	return rb.count
}

// WebSocketHub manages websocket client connections and broadcasts
type WebSocketHub struct {
	clients     map[string]*client
	broadcast   chan []byte
	register    chan *client
	unregister  chan *client
	unicast     chan clientSend
	incoming    chan ClientMessage
	mutex       sync.RWMutex
	logger      *lsm.SharedLogger
	eventBuffer *EventRingBuffer
	instanceID  string
	seq         uint64
	startTime   time.Time
	// limits for the initial bulk send on new connections
	bulkMaxEvents int
	bulkMaxBytes  int
}

const writeDeadline = 5 * time.Second
const heartbeatInterval = 10 * time.Second
const pongWait = 60 * time.Second
const pingInterval = 30 * time.Second

var upgrader = gws.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type client struct {
	id      string
	conn    *gws.Conn
	send    chan []byte
	hub     *WebSocketHub
	closed  chan struct{}
	closeMu sync.Mutex
}

type clientSend struct {
	clientID string
	payload  []byte
}

// ClientMessage represents an inbound message from a websocket client.
type ClientMessage struct {
	ClientID string
	Payload  []byte
}

// NewWebSocketHub creates a new WebSocket hub
func NewWebSocketHub(logger *lsm.SharedLogger, bufferSize int, bulkMaxEvents int, bulkMaxBytes int) *WebSocketHub {
	hub := &WebSocketHub{
		clients:       make(map[string]*client),
		broadcast:     make(chan []byte, 256),
		register:      make(chan *client),
		unregister:    make(chan *client),
		unicast:       make(chan clientSend, 128),
		incoming:      make(chan ClientMessage, 256),
		logger:        logger,
		eventBuffer:   NewEventRingBuffer(bufferSize),
		instanceID:    uuid.NewString(),
		startTime:     time.Now(),
		bulkMaxEvents: bulkMaxEvents,
		bulkMaxBytes:  bulkMaxBytes,
	}

	hub.emitHello()

	return hub
}

// Run starts the hub's main loop
func (h *WebSocketHub) Run() {
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client.id] = client
			h.mutex.Unlock()
			log.Printf("WebSocket client connected. Total clients: %d", len(h.clients))

		case client := <-h.unregister:
			h.removeClient(client.id)

		case message := <-h.broadcast:
			for _, client := range h.snapshotClients() {
				h.enqueue(client, message)
			}

		case msg := <-h.unicast:
			if c := h.getClient(msg.clientID); c != nil {
				h.enqueue(c, msg.payload)
			}

		case <-heartbeatTicker.C:
			h.emitHeartbeat()
		}
	}
}

func (h *WebSocketHub) snapshotClients() []*client {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	clients := make([]*client, 0, len(h.clients))
	for _, client := range h.clients {
		clients = append(clients, client)
	}
	return clients
}

func (h *WebSocketHub) getClient(id string) *client {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.clients[id]
}

func (h *WebSocketHub) enqueue(client *client, payload []byte) {
	select {
	case client.send <- payload:
	default:
		log.Printf("websocket: dropping message for client %s (send buffer full)", client.id)
	}
}

func (h *WebSocketHub) removeClient(id string) {
	h.mutex.Lock()
	client, ok := h.clients[id]
	if ok {
		delete(h.clients, id)
	}
	h.mutex.Unlock()

	if ok && client != nil {
		client.close()
	}
	log.Printf("WebSocket client disconnected. Total clients: %d", len(h.clients))
}

// getHistoricalEvents returns all buffered events formatted as NDJSON
func (h *WebSocketHub) getHistoricalEvents() ([]byte, int) {
	// If limits are not set or invalid, fall back to full buffer
	if h.bulkMaxEvents <= 0 && h.bulkMaxBytes <= 0 {
		data := h.eventBuffer.GetBulkNDJSON()
		return data, h.eventBuffer.GetCount()
	}

	// Derive a sensible event limit
	maxEvents := h.bulkMaxEvents
	if maxEvents <= 0 {
		// if bytes limit only, start with full buffer and trim by bytes
		maxEvents = h.eventBuffer.GetCount()
	}
	events := h.eventBuffer.GetTail(maxEvents)

	// Encode with byte bound if set
	if h.bulkMaxBytes > 0 {
		return encodeNDJSONLimited(events, h.bulkMaxBytes)
	}
	// No byte bound, just encode all selected events
	var sb strings.Builder
	included := 0
	for _, e := range events {
		if jsonData, err := json.Marshal(e); err == nil {
			sb.Write(jsonData)
			sb.WriteByte('\n')
			included++
		}
	}
	return []byte(sb.String()), included
}

// EmitJSON publishes a structured event with the provided payload to all clients.
func (h *WebSocketHub) EmitJSON(event string, payload any) {
	if strings.TrimSpace(event) == "" {
		return
	}

	var raw json.RawMessage
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			log.Printf("failed to marshal websocket payload for %s: %v", event, err)
			return
		}
		raw = data
	}

	entry := LogEntry{
		Event:   event,
		Payload: raw,
	}
	h.emit(entry)
}

// Incoming returns a channel for consuming raw messages from clients.
func (h *WebSocketHub) Incoming() <-chan ClientMessage {
	return h.incoming
}

// SendToClient queues a payload to a specific client by ID.
func (h *WebSocketHub) SendToClient(clientID string, payload []byte) error {
	if clientID == "" {
		return fmt.Errorf("client id required")
	}
	if h.getClient(clientID) == nil {
		return fmt.Errorf("client %s not found", clientID)
	}
	h.unicast <- clientSend{
		clientID: clientID,
		payload:  payload,
	}
	return nil
}

// SendJSONToClient marshals the value and sends it to the client.
func (h *WebSocketHub) SendJSONToClient(clientID string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return h.SendToClient(clientID, data)
}

// BroadcastLog sends a log entry to all connected clients
func (h *WebSocketHub) BroadcastLog(logfmtEntry string) {
	logEntry := parseLogfmtToJSON(logfmtEntry)
	h.emit(logEntry)
}

func (h *WebSocketHub) emit(entry LogEntry) {
	if entry.Time == "" {
		entry.Time = time.Now().Format(time.RFC3339)
	}
	entry.InstanceID = h.instanceID
	seq := atomic.AddUint64(&h.seq, 1)
	entry.Seq = seq

	h.eventBuffer.Add(entry)

	if jsonData, err := json.Marshal(entry); err == nil {
		select {
		case h.broadcast <- jsonData:
		default:
			// Channel is full, drop the message
		}
	}
}

// RecentEvents returns the newest events from the ring buffer. When limit <= 0
// all buffered events are returned.
func (h *WebSocketHub) RecentEvents(limit int) []LogEntry {
	if limit <= 0 {
		return h.eventBuffer.GetAll()
	}
	return h.eventBuffer.GetTail(limit)
}

// SnapshotHints extracts recent hostnames and header names from the ring buffer.
func (h *WebSocketHub) SnapshotHints(limit int) (hosts []string, headers []string) {
	if h == nil || h.eventBuffer == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 512
	}
	events := h.eventBuffer.GetTail(limit)

	hostSeen := make(map[string]struct{})
	headerSeen := make(map[string]struct{})
	const hintCap = 16

	for i := len(events) - 1; i >= 0; i-- {
		entry := events[i]
		candidates := []string{
			entry.Hostname,
			entry.HostnameObserved,
			entry.HostnameResolved,
			entry.Domain,
		}
		if entry.Addr != "" && strings.Contains(entry.Addr, ":") {
			candidates = append(candidates, entry.Addr)
		}
		for _, value := range candidates {
			if len(hosts) >= hintCap {
				break
			}
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if _, ok := hostSeen[key]; ok {
				continue
			}
			hostSeen[key] = struct{}{}
			hosts = append(hosts, value)
		}

		if entry.Header != "" && len(headers) < hintCap {
			value := strings.TrimSpace(entry.Header)
			if value != "" {
				key := strings.ToLower(value)
				if _, ok := headerSeen[key]; !ok {
					headerSeen[key] = struct{}{}
					headers = append(headers, value)
				}
			}
		}
	}
	return hosts, headers
}

func (h *WebSocketHub) emitHello() {
	entry := LogEntry{
		Time:      time.Now().Format(time.RFC3339),
		Event:     "leash.hello",
		StartedAt: h.startTime.Format(time.RFC3339),
	}
	h.emit(entry)
}

func (h *WebSocketHub) emitHeartbeat() {
	last := atomic.LoadUint64(&h.seq)
	lastSeq := last
	uptime := int64(time.Since(h.startTime).Seconds())
	entry := LogEntry{
		Time:      time.Now().Format(time.RFC3339),
		Event:     "leash.heartbeat",
		UptimeSec: &uptime,
		LastSeq:   &lastSeq,
	}
	h.emit(entry)
}

// HandleWebSocket handles websocket connections
func (h *WebSocketHub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// Always send bulk message first (per protocol specification)
	// This ensures consistent behavior whether there are historical events or not
	bulkEvents, included := h.getHistoricalEvents()

	if err := conn.WriteMessage(gws.TextMessage, bulkEvents); err != nil {
		log.Printf("Failed to send bulk message to client: %v", err)
		conn.Close()
		return
	}

	log.Printf("Sent bulk message with %d historical events (%d bytes) to new WebSocket client", included, len(bulkEvents))

	c := newClient(h, conn)
	h.register <- c

	// Keep connection alive and handle disconnections
	go c.writePump()
	go c.readPump()
}

func newClient(h *WebSocketHub, conn *gws.Conn) *client {
	c := &client{
		id:     uuid.NewString(),
		conn:   conn,
		send:   make(chan []byte, 256),
		hub:    h,
		closed: make(chan struct{}),
	}
	return c
}

func (c *client) readPump() {
	defer func() {
		c.hub.unregister <- c
	}()

	c.conn.SetReadLimit(1 << 20) // 1 MiB
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		msgType, payload, err := c.conn.ReadMessage()
		if err != nil {
			if gws.IsUnexpectedCloseError(err, gws.CloseGoingAway, gws.CloseAbnormalClosure) {
				log.Printf("websocket read error (client %s): %v", c.id, err)
			}
			break
		}

		if msgType != gws.TextMessage {
			continue
		}

		select {
		case c.hub.incoming <- ClientMessage{ClientID: c.id, Payload: payload}:
		default:
			log.Printf("websocket: dropping inbound message for hub (client %s), channel full", c.id)
		}
	}
}

func (c *client) writePump() {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		c.close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
			if !ok {
				// Hub closed the channel
				_ = c.conn.WriteMessage(gws.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(gws.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
			if err := c.conn.WriteMessage(gws.PingMessage, nil); err != nil {
				return
			}

		case <-c.closed:
			return
		}
	}
}

func (c *client) close() {
	c.closeMu.Lock()
	select {
	case <-c.closed:
		// already closed
	default:
		close(c.closed)
		close(c.send)
		_ = c.conn.Close()
	}
	c.closeMu.Unlock()
}

// parseLogfmtToJSON converts a logfmt string to a LogEntry struct
func parseLogfmtToJSON(logfmt string) LogEntry {
	entry := LogEntry{}

	// Regular expression to match key=value pairs, handling quoted values
	re := regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)`)
	matches := re.FindAllStringSubmatch(logfmt, -1)

	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		key := match[1]
		value := match[2]

		// Remove quotes if present
		if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = strings.Trim(value, `"`)
			// Unescape escaped quotes
			value = strings.ReplaceAll(value, `\"`, `"`)
		}

		switch key {
		case "time":
			entry.Time = value
		case "event":
			entry.Event = value
		case "pid":
			if pid, err := strconv.Atoi(value); err == nil {
				entry.PID = &pid
			}
		case "cgroup":
			if cgroup, err := strconv.Atoi(value); err == nil {
				entry.Cgroup = &cgroup
			}
		case "exe":
			entry.Exe = value
		case "path":
			entry.Path = value
		case "decision":
			entry.Decision = value
		case "protocol":
			entry.Protocol = value
		case "addr":
			entry.Addr = value
		case "addr_ip":
			entry.AddrIP = value
		case "port":
			entry.Port = value
		case "status":
			if status, err := strconv.Atoi(value); err == nil {
				entry.Status = &status
			}
		case "error":
			entry.Error = value
		case "reason":
			entry.Reason = value
		case "args":
			entry.Args = value
		case "argc":
			if argc, err := strconv.Atoi(value); err == nil {
				entry.Argc = &argc
			}
		case "hostname":
			entry.Hostname = value
		case "hostname_resolved":
			entry.HostnameResolved = value
		case "hostname_observed":
			entry.HostnameObserved = value
		case "hostname_kind":
			entry.HostnameKind = value
		case "domain":
			entry.Domain = value
		case "family":
			entry.Family = value
		case "header":
			entry.Header = value
		case "old_value":
			entry.OldValue = value
		case "from":
			// Alias used by alternate HTTP rewrite emitters
			entry.OldValue = value
		case "new_value":
			entry.NewValue = value
		case "to":
			// Alias used by alternate HTTP rewrite emitters
			entry.NewValue = value
		case "auth":
			entry.Auth = value
		case "rule":
			entry.Rule = value
		case "method":
			entry.Method = value
		case "server":
			entry.Server = value
		case "tool":
			entry.Tool = value
		}
	}

	return entry
}
