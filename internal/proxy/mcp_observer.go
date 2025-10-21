package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/telemetry/otel"
)

const (
	defaultMCPSniffLimit = int64(1 * 1024 * 1024) // 1MB
	defaultSSEEventLimit = 10
)

// MCPMode controls whether MCP observability is active and which attributes are logged.
type MCPMode int

const (
	MCPModeOff MCPMode = iota
	MCPModeBasic
	MCPModeEnhanced
)

// MCPConfig contains runtime configuration for MCP observability.
type MCPConfig struct {
	Mode          MCPMode
	SniffLimit    int64
	SSEEventLimit int
	Telemetry     *otel.MCPInstruments
}

// mcpObserver coordinates request/response sniffing with sampling and logging.
type mcpObserver struct {
	cfg       MCPConfig
	logger    *lsm.SharedLogger
	telemetry *otel.MCPInstruments

	sessionMu  sync.RWMutex
	sessions   map[string]*sessionInfo
	forceParse bool
}

type mcpRequestContext struct {
	event           string
	method          string
	server          string
	tool            string
	id              string
	notification    bool
	proto           string
	transport       string
	streamOutcome   string
	streamError     string
	responseOutcome string
	responseError   string
	telemetryHandle *otel.RequestHandle
	session         string

	started time.Time
	sampled bool
}

type sessionInfo struct {
	server    string
	proto     string
	truncated string
}

const maxTrackedSessions = 64

func newMCPObserver(cfg MCPConfig, logger *lsm.SharedLogger) *mcpObserver {
	if cfg.SniffLimit <= 0 {
		cfg.SniffLimit = defaultMCPSniffLimit
	}
	if cfg.SSEEventLimit <= 0 {
		cfg.SSEEventLimit = defaultSSEEventLimit
	}
	return &mcpObserver{
		cfg:       cfg,
		logger:    logger,
		telemetry: cfg.Telemetry,
		sessions:  make(map[string]*sessionInfo),
	}
}

func (o *mcpObserver) setForceParse(enabled bool) {
	if o == nil {
		return
	}
	o.forceParse = enabled
}

func (o *mcpObserver) inspectHTTPRequest(req *http.Request, server string) (*mcpRequestContext, error) {
	if o == nil || req == nil {
		return nil, nil
	}
	disabled := o.cfg.Mode == MCPModeOff

	if !isJSONContent(req.Header.Get("Content-Type")) {
		return nil, nil
	}

	bodyCopy, restoredBody, truncated, err := readBodyWithLimit(req.Body, o.cfg.SniffLimit)
	if err != nil {
		return nil, fmt.Errorf("mcp sniff body: %w", err)
	}
	req.Body = restoredBody
	if truncated {
		return nil, nil
	}

	envelope, err := decodeJSONRPCEnvelope(bodyCopy)
	if err != nil {
		return nil, nil
	}

	eventName, ok := methodToEvent(envelope.Method)
	if !ok {
		return nil, nil
	}

	ctx := &mcpRequestContext{
		event:     eventName,
		method:    envelope.Method,
		server:    server,
		id:        envelope.ID,
		proto:     strings.TrimSpace(req.Header.Get("MCP-Protocol-Version")),
		started:   time.Now(),
		transport: "json",
	}

	if isNotification(envelope) {
		ctx.notification = true
	}
	if envelope.Method == "tools/call" {
		ctx.tool = envelope.ToolName
	}

	ctx.sampled = true

	if disabled {
		return ctx, nil
	}

	if o.telemetry != nil {
		info := otel.MCPRequestInfo{
			Server:    ctx.server,
			Method:    ctx.method,
			Tool:      ctx.tool,
			Transport: ctx.transport,
			Proto:     ctx.proto,
		}
		handle, otelCtx := o.telemetry.Start(req.Context(), info)
		ctx.telemetryHandle = handle
		if otelCtx != nil && otelCtx != req.Context() {
			clone := req.Clone(otelCtx)
			clone.Body = req.Body
			clone.GetBody = req.GetBody
			*req = *clone
		}
		if otelCtx == nil {
			otelCtx = req.Context()
		}
		o.telemetry.InjectHTTP(otelCtx, otel.HeaderCarrier(req.Header))
	}

	return ctx, nil
}

func (o *mcpObserver) inspectHTTPResponse(ctx *mcpRequestContext, resp *http.Response) {
	if o == nil || ctx == nil || resp == nil {
		return
	}
	if !isJSONContent(resp.Header.Get("Content-Type")) {
		return
	}

	bodyCopy, restoredBody, truncated, err := readBodyWithLimit(resp.Body, o.cfg.SniffLimit)
	if err != nil {
		resp.Body = restoredBody
		return
	}
	resp.Body = restoredBody
	if truncated {
		return
	}

	outcome, errText := evaluateJSONRPCResponse(bodyCopy)
	if outcome != "" {
		ctx.responseOutcome = outcome
	}
	if errText != "" {
		ctx.responseError = errText
	}
}

func (o *mcpObserver) logHTTPRequest(ctx *mcpRequestContext, status int, outcome string, session string, decision string, err error) {
	if o == nil || ctx == nil || o.logger == nil {
		return
	}

	transport := ctx.transport
	if transport == "" {
		transport = "json"
	}
	duration := time.Since(ctx.started)
	ms := int(math.Round(duration.Seconds() * 1000))

	finalOutcome := outcome
	if ctx.responseOutcome != "" {
		finalOutcome = ctx.responseOutcome
	}
	if ctx.streamOutcome != "" {
		finalOutcome = ctx.streamOutcome
	}
	if finalOutcome == "" {
		finalOutcome = "success"
	}

	errorField := ""
	if err != nil {
		errorField = shortError(err)
	} else if ctx.streamError != "" {
		errorField = ctx.streamError
	} else if ctx.responseError != "" {
		errorField = ctx.responseError
	}

	if ctx.notification {
		status = 202
	}

	if decision == "" {
		if finalOutcome == "error" {
			decision = "denied"
		} else {
			decision = "allowed"
		}
	}

	truncatedSession := ""
	if session != "" {
		truncatedSession = truncateSession(session)
		if ctx.session == "" {
			ctx.session = truncatedSession
		}
	}

	if o.telemetry != nil && ctx.telemetryHandle != nil {
		o.telemetry.Finish(ctx.telemetryHandle, status, finalOutcome, transport, ctx.proto, truncatedSession, errorField)
	}

	var sb strings.Builder
	sb.WriteString("event=")
	sb.WriteString(ctx.event)
	sb.WriteString(` server="`)
	sb.WriteString(escapeQuotes(ctx.server))
	sb.WriteString(`" method="`)
	sb.WriteString(escapeQuotes(ctx.method))
	sb.WriteString(`"`)

	if ctx.tool != "" {
		sb.WriteString(` tool="`)
		sb.WriteString(escapeQuotes(ctx.tool))
		sb.WriteString(`"`)
	}

	if ctx.id != "" && o.cfg.Mode != MCPModeOff {
		sb.WriteString(` id="`)
		sb.WriteString(escapeQuotes(ctx.id))
		sb.WriteString(`"`)
	}

	if ctx.notification {
		sb.WriteString(" notification=true")
	}

	if status > 0 {
		sb.WriteString(fmt.Sprintf(" status=%d", status))
	}

	sb.WriteString(" outcome=")
	sb.WriteString(finalOutcome)
	sb.WriteString(" decision=")
	sb.WriteString(decision)
	sb.WriteString(fmt.Sprintf(" duration_ms=%d", ms))

	if o.cfg.Mode == MCPModeEnhanced {
		sb.WriteString(` transport="`)
		sb.WriteString(escapeQuotes(transport))
		sb.WriteString(`"`)
		if ctx.proto != "" {
			sb.WriteString(` proto="`)
			sb.WriteString(escapeQuotes(ctx.proto))
			sb.WriteString(`"`)
		}
		if truncatedSession != "" {
			sb.WriteString(` session="`)
			sb.WriteString(escapeQuotes(truncatedSession))
			sb.WriteString(`"`)
		}
	}

	if errorField != "" {
		sb.WriteString(` error="`)
		sb.WriteString(escapeQuotes(errorField))
		sb.WriteString(`"`)
	}

	_ = o.logger.Write(sb.String())
}

func (o *mcpObserver) logNotification(ctx *mcpRequestContext, method string) {
	if o == nil || ctx == nil || o.logger == nil {
		return
	}
	var sb strings.Builder
	sb.WriteString("event=mcp.notification")
	sb.WriteString(` server="`)
	sb.WriteString(escapeQuotes(ctx.server))
	sb.WriteString(`" method="`)
	sb.WriteString(escapeQuotes(method))
	sb.WriteString(`" status=200 outcome=success decision=allowed duration_ms=0`)
	if o.cfg.Mode == MCPModeEnhanced {
		sb.WriteString(` transport="sse"`)
		if ctx.proto != "" {
			sb.WriteString(` proto="`)
			sb.WriteString(escapeQuotes(ctx.proto))
			sb.WriteString(`"`)
		}
		if ctx.session != "" {
			sb.WriteString(` session="`)
			sb.WriteString(escapeQuotes(ctx.session))
			sb.WriteString(`"`)
		}
	}
	_ = o.logger.Write(sb.String())
}

func (o *mcpObserver) wrapSSEBody(ctx *mcpRequestContext, body io.ReadCloser) io.ReadCloser {
	if o == nil || ctx == nil || body == nil {
		return body
	}
	ctx.transport = "sse"
	limit := o.cfg.SniffLimit
	if limit <= 0 {
		limit = defaultMCPSniffLimit
	}
	return &sseSniffer{
		observer:     o,
		ctx:          ctx,
		underlying:   body,
		limit:        limit,
		eventLimit:   o.cfg.SSEEventLimit,
		eventsLogged: 0,
	}
}

type sseSniffer struct {
	observer     *mcpObserver
	ctx          *mcpRequestContext
	underlying   io.ReadCloser
	limit        int64
	consumed     int64
	buffer       bytes.Buffer
	eventLimit   int
	eventsLogged int
}

func (s *sseSniffer) Read(p []byte) (int, error) {
	n, err := s.underlying.Read(p)
	if n > 0 && s.limit > 0 && s.ctx != nil && s.withinEventBudget() {
		remaining := s.limit - s.consumed
		if remaining > 0 {
			capture := n
			if int64(capture) > remaining {
				capture = int(remaining)
			}
			chunk := make([]byte, capture)
			copy(chunk, p[:capture])
			chunk = bytes.ReplaceAll(chunk, []byte("\r\n"), []byte("\n"))
			s.buffer.Write(chunk)
			s.consumed += int64(capture)
			s.processBuffer()
		}
	}
	if err == io.EOF {
		s.finish()
	}
	return n, err
}

func (s *sseSniffer) Close() error {
	return s.underlying.Close()
}

func (s *sseSniffer) finish() {}

func (s *sseSniffer) withinEventBudget() bool {
	if s.eventLimit <= 0 {
		return true
	}
	return s.eventsLogged < s.eventLimit
}

func (s *sseSniffer) processBuffer() {
	for {
		if !s.withinEventBudget() {
			return
		}
		data := s.buffer.Bytes()
		idx := bytes.Index(data, []byte("\n\n"))
		if idx == -1 {
			return
		}
		message := make([]byte, idx)
		copy(message, data[:idx])
		s.buffer.Next(idx + 2)
		s.handleMessage(message)
	}
}

func (s *sseSniffer) handleMessage(msg []byte) {
	if !s.withinEventBudget() {
		return
	}
	lines := bytes.Split(msg, []byte("\n"))
	var dataBuilder strings.Builder
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		if bytes.HasPrefix(trimmed, []byte("data:")) {
			payload := bytes.TrimSpace(trimmed[len("data:"):])
			if dataBuilder.Len() > 0 {
				dataBuilder.WriteByte('\n')
			}
			dataBuilder.Write(payload)
		}
	}
	if dataBuilder.Len() == 0 {
		return
	}
	s.eventsLogged++
	s.processPayload(dataBuilder.String())
}

func (s *sseSniffer) processPayload(raw string) {
	if s.observer == nil || s.ctx == nil {
		return
	}

	env, err := decodeJSONRPCEnvelope([]byte(raw))
	if err != nil {
		return
	}

	if strings.HasPrefix(env.Method, "notifications/") {
		s.observer.logNotification(s.ctx, env.Method)
		return
	}

	if env.Method != "" {
		s.observer.logStreamRequest(s.ctx, env)
		return
	}

	if env.ID == "" {
		return
	}

	outcome, errText := evaluateJSONRPCResponse([]byte(raw))
	if s.ctx.id != "" && env.ID == s.ctx.id {
		if outcome != "" {
			s.ctx.streamOutcome = outcome
		}
		if errText != "" {
			s.ctx.streamError = errText
		}
		return
	}
	if outcome == "" {
		outcome = "success"
	}
	s.observer.logStreamResponse(s.ctx, env.ID, outcome, errText)
}

func readBodyWithLimit(body io.ReadCloser, limit int64) ([]byte, io.ReadCloser, bool, error) {
	if body == nil {
		return nil, io.NopCloser(bytes.NewReader(nil)), false, nil
	}

	if limit <= 0 {
		limit = defaultMCPSniffLimit
	}

	limited := io.LimitReader(body, limit+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, body, false, err
	}

	truncate := int64(len(buf)) > limit
	parseSlice := buf
	if truncate {
		parseSlice = buf[:limit]
	}

	reader := io.MultiReader(bytes.NewReader(buf), body)
	return parseSlice, &replaceBodyReader{Reader: reader, Closer: body}, truncate, nil
}

type replaceBodyReader struct {
	io.Reader
	Closer io.Closer
}

func (r *replaceBodyReader) Close() error {
	if r.Closer != nil {
		return r.Closer.Close()
	}
	return nil
}

func isJSONContent(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/json-rpc")
}

type jsonrpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	RawID   json.RawMessage `json:"id"`
	Params  json.RawMessage `json:"params"`
}

type jsonrpcCallParams struct {
	Name string `json:"name"`
}

type parsedEnvelope struct {
	JSONRPC  string
	Method   string
	ID       string
	ToolName string
}

func decodeJSONRPCEnvelope(raw []byte) (*parsedEnvelope, error) {
	var env jsonrpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if strings.TrimSpace(env.JSONRPC) != "2.0" {
		return nil, fmt.Errorf("not jsonrpc2")
	}
	out := &parsedEnvelope{
		JSONRPC: env.JSONRPC,
		Method:  strings.TrimSpace(env.Method),
	}
	if len(env.RawID) > 0 && string(env.RawID) != "null" {
		out.ID = normalizeID(env.RawID)
	}
	if out.Method == "tools/call" && len(env.Params) > 0 {
		var params jsonrpcCallParams
		if err := json.Unmarshal(env.Params, &params); err == nil {
			out.ToolName = strings.TrimSpace(params.Name)
		}
	}
	return out, nil
}

func normalizeID(raw json.RawMessage) string {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString
	}
	var asNumber json.Number
	if err := json.Unmarshal(raw, &asNumber); err == nil {
		return asNumber.String()
	}
	return string(bytes.TrimSpace(raw))
}

func methodToEvent(method string) (string, bool) {
	switch method {
	case "tools/list":
		return "mcp.discover", true
	case "tools/call":
		return "mcp.call", true
	case "resources/list":
		return "mcp.resources.list", true
	case "resources/read":
		return "mcp.resources.read", true
	case "prompts/list":
		return "mcp.prompts.list", true
	case "prompts/get":
		return "mcp.prompts.get", true
	case "initialize":
		return "mcp.initialize", true
	case "initialized":
		return "mcp.initialized", true
	default:
		return "", false
	}
}

func isNotification(env *parsedEnvelope) bool {
	if env == nil {
		return false
	}
	if env.Method == "initialized" {
		return true
	}
	return strings.TrimSpace(env.ID) == ""
}

func truncateSession(session string) string {
	session = strings.TrimSpace(session)
	if len(session) <= 8 {
		return session
	}
	return session[:8]
}

func shortError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 96 {
		msg = msg[:96]
	}
	return msg
}

func escapeQuotes(s string) string {
	return strings.ReplaceAll(s, `"`, `'`)
}

func truncateString(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func (o *mcpObserver) registerSession(session string, ctx *mcpRequestContext) {
	if o == nil || ctx == nil {
		return
	}
	session = strings.TrimSpace(session)
	if session == "" {
		return
	}

	truncated := truncateSession(session)
	ctx.session = truncated

	o.sessionMu.Lock()
	defer o.sessionMu.Unlock()

	if len(o.sessions) >= maxTrackedSessions {
		for key := range o.sessions {
			delete(o.sessions, key)
			break
		}
	}

	o.sessions[session] = &sessionInfo{
		server:    ctx.server,
		proto:     ctx.proto,
		truncated: truncated,
	}
}

func (o *mcpObserver) sessionContext(session string, fallbackServer string, fallbackProto string) *mcpRequestContext {
	if o == nil {
		return nil
	}
	session = strings.TrimSpace(session)
	if session == "" {
		return nil
	}

	o.sessionMu.RLock()
	info, ok := o.sessions[session]
	o.sessionMu.RUnlock()
	if !ok {
		return nil
	}

	server := info.server
	if server == "" {
		server = fallbackServer
	}
	proto := info.proto
	if proto == "" {
		proto = fallbackProto
	}

	return &mcpRequestContext{
		event:   "mcp.stream",
		server:  server,
		proto:   proto,
		session: info.truncated,
		started: time.Now(),
		sampled: true,
	}
}

func (o *mcpObserver) wrapSessionSSE(session string, server string, proto string, body io.ReadCloser) io.ReadCloser {
	if o == nil || body == nil {
		return body
	}
	ctx := o.sessionContext(session, server, proto)
	if ctx == nil {
		return body
	}
	return o.wrapSSEBody(ctx, body)
}

func (o *mcpObserver) logStreamRequest(ctx *mcpRequestContext, env *parsedEnvelope) {
	if o == nil || ctx == nil || env == nil || o.logger == nil {
		return
	}

	eventName, ok := methodToEvent(env.Method)
	if !ok || eventName == "" {
		eventName = "mcp.stream"
	}

	var sb strings.Builder
	sb.WriteString("event=")
	sb.WriteString(eventName)
	sb.WriteString(` server="`)
	sb.WriteString(escapeQuotes(ctx.server))
	sb.WriteString(`" method="`)
	sb.WriteString(escapeQuotes(env.Method))
	sb.WriteString(`" status=200 outcome=pending decision=allowed duration_ms=0`)

	if env.ToolName != "" {
		sb.WriteString(` tool="`)
		sb.WriteString(escapeQuotes(env.ToolName))
		sb.WriteString(`"`)
	}

	if env.ID != "" {
		sb.WriteString(` id="`)
		sb.WriteString(escapeQuotes(env.ID))
		sb.WriteString(`"`)
	}

	if o.cfg.Mode == MCPModeEnhanced {
		sb.WriteString(` transport="sse"`)
		if ctx.proto != "" {
			sb.WriteString(` proto="`)
			sb.WriteString(escapeQuotes(ctx.proto))
			sb.WriteString(`"`)
		}
		if ctx.session != "" {
			sb.WriteString(` session="`)
			sb.WriteString(escapeQuotes(ctx.session))
			sb.WriteString(`"`)
		}
	}

	_ = o.logger.Write(sb.String())
}

func (o *mcpObserver) logStreamResponse(ctx *mcpRequestContext, id string, outcome string, errText string) {
	if o == nil || ctx == nil || o.logger == nil {
		return
	}

	if outcome == "" {
		outcome = "success"
	}
	status := 200
	if outcome == "error" {
		status = 500
	}

	var sb strings.Builder
	sb.WriteString("event=mcp.stream")
	sb.WriteString(` server="`)
	sb.WriteString(escapeQuotes(ctx.server))
	sb.WriteString(`"`)
	if id != "" {
		sb.WriteString(` id="`)
		sb.WriteString(escapeQuotes(id))
		sb.WriteString(`"`)
	}
	sb.WriteString(fmt.Sprintf(" status=%d outcome=%s decision=allowed duration_ms=0", status, outcome))

	if o.cfg.Mode == MCPModeEnhanced {
		sb.WriteString(` transport="sse"`)
		if ctx.proto != "" {
			sb.WriteString(` proto="`)
			sb.WriteString(escapeQuotes(ctx.proto))
			sb.WriteString(`"`)
		}
		if ctx.session != "" {
			sb.WriteString(` session="`)
			sb.WriteString(escapeQuotes(ctx.session))
			sb.WriteString(`"`)
		}
	}

	if errText != "" {
		sb.WriteString(` error="`)
		sb.WriteString(escapeQuotes(errText))
		sb.WriteString(`"`)
	}

	_ = o.logger.Write(sb.String())
}

type jsonrpcResponseEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

type jsonrpcErrorEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type jsonrpcResultEnvelope struct {
	IsError  bool            `json:"isError"`
	Decision string          `json:"decision"`
	Error    json.RawMessage `json:"error"`
}

func evaluateJSONRPCResponse(raw []byte) (string, string) {
	var env jsonrpcResponseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", ""
	}
	if len(env.Error) > 0 && string(env.Error) != "null" {
		var e jsonrpcErrorEnvelope
		if err := json.Unmarshal(env.Error, &e); err == nil {
			message := strings.TrimSpace(e.Message)
			if message == "" && len(e.Data) > 0 {
				message = truncateString(string(e.Data), 96)
			}
			return "error", truncateString(message, 96)
		}
		return "error", truncateString(string(env.Error), 96)
	}

	if len(env.Result) > 0 && string(env.Result) != "null" {
		var r jsonrpcResultEnvelope
		if err := json.Unmarshal(env.Result, &r); err == nil {
			if r.IsError || strings.EqualFold(r.Decision, "deny") {
				msg := ""
				if len(r.Error) > 0 {
					msg = truncateString(string(r.Error), 96)
				}
				if msg == "" {
					msg = "denied"
				}
				return "error", msg
			}
		}
	}

	return "success", ""
}
