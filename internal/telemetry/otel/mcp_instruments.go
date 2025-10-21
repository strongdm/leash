package otel

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// MCPInstruments publishes metrics and traces for MCP traffic.
type MCPInstruments struct {
	meterEnabled  bool
	traceEnabled  bool
	propagateHTTP bool

	counterRequests metric.Int64Counter
	counterErrors   metric.Int64Counter
	histDuration    metric.Int64Histogram

	tracer trace.Tracer
}

type RequestHandle struct {
	ctx     context.Context
	span    trace.Span
	start   time.Time
	attrs   []attribute.KeyValue
	outcome string
}

type MCPRequestInfo struct {
	Server    string
	Method    string
	Tool      string
	Transport string
	Proto     string
}

// HeaderCarrier adapts http.Header to OTEL propagation carrier.
type HeaderCarrier http.Header

// Get returns the first value associated with the given key.
func (hc HeaderCarrier) Get(key string) string {
	return http.Header(hc).Get(key)
}

// Set sets the header entries associated with key to the single element value.
func (hc HeaderCarrier) Set(key, value string) {
	http.Header(hc).Set(key, value)
}

// Keys returns all keys in the carrier.
func (hc HeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(hc))
	for k := range hc {
		keys = append(keys, k)
	}
	return keys
}

// Values provides the values associated with a key.
func (hc HeaderCarrier) Values(key string) []string {
	return http.Header(hc).Values(key)
}

func newMCPInstruments(p *Provider, propagate bool) *MCPInstruments {
	if p == nil {
		return nil
	}

	inst := &MCPInstruments{
		meterEnabled:  p.meterProvider != nil,
		traceEnabled:  p.tracerProvider != nil,
		propagateHTTP: propagate,
	}
	if p.meterProvider != nil {
		inst.counterRequests, _ = p.meter.Int64Counter(
			"mcp.requests_total",
			metric.WithDescription("Number of MCP requests processed by the proxy"),
		)
		inst.counterErrors, _ = p.meter.Int64Counter(
			"mcp.errors_total",
			metric.WithDescription("Number of MCP requests that ended in error"),
		)
		inst.histDuration, _ = p.meter.Int64Histogram(
			"mcp.request.duration",
			metric.WithDescription("Duration of MCP requests in milliseconds"),
		)
	}
	if p.tracerProvider != nil {
		inst.tracer = p.tracer
	}
	return inst
}

// Start returns a request handle and context including the active span when tracing is enabled.
func (i *MCPInstruments) Start(parent context.Context, info MCPRequestInfo) (*RequestHandle, context.Context) {
	if i == nil {
		return nil, parent
	}

	h := &RequestHandle{
		ctx:   parent,
		start: time.Now(),
		attrs: buildAttributes(info),
	}

	if i.traceEnabled && i.tracer != nil {
		spanName := spanNameFor(info.Method, info.Tool)
		ctx, span := i.tracer.Start(parent, spanName, trace.WithAttributes(h.attrs...))
		h.ctx = ctx
		h.span = span
	}
	return h, h.ctx
}

// InjectHTTP injects trace propagation headers into the provided HTTP headers.
func (i *MCPInstruments) InjectHTTP(ctx context.Context, hdr HeaderCarrier) {
	if i == nil || !i.traceEnabled || !i.propagateHTTP {
		return
	}
	i.injectTrace(ctx, hdr)
}

func (i *MCPInstruments) injectTrace(ctx context.Context, carrier propagation.TextMapCarrier) {
	if i == nil || !i.traceEnabled || !i.propagateHTTP {
		return
	}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
}

// Finish records metrics and updates the span with outcome information.
func (i *MCPInstruments) Finish(h *RequestHandle, status int, outcome string, transport, proto, session string, errText string) {
	if i == nil || h == nil {
		return
	}
	elapsed := time.Since(h.start)
	attrs := append([]attribute.KeyValue{}, h.attrs...)
	if transport != "" {
		attrs = append(attrs, attribute.String("transport", transport))
	}
	if proto != "" {
		attrs = append(attrs, attribute.String("proto", proto))
	}
	if session != "" {
		attrs = append(attrs, attribute.String("mcp.session", session))
	}
	if status > 0 {
		attrs = append(attrs, attribute.Int("http.status_code", status))
	}
	if outcome != "" {
		attrs = append(attrs, attribute.String("outcome", outcome))
	}
	if errText != "" {
		attrs = append(attrs, attribute.String("error.message", errText))
	}

	if i.meterEnabled {
		i.counterRequests.Add(h.ctx, 1, metric.WithAttributes(attrs...))
		if strings.EqualFold(outcome, "error") {
			i.counterErrors.Add(h.ctx, 1, metric.WithAttributes(attrs...))
		}
		i.histDuration.Record(h.ctx, elapsed.Milliseconds(), metric.WithAttributes(attrs...))
	}

	if h.span != nil {
		h.span.SetAttributes(attrs...)
		if strings.EqualFold(outcome, "error") {
			h.span.SetStatus(codes.Error, errText)
		}
		h.span.End()
	}
}

func buildAttributes(info MCPRequestInfo) []attribute.KeyValue {
	attrs := []attribute.KeyValue{}
	if info.Server != "" {
		attrs = append(attrs, attribute.String("mcp.server", info.Server))
	}
	if info.Method != "" {
		attrs = append(attrs, attribute.String("mcp.method", info.Method))
	}
	if info.Tool != "" {
		attrs = append(attrs, attribute.String("mcp.tool", info.Tool))
	}
	return attrs
}

func spanNameFor(method, tool string) string {
	method = strings.TrimSpace(method)
	if method == "" {
		return "mcp.request"
	}
	switch method {
	case "tools/call":
		if tool != "" {
			return fmt.Sprintf("mcp.%s:%s", method, tool)
		}
		return "mcp.tools/call"
	default:
		return "mcp." + method
	}
}
