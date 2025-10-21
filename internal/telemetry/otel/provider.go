package otel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Config controls OTEL exporter behaviour.
type Config struct {
	ServiceName   string
	EnableMetrics bool
	EnableTraces  bool
	Endpoint      string
	Headers       map[string]string
	PropagateHTTP bool
}

// Provider owns OTEL meter/tracer providers and derived MCP instruments.
type Provider struct {
	cfg            Config
	meterProvider  *sdkmetric.MeterProvider
	tracerProvider *sdktrace.TracerProvider
	meter          metric.Meter
	tracer         trace.Tracer

	mcpInstruments *MCPInstruments
	shutdownOnce   sync.Once
}

// Setup initialises OTEL exporters (OTLP/HTTP) for metrics and traces following the provided config.
func Setup(ctx context.Context, cfg Config) (*Provider, error) {
	if !cfg.EnableMetrics && !cfg.EnableTraces {
		return &Provider{cfg: cfg}, nil
	}

	if strings.TrimSpace(cfg.ServiceName) == "" {
		cfg.ServiceName = "leash"
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			attribute.String("service.name", cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	p := &Provider{cfg: cfg}

	if cfg.EnableMetrics {
		mp, err := createMeterProvider(ctx, cfg, res)
		if err != nil {
			return nil, err
		}
		p.meterProvider = mp
		otel.SetMeterProvider(mp)
		p.meter = mp.Meter("github.com/strongdm/leash/mcp")
	}

	if cfg.EnableTraces {
		tp, err := createTracerProvider(ctx, cfg, res)
		if err != nil {
			return nil, err
		}
		p.tracerProvider = tp
		otel.SetTracerProvider(tp)
		p.tracer = tp.Tracer("github.com/strongdm/leash/mcp")
	}

	p.mcpInstruments = newMCPInstruments(p, cfg.PropagateHTTP)
	return p, nil
}

func createMeterProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdkmetric.MeterProvider, error) {
	if strings.TrimSpace(cfg.Endpoint) != "" {
		log.Printf("LEASH_OTEL_ENDPOINT=%s ignored: remote OTLP metric export not implemented", cfg.Endpoint)
	}

	reader := sdkmetric.NewManualReader()
	return sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(res),
	), nil
}

func createTracerProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdktrace.TracerProvider, error) {
	if strings.TrimSpace(cfg.Endpoint) != "" {
		log.Printf("LEASH_OTEL_ENDPOINT=%s ignored: OTLP trace export unsupported; using stdout exporter", cfg.Endpoint)
	}

	exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, fmt.Errorf("init stdout trace exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithMaxExportBatchSize(64)),
		sdktrace.WithResource(res),
	)
	return tp, nil
}

// Shutdown flushes and stops the configured providers.
func (p *Provider) Shutdown(ctx context.Context) error {
	var err error
	p.shutdownOnce.Do(func() {
		var errs []error
		if p.meterProvider != nil {
			if shutdownErr := p.meterProvider.Shutdown(ctx); shutdownErr != nil {
				errs = append(errs, shutdownErr)
			}
		}
		if p.tracerProvider != nil {
			if shutdownErr := p.tracerProvider.Shutdown(ctx); shutdownErr != nil {
				errs = append(errs, shutdownErr)
			}
		}
		if len(errs) > 0 {
			err = errors.Join(errs...)
		}
	})
	return err
}

// MCP returns MCP-specific instruments.
func (p *Provider) MCP() *MCPInstruments {
	if p == nil {
		return nil
	}
	return p.mcpInstruments
}

// ParseHeadersEnv converts LEASH_OTEL_HEADERS into a header map (comma/whitespace separated).
func ParseHeadersEnv(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	pairs := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})
	headers := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" && value != "" {
			headers[key] = value
		}
	}
	return headers
}

// MergeHeaders merges custom headers onto the request before exporting.
func MergeHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

// EnvBool interprets LEASH_* env toggles.
func EnvBool(value string, defaultOn bool) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "":
		return defaultOn
	case "1", "true", "on", "enable", "enabled", "yes":
		return true
	case "0", "false", "off", "disable", "disabled", "no":
		return false
	default:
		return defaultOn
	}
}

// LoadConfigFromEnv reads OTEL config from environment (used by runtime).
func LoadConfigFromEnv() Config {
	return Config{
		ServiceName:   "leash",
		EnableMetrics: EnvBool(os.Getenv("LEASH_OTEL_METRICS"), false),
		EnableTraces:  EnvBool(os.Getenv("LEASH_OTEL_TRACES"), false),
		Endpoint:      strings.TrimSpace(os.Getenv("LEASH_OTEL_ENDPOINT")),
		Headers:       ParseHeadersEnv(os.Getenv("LEASH_OTEL_HEADERS")),
		PropagateHTTP: EnvBool(os.Getenv("LEASH_OTEL_PROPAGATE_HTTP_HEADERS"), false),
	}
}
