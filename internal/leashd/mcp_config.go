package leashd

import (
	"os"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/proxy"
)

const (
	defaultMCPSniffLimit = int64(1 * 1024 * 1024) // 1MB default sniff budget
	defaultSSEEventLimit = 10
)

// loadMCPConfigFromEnv builds the proxy MCP configuration from environment.
// Telemetry handles are injected later once OTEL instrumentation is ready.
func loadMCPConfigFromEnv() proxy.MCPConfig {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LEASH_MCP_OBS")))
	var obsMode proxy.MCPMode
	switch mode {
	case "off":
		obsMode = proxy.MCPModeOff
	case "enhanced":
		obsMode = proxy.MCPModeEnhanced
	default:
		obsMode = proxy.MCPModeBasic
	}

	sniffLimit := defaultMCPSniffLimit
	if raw := strings.TrimSpace(os.Getenv("LEASH_MCP_SNIFF_LIMIT")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			sniffLimit = parsed
		}
	}

	sseLimit := defaultSSEEventLimit
	if raw := strings.TrimSpace(os.Getenv("LEASH_MCP_SSE_EVENT_LIMIT")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			sseLimit = parsed
		}
	}

	return proxy.MCPConfig{
		Mode:          obsMode,
		SniffLimit:    sniffLimit,
		SSEEventLimit: sseLimit,
	}
}
