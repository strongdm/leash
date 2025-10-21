package transpiler

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

// Forbid McpCall on a server -> connect deny to that host
func TestTranspile_MCPCall_ServerDeny_ToConnect(t *testing.T) {
	cedar := `
forbid (principal, action == Action::"McpCall", resource) when { resource in [ MCP::Server::"mcp.context7.com" ] };`

	tr := NewCedarToLeashTranspiler()
	ps, httpRules, err := tr.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("transpile failed: %v", err)
	}
	if len(httpRules) != 0 {
		t.Fatalf("expected no http rules, got %d", len(httpRules))
	}
	if ps == nil || len(ps.Connect) == 0 {
		t.Fatalf("expected at least one connect rule")
	}
	got := ps.Connect[0].String()
	if !strings.Contains(got, "deny net.send mcp.context7.com") {
		t.Fatalf("unexpected connect rule: %s", got)
	}
	if len(ps.MCP) != 1 {
		t.Fatalf("expected one MCP rule, got %d", len(ps.MCP))
	}
	rule := ps.MCP[0]
	if rule.Action != int32(lsm.PolicyDeny) || rule.Server != "mcp.context7.com" || rule.Tool != "" {
		t.Fatalf("unexpected MCP rule: %+v", rule)
	}
}

// Forbid McpCall on tool only -> no IR yet (v1), but no error
func TestTranspile_MCPCall_ToolOnly_NoIR(t *testing.T) {
	cedar := `
forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"resolve-library-id");`

	tr := NewCedarToLeashTranspiler()
	ps, httpRules, err := tr.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("transpile failed: %v", err)
	}
	if len(httpRules) != 0 {
		t.Fatalf("expected no http rules, got %d", len(httpRules))
	}
	if ps == nil {
		t.Fatalf("expected policy set")
	}
	if len(ps.Open)+len(ps.Exec)+len(ps.Connect) != 0 {
		t.Fatalf("expected no IR rules for tool-only deny in v1")
	}
	if len(ps.MCP) != 1 {
		t.Fatalf("expected one MCP rule, got %d", len(ps.MCP))
	}
	rule := ps.MCP[0]
	if rule.Server != "" || rule.Tool != "resolve-library-id" || rule.Action != int32(lsm.PolicyDeny) {
		t.Fatalf("unexpected MCP rule: %+v", rule)
	}
}
