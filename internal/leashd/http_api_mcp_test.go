package leashd

import "testing"

func TestBuildCedarFromAction_MCPAllowURLServer(t *testing.T) {
	cedar, err := buildCedarFromActionRequest(addPolicyFromActionRequest{
		Effect: "permit",
		Action: actionPayload{
			Type: "mcp/allow",
			Name: "mcp.allow method=tools/call server=https://api.example.com/v1 tool=db.query",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `permit (principal, action == Action::"McpCall", resource == MCP::Tool::"db.query") when { resource in [ MCP::Server::"api.example.com" ] };`
	if cedar != want {
		t.Fatalf("got %q, want %q", cedar, want)
	}
}

func TestBuildCedarFromAction_MCPDenyHostServer(t *testing.T) {
	cedar, err := buildCedarFromActionRequest(addPolicyFromActionRequest{
		Effect: "forbid",
		Action: actionPayload{
			Type: "mcp/deny",
			Name: "mcp.deny method=tools/call server=registry.corp tool=danger",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"danger") when { resource in [ MCP::Server::"registry.corp" ] };`
	if cedar != want {
		t.Fatalf("got %q, want %q", cedar, want)
	}
}

func TestBuildCedarFromAction_MCPOtherKinds(t *testing.T) {
	cedar, err := buildCedarFromActionRequest(addPolicyFromActionRequest{
		Effect: "permit",
		Action: actionPayload{
			Type: "mcp/call",
			Name: "mcp.call method=tools/call server=wss://mcp.github.com:443 session=abc123",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `permit (principal, action == Action::"McpCall", resource) when { resource in [ MCP::Server::"mcp.github.com" ] };`
	if cedar != want {
		t.Fatalf("got %q, want %q", cedar, want)
	}
}

func TestBuildCedarFromAction_MCPFallback(t *testing.T) {
	cedar, err := buildCedarFromActionRequest(addPolicyFromActionRequest{
		Effect: "forbid",
		Action: actionPayload{
			Type: "mcp/prompts",
			Name: "mcp.prompts list prompts", // no server/host; falls back
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `forbid (principal, action == Action::"McpCall", resource) when { resource in [ MCP::Server::"example.com" ] };`
	if cedar != want {
		t.Fatalf("got %q, want %q", cedar, want)
	}
}

func TestBuildCedarFromAction_MCPAllowStructured(t *testing.T) {
	cedar, err := buildCedarFromActionRequest(addPolicyFromActionRequest{
		Effect: "permit",
		Action: actionPayload{
			Type:   "mcp/allow",
			Name:   "mcp.allow method=tools/call", // minimal name; structured fields carry server/tool
			Server: "mcp.context7.com",
			Tool:   "resolve-library-id",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `permit (principal, action == Action::"McpCall", resource == MCP::Tool::"resolve-library-id") when { resource in [ MCP::Server::"mcp.context7.com" ] };`
	if cedar != want {
		t.Fatalf("got %q, want %q", cedar, want)
	}
}

// Reproduces the bug: clicking "add allow" on an mcp/call with tool should include the tool in the policy
func TestBuildCedarFromAction_MCPCallWithToolStructured(t *testing.T) {
	cedar, err := buildCedarFromActionRequest(addPolicyFromActionRequest{
		Effect: "permit",
		Action: actionPayload{
			Type:   "mcp/call",
			Name:   "tools/call",
			Server: "mcp.context7.com",
			Tool:   "resolve-library-id",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `permit (principal, action == Action::"McpCall", resource == MCP::Tool::"resolve-library-id") when { resource in [ MCP::Server::"mcp.context7.com" ] };`
	if cedar != want {
		t.Fatalf("got %q, want %q", cedar, want)
	}
}
