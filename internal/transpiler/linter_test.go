package transpiler

import "testing"

func TestLint_MissingAction(t *testing.T) {
	cedar := `
permit (principal, action, resource)
when { resource in [ Host::"api.example.com" ] };`
	rep, err := LintFromString(cedar)
	if err != nil {
		t.Fatalf("lint parse failed: %v", err)
	}
	found := false
	for _, it := range rep.Issues {
		if it.Code == "missing_action" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing_action lint")
	}
}

func TestLint_NoResources(t *testing.T) {
	cedar := `permit (principal, action == Action::"NetworkConnect", resource);`
	rep, err := LintFromString(cedar)
	if err != nil {
		t.Fatalf("lint parse failed: %v", err)
	}
	found := false
	for _, it := range rep.Issues {
		if it.Code == "no_resources" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected no_resources lint")
	}
}

func TestLint_ResourceMismatch_FileOpOnHost(t *testing.T) {
	cedar := `
permit (principal, action == Action::"FileOpen", resource)
when { resource in [ Host::"api.example.com" ] };`
	rep, err := LintFromString(cedar)
	if err != nil {
		t.Fatalf("lint parse failed: %v", err)
	}
	found := false
	for _, it := range rep.Issues {
		if it.Code == "resource_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected resource_mismatch lint for file op on host")
	}
}

func TestLint_HeadHostnameIsSupported(t *testing.T) {
	cedar := `
permit (
  principal,
  action == Net::"Connect",
  resource == Net::Hostname::"api.example.com"
);`
	rep, err := LintFromString(cedar)
	if err != nil {
		t.Fatalf("lint parse failed: %v", err)
	}
	for _, it := range rep.Issues {
		if it.Code == "unsupported_resource_type" {
			t.Fatalf("did not expect unsupported_resource_type for Net::Hostname in head: %+v", it)
		}
	}
}

func TestLint_UnsupportedAction(t *testing.T) {
	cedar := `permit (principal, action == Action::"Delete", resource == File::"/tmp/x");`
	rep, err := LintFromString(cedar)
	if err != nil {
		t.Fatalf("lint parse failed: %v", err)
	}
	found := false
	for _, it := range rep.Issues {
		if it.Code == "unsupported_action_id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unsupported_action_id lint")
	}
}

func TestLint_UnsupportedWildcard(t *testing.T) {
	cedar := `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [ Host::"foo*bar.com" ] };`
	rep, err := LintFromString(cedar)
	if err != nil {
		t.Fatalf("lint parse failed: %v", err)
	}
	found := false
	for _, it := range rep.Issues {
		if it.Code == "unsupported_wildcard" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unsupported_wildcard lint")
	}
}

func TestLint_MCPResourcesAllowedWithMCPCall(t *testing.T) {
	cedar := `
forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"resolve-library-id")
when { resource in [ MCP::Server::"mcp.context7.com" ] };`
	rep, err := LintFromString(cedar)
	if err != nil {
		t.Fatalf("lint parse failed: %v", err)
	}
	for _, it := range rep.Issues {
		if it.Severity == LintError {
			t.Fatalf("expected no lint errors, found %+v", rep.Issues)
		}
	}
}
