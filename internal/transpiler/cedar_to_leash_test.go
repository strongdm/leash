package transpiler

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

func TestCedarToLeashTranspiler_BasicFileOpen(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
action == Action::"FileOpen",
	resource
)
when {
	resource in [
		File::"/etc/passwd",
		Dir::"/tmp"
	]
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Open) != 2 {
		t.Fatalf("Expected 2 open policies, got %d", len(policies.Open))
	}

	var dirRule *lsm.PolicyRule
	for i := range policies.Open {
		rule := &policies.Open[i]
		if rule.Action != lsm.PolicyAllow {
			t.Errorf("Expected PolicyAllow, got %d", rule.Action)
		}
		if rule.Operation != lsm.OpOpen {
			t.Errorf("Expected OpOpen, got %d", rule.Operation)
		}
		if string(rule.Path[:rule.PathLen]) == "/tmp/" {
			dirRule = rule
		}
	}
	if dirRule == nil {
		t.Fatalf("expected directory rule for /tmp/")
	}
	if dirRule.IsDirectory != 1 {
		t.Fatalf("expected IsDirectory=1 for directory rule, got %d", dirRule.IsDirectory)
	}
}

func TestCedarToLeashTranspiler_ExecOperation(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
    action == Action::"ProcessExec",
	resource
)
when {
	resource in [
		File::"/bin/bash",
		Dir::"/usr/bin"
	]
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Exec) != 2 {
		t.Fatalf("Expected 2 exec policies, got %d", len(policies.Exec))
	}

	for _, rule := range policies.Exec {
		if rule.Action != lsm.PolicyAllow {
			t.Errorf("Expected PolicyAllow, got %d", rule.Action)
		}
		if rule.Operation != lsm.OpExec {
			t.Errorf("Expected OpExec, got %d", rule.Operation)
		}
	}
}

func TestCedarToLeashTranspiler_ConnectOperation(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
action == Action::"NetworkConnect",
	resource
)
when {
	resource in [
		Host::"api.anthropic.com",
		Host::"*.example.com",
		Host::"192.168.1.1:8080"
	]
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Connect) != 3 {
		t.Fatalf("Expected 3 connect policies, got %d", len(policies.Connect))
	}

	for _, rule := range policies.Connect {
		if rule.Action != lsm.PolicyAllow {
			t.Errorf("Expected PolicyAllow, got %d", rule.Action)
		}
		if rule.Operation != lsm.OpConnect {
			t.Errorf("Expected OpConnect, got %d", rule.Operation)
		}
	}

	wildcardFound := false
	ipFound := false
	hostnameFound := false

	for _, rule := range policies.Connect {
		hostname := string(rule.Hostname[:rule.HostnameLen])
		if rule.IsWildcard == 1 && strings.HasPrefix(hostname, "*.") {
			wildcardFound = true
		}
		if rule.DestIP != 0 {
			ipFound = true
		}
		if hostname == "api.anthropic.com" {
			hostnameFound = true
		}
	}

	if !wildcardFound {
		t.Error("Expected to find wildcard rule")
	}
	if !ipFound {
		t.Error("Expected to find IP-based rule")
	}
	if !hostnameFound {
		t.Error("Expected to find hostname rule")
	}
}

func TestCedarToLeashTranspiler_ContextHostnameLike(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
action == Action::"NetworkConnect",
	resource
)
when {
	context.hostname like "*.example.com"
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Connect) != 1 {
		t.Fatalf("Expected 1 connect policy, got %d", len(policies.Connect))
	}

	rule := policies.Connect[0]
	if rule.Action != lsm.PolicyAllow {
		t.Errorf("Expected PolicyAllow, got %d", rule.Action)
	}
	if rule.Operation != lsm.OpConnect {
		t.Errorf("Expected OpConnect, got %d", rule.Operation)
	}

	hostname := string(rule.Hostname[:rule.HostnameLen])
	if hostname != "*.example.com" {
		t.Errorf("Expected *.example.com, got %s", hostname)
	}

	if rule.IsWildcard != 1 {
		t.Error("Expected IsWildcard to be 1")
	}
}

func TestCedarToLeashTranspiler_ContextHostnameEquals(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
action == Action::"NetworkConnect",
	resource
)
when {
	context.hostname == "api.example.com"
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Connect) != 1 {
		t.Fatalf("Expected 1 connect policy, got %d", len(policies.Connect))
	}

	rule := policies.Connect[0]
	hostname := string(rule.Hostname[:rule.HostnameLen])
	if hostname != "api.example.com" {
		t.Errorf("Expected api.example.com, got %s", hostname)
	}

	if rule.IsWildcard != 0 {
		t.Error("Expected IsWildcard to be 0 for exact match")
	}
}

func TestCedarToLeashTranspiler_ImplicitConnectDefaultAllow(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
    principal,
    action == Action::"NetworkConnect",
    resource
)
when {
    resource in [ Host::"*" ]
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}
	if !policies.ConnectDefaultAllow {
		t.Fatalf("expected ConnectDefaultAllow to be true")
	}
	if policies.ConnectDefaultExplicit {
		t.Fatalf("expected implicit default (explicit=false)")
	}
}

func TestCedarToLeashTranspiler_ExplicitConnectDefaultDeny(t *testing.T) {
	t.Parallel()

	cedar := `
forbid (
    principal,
    action == Action::"NetworkConnect",
    resource
)
when {
    resource in [ Host::"*" ]
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}
	if policies.ConnectDefaultAllow {
		t.Fatalf("expected ConnectDefaultAllow to be false")
	}
	if !policies.ConnectDefaultExplicit {
		t.Fatalf("expected explicit default flag to be true")
	}
}

func TestCedarToLeashTranspiler_ForbidPolicy(t *testing.T) {
	t.Parallel()

	cedar := `
forbid (
	principal == User::"claude",
action == Action::"ProcessExec",
	resource == File::"/bin/foo"
);
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Exec) != 1 {
		t.Fatalf("Expected 1 exec policy, got %d", len(policies.Exec))
	}

	rule := policies.Exec[0]
	if rule.Action != lsm.PolicyDeny {
		t.Errorf("Expected PolicyDeny, got %d", rule.Action)
	}

	path := string(rule.Path[:rule.PathLen])
	if path != "/bin/foo" {
		t.Errorf("Expected /bin/foo, got %s", path)
	}
}

func TestCedarToLeashTranspiler_MultipleActions(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
    action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
	resource
)
when {
	resource in [
		Dir::"/tmp"
	]
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	totalRules := len(policies.Open)
	if totalRules != 3 {
		t.Fatalf("Expected 3 open-related policies (open, read, write), got %d", totalRules)
	}

	operations := make(map[int32]bool)
	for _, rule := range policies.Open {
		operations[rule.Operation] = true
	}

	if !operations[lsm.OpOpen] {
		t.Error("Expected OpOpen operation")
	}
	if !operations[lsm.OpOpenRO] {
		t.Error("Expected OpOpenRO operation")
	}
	if !operations[lsm.OpOpenRW] {
		t.Error("Expected OpOpenRW operation")
	}
}

func TestCedarToLeashTranspiler_DirectoryHandling(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
action == Action::"FileOpen",
	resource
)
when {
	resource in [
		Dir::"/home/user"
	]
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Open) != 1 {
		t.Fatalf("Expected 1 open policy, got %d", len(policies.Open))
	}

	rule := policies.Open[0]
	path := string(rule.Path[:rule.PathLen])

	if !strings.HasSuffix(path, "/") {
		t.Errorf("Expected directory path to end with /, got %s", path)
	}

	if rule.IsDirectory != 1 {
		t.Error("Expected IsDirectory to be 1")
	}
}

func TestCedarToLeashTranspiler_PortHandling(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
action == Action::"NetworkConnect",
	resource
)
when {
	resource in [
		Host::"example.com:443"
	]
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Connect) != 1 {
		t.Fatalf("Expected 1 connect policy, got %d", len(policies.Connect))
	}

	rule := policies.Connect[0]
	hostname := string(rule.Hostname[:rule.HostnameLen])

	if !strings.Contains(hostname, "example.com") {
		t.Errorf("Expected hostname to contain example.com, got %s", hostname)
	}

	if rule.DestPort != 443 {
		t.Errorf("Expected port 443, got %d", rule.DestPort)
	}
}

func TestCedarToLeashTranspiler_ComplexPolicy(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
	resource
)
when {
	resource in [
		Dir::"/dev",
		Dir::"/etc",
		Dir::"/tmp",
		File::"/etc/passwd"
	]
};

permit (
	principal == User::"claude",
action == Action::"NetworkConnect",
	resource
)
when {
	resource in [
		Host::"api.anthropic.com",
		Host::"*.example.com"
	]
};

permit (
	principal == User::"claude",
action == Action::"ProcessExec",
	resource
)
when {
	resource in [
		File::"/bin/bash",
		Dir::"/usr/bin"
	]
};

forbid (
	principal == User::"claude",
action == Action::"ProcessExec",
	resource == File::"/bin/dangerous"
);
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Open) == 0 {
		t.Error("Expected open policies")
	}

	if len(policies.Connect) != 2 {
		t.Errorf("Expected 2 connect policies, got %d", len(policies.Connect))
	}

	if len(policies.Exec) == 0 {
		t.Error("Expected exec policies")
	}

	denyFound := false
	for _, rule := range policies.Exec {
		if rule.Action == lsm.PolicyDeny {
			denyFound = true
			path := string(rule.Path[:rule.PathLen])
			if path != "/bin/dangerous" {
				t.Errorf("Expected /bin/dangerous, got %s", path)
			}
		}
	}

	if !denyFound {
		t.Error("Expected to find deny policy")
	}
}

func TestCedarToLeashTranspiler_MixedContextAndResourceConditions(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
	principal == User::"claude",
action == Action::"NetworkConnect",
	resource
)
when {
	resource in [
		Host::"api.example.com"
	]
};

permit (
	principal == User::"claude",
action == Action::"NetworkConnect",
	resource
)
when {
	context.hostname like "*.wildcard.com"
};

forbid (
	principal == User::"claude",
action == Action::"NetworkConnect",
	resource
)
when {
	context.hostname == "blocked.example.com"
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, _, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	if len(policies.Connect) != 3 {
		t.Fatalf("Expected 3 connect policies, got %d", len(policies.Connect))
	}

	foundExact := false
	foundWildcard := false
	foundBlocked := false

	for _, rule := range policies.Connect {
		hostname := string(rule.Hostname[:rule.HostnameLen])

		if hostname == "api.example.com" && rule.Action == lsm.PolicyAllow {
			foundExact = true
		}

		if hostname == "*.wildcard.com" && rule.IsWildcard == 1 && rule.Action == lsm.PolicyAllow {
			foundWildcard = true
		}

		if hostname == "blocked.example.com" && rule.Action == lsm.PolicyDeny {
			foundBlocked = true
		}
	}

	if !foundExact {
		t.Error("Expected to find exact hostname rule")
	}
	if !foundWildcard {
		t.Error("Expected to find wildcard hostname rule")
	}
	if !foundBlocked {
		t.Error("Expected to find blocked hostname rule")
	}
}

func TestPolicySetToLines(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
    principal == User::"test",
action in [Action::"FileOpen", Action::"FileOpenReadOnly"],
    resource == File::"/etc/passwd"
);

permit (
    principal == User::"test",
action == Action::"FileOpen",
    resource == Dir::"/tmp"
);

permit (
    principal == User::"test",
    action == Action::"NetworkConnect",
    resource
)
when {
    resource in [
        Host::"api.example.com",
        Host::"*.example.com"
    ]
};
`

	transpiler := NewCedarToLeashTranspiler()
	policies, httpRules, err := transpiler.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("Failed to transpile: %v", err)
	}

	lines := PolicySetToLines(policies, httpRules)

	expected := []string{
		"allow file.open /etc/passwd",
		"allow file.open:ro /etc/passwd",
		"allow file.open /tmp/",
		"allow net.send api.example.com",
		"allow net.send *.example.com",
	}

	if !equalStringSlices(lines, expected) {
		t.Fatalf("unexpected lines: got %v, want %v", lines, expected)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
