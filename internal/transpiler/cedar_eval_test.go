package transpiler

import (
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
)

// Light-touch Cedar evaluation tests to sanity-check example semantics.

func TestCedarEval_ActionConnect_AllowsMatchingHostname(t *testing.T) {
	policyText := `
permit (
  principal,
  action == Action::"NetworkConnect",
  resource == Net::Hostname::"api.example.com"
);`

	ps, err := cedar.NewPolicySetFromBytes("policies", []byte(policyText))
	if err != nil {
		t.Fatalf("failed to parse cedar: %v", err)
	}
	var entities cedar.EntityMap

	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "NetworkConnect"),
		Resource:  cedar.NewEntityUID("Net::Hostname", "api.example.com"),
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision != cedar.Allow {
		t.Fatalf("expected allow, got %q", decision)
	}

	// Different host denied
	req.Resource = cedar.NewEntityUID("Net::Hostname", "other.example.com")
	decision, _ = cedar.Authorize(ps, entities, req)
	if decision != cedar.Deny {
		t.Fatalf("expected deny for non-matching host, got %q", decision)
	}
}

func TestCedarEval_ActionConnect_ForbidOverridesPermit(t *testing.T) {
	policyText := `
permit (principal, action == Action::"NetworkConnect", resource == Net::Hostname::"api.example.com");
forbid (principal, action == Action::"NetworkConnect", resource == Net::Hostname::"api.example.com");
`
	ps, err := cedar.NewPolicySetFromBytes("policies", []byte(policyText))
	if err != nil {
		t.Fatalf("failed to parse cedar: %v", err)
	}
	var entities cedar.EntityMap
	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "NetworkConnect"),
		Resource:  cedar.NewEntityUID("Net::Hostname", "api.example.com"),
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision != cedar.Deny {
		t.Fatalf("expected deny (forbid overrides permit), got %q", decision)
	}
}

func TestCedarEval_FileRead_AllowsExactFile(t *testing.T) {
	policyText := `
permit (
  principal,
  action == Action::"FileOpenReadOnly",
  resource == Fs::File::"/etc/hosts"
);`

	ps, err := cedar.NewPolicySetFromBytes("policies", []byte(policyText))
	if err != nil {
		t.Fatalf("failed to parse cedar: %v", err)
	}
	var entities cedar.EntityMap

	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "FileOpenReadOnly"),
		Resource:  cedar.NewEntityUID("Fs::File", "/etc/hosts"),
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision != cedar.Allow {
		t.Fatalf("expected allow, got %q", decision)
	}

	req.Resource = cedar.NewEntityUID("Fs::File", "/etc/shadow")
	decision, _ = cedar.Authorize(ps, entities, req)
	if decision != cedar.Deny {
		t.Fatalf("expected deny, got %q", decision)
	}
}

func TestCedarEval_ContextHostnameEquals_And_Like(t *testing.T) {
	policyText := `
permit (principal, action == Action::"NetworkConnect", resource) when { context.hostname == "api.example.com" };
permit (principal, action == Action::"NetworkConnect", resource) when { context.hostname like "*.wild.example.com" };`

	ps, err := cedar.NewPolicySetFromBytes("policies", []byte(policyText))
	if err != nil {
		t.Fatalf("failed to parse cedar: %v", err)
	}
	var entities cedar.EntityMap

	// Equals match
	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "NetworkConnect"),
		Resource:  cedar.NewEntityUID("Net::Hostname", "ignored"),
		Context:   cedar.NewRecord(cedar.RecordMap{"hostname": cedar.String("api.example.com")}),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision != cedar.Allow {
		t.Fatalf("expected allow for equals, got %q", decision)
	}

	// Like match
	req.Context = cedar.NewRecord(cedar.RecordMap{"hostname": cedar.String("svc.wild.example.com")})
	decision, _ = cedar.Authorize(ps, entities, req)
	if decision != cedar.Allow {
		t.Fatalf("expected allow for like, got %q", decision)
	}

	// No match
	req.Context = cedar.NewRecord(cedar.RecordMap{"hostname": cedar.String("nope.example.com")})
	decision, _ = cedar.Authorize(ps, entities, req)
	if decision != cedar.Deny {
		t.Fatalf("expected deny when neither matches, got %q", decision)
	}
}

func TestCedarEval_HttpRewrite_ContextConditions(t *testing.T) {
	policyText := `
permit (
  principal,
  action == Action::"HttpRewrite",
  resource == Net::Hostname::"api.example.com"
) when { context.header == "X-Key" && context.value == "v" };`

	ps, err := cedar.NewPolicySetFromBytes("policies", []byte(policyText))
	if err != nil {
		t.Fatalf("failed to parse cedar: %v", err)
	}
	var entities cedar.EntityMap

	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "HttpRewrite"),
		Resource:  cedar.NewEntityUID("Net::Hostname", "api.example.com"),
		Context: cedar.NewRecord(cedar.RecordMap{
			"header": cedar.String("X-Key"),
			"value":  cedar.String("v"),
		}),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision != cedar.Allow {
		t.Fatalf("expected allow for matching header/value, got %q", decision)
	}

	// Mismatch value
	req.Context = cedar.NewRecord(cedar.RecordMap{"header": cedar.String("X-Key"), "value": cedar.String("nope")})
	decision, _ = cedar.Authorize(ps, entities, req)
	if decision != cedar.Deny {
		t.Fatalf("expected deny for mismatched value, got %q", decision)
	}
}

func TestCedarEval_DnsZoneMembership_AllowsHostname(t *testing.T) {
	policyText := `
permit (principal, action == Action::"NetworkConnect", resource in Net::DnsZone::"example.com");`

	ps, err := cedar.NewPolicySetFromBytes("policies", []byte(policyText))
	if err != nil {
		t.Fatalf("failed to parse cedar: %v", err)
	}

	zone := cedar.NewEntityUID("Net::DnsZone", "example.com")
	host := cedar.NewEntityUID("Net::Hostname", "api.example.com")

	entities := cedar.EntityMap{
		zone: cedar.Entity{UID: zone},
		host: cedar.Entity{UID: host, Parents: cedar.NewEntityUIDSet(zone)},
	}

	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "NetworkConnect"),
		Resource:  host,
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision != cedar.Allow {
		t.Fatalf("expected allow via membership, got %q", decision)
	}

	// Host outside zone
	other := cedar.NewEntityUID("Net::Hostname", "api.other.com")
	entities[other] = cedar.Entity{UID: other}
	req.Resource = other
	decision, _ = cedar.Authorize(ps, entities, req)
	if decision != cedar.Deny {
		t.Fatalf("expected deny for non-member, got %q", decision)
	}
}

func TestCedarEval_DirMembership_AllowsFileUnderDir(t *testing.T) {
	policyText := `
permit (principal, action == Action::"FileOpenReadOnly", resource in Fs::Directory::"/var/log");`

	ps, err := cedar.NewPolicySetFromBytes("policies", []byte(policyText))
	if err != nil {
		t.Fatalf("failed to parse cedar: %v", err)
	}

	dir := cedar.NewEntityUID("Fs::Directory", "/var/log")
	file := cedar.NewEntityUID("Fs::File", "/var/log/syslog")
	other := cedar.NewEntityUID("Fs::File", "/home/user/file")

	entities := cedar.EntityMap{
		dir:   cedar.Entity{UID: dir},
		file:  cedar.Entity{UID: file, Parents: cedar.NewEntityUIDSet(dir)},
		other: cedar.Entity{UID: other},
	}

	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "FileOpenReadOnly"),
		Resource:  file,
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision != cedar.Allow {
		t.Fatalf("expected allow via dir membership, got %q", decision)
	}

	req.Resource = other
	decision, _ = cedar.Authorize(ps, entities, req)
	if decision != cedar.Deny {
		t.Fatalf("expected deny for file outside dir, got %q", decision)
	}
}
