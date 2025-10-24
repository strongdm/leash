package transpiler

import (
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/strongdm/leash/internal/lsm"
)

// Compare Cedar Authorize vs IR decision for DnsZone mapping. We intentionally
// exercise a known divergence at the apex host and assert our linter warns.
func TestDual_CedarDnsZone_vs_IRWildcard_ApexDivergenceWarned(t *testing.T) {
	cedarText := `permit (principal, action == Action::"NetworkConnect", resource in Net::DnsZone::"example.com");`

	// Lint must warn that apex is excluded by IR mapping
	rep, err := LintFromString(cedarText)
	if err != nil {
		t.Fatalf("lint failed: %v", err)
	}
	saw := false
	for _, it := range rep.Issues {
		if it.Code == "dnszone_apex_excluded" {
			saw = true
			break
		}
	}
	if !saw {
		t.Fatalf("expected dnszone_apex_excluded warning")
	}

	// Transpile to IR
	tr := NewCedarToLeashTranspiler()
	ps, _, err := tr.TranspileFromString(cedarText)
	if err != nil {
		t.Fatalf("transpile failed: %v", err)
	}
	checker := lsm.NewSimplePolicyChecker(lsm.ConvertToConnectRules(ps.Connect), false, ps.MCP)

	// Cedar entities: DnsZone parent of both apex and subdomain
	zone := cedar.NewEntityUID("Net::DnsZone", "example.com")
	apex := cedar.NewEntityUID("Net::Hostname", "example.com")
	sub := cedar.NewEntityUID("Net::Hostname", "svc.example.com")
	entities := cedar.EntityMap{
		zone: cedar.Entity{UID: zone},
		apex: cedar.Entity{UID: apex, Parents: cedar.NewEntityUIDSet(zone)},
		sub:  cedar.Entity{UID: sub, Parents: cedar.NewEntityUIDSet(zone)},
	}
	psCedar, _ := cedar.NewPolicySetFromBytes("p", []byte(cedarText))

	// Cedar: apex allow
	decApex, _ := cedar.Authorize(psCedar, entities, cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "NetworkConnect"),
		Resource:  apex,
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	})
	if decApex != cedar.Allow {
		t.Fatalf("cedar apex expected allow, got %v", decApex)
	}
	// IR: apex deny (wildcard does not include apex)
	if checker.CheckConnect("example.com", "", 0) {
		t.Fatalf("IR unexpectedly allowed apex host")
	}
	// Subdomain: both should allow
	decSub, _ := cedar.Authorize(psCedar, entities, cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "NetworkConnect"),
		Resource:  sub,
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	})
	if decSub != cedar.Allow {
		t.Fatalf("cedar subdomain expected allow, got %v", decSub)
	}
	if !checker.CheckConnect("svc.example.com", "", 0) {
		t.Fatalf("IR expected allow for subdomain")
	}
}

// When using context.hostname like "*.example.com", both Cedar and IR exclude apex
// and include subdomains. Validate alignment.
func TestDual_CedarHostnameLike_vs_IRWildcard_Aligned(t *testing.T) {
	cedarText := `permit (principal, action == Action::"NetworkConnect", resource) when { context.hostname like "*.example.com" };`

	tr := NewCedarToLeashTranspiler()
	ps, _, err := tr.TranspileFromString(cedarText)
	if err != nil {
		t.Fatalf("transpile failed: %v", err)
	}
	checker := lsm.NewSimplePolicyChecker(lsm.ConvertToConnectRules(ps.Connect), false, ps.MCP)

	psCedar, _ := cedar.NewPolicySetFromBytes("p", []byte(cedarText))
	entities := cedar.EntityMap{}

	// Apex denied by both
	decApex, _ := cedar.Authorize(psCedar, entities, cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "NetworkConnect"),
		Resource:  cedar.NewEntityUID("Net::Hostname", "example.com"),
		Context:   cedar.NewRecord(cedar.RecordMap{"hostname": cedar.String("example.com")}),
	})
	if decApex != cedar.Deny {
		t.Fatalf("cedar apex expected deny, got %v", decApex)
	}
	if checker.CheckConnect("example.com", "", 0) {
		t.Fatalf("IR apex expected deny")
	}

	// Subdomain allowed by both
	decSub, _ := cedar.Authorize(psCedar, entities, cedar.Request{
		Principal: cedar.NewEntityUID("User", "any"),
		Action:    cedar.NewEntityUID("Action", "NetworkConnect"),
		Resource:  cedar.NewEntityUID("Net::Hostname", "svc.example.com"),
		Context:   cedar.NewRecord(cedar.RecordMap{"hostname": cedar.String("svc.example.com")}),
	})
	if decSub != cedar.Allow {
		t.Fatalf("cedar subdomain expected allow, got %v", decSub)
	}
	if !checker.CheckConnect("svc.example.com", "", 0) {
		t.Fatalf("IR subdomain expected allow")
	}
}
