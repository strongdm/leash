package suggest

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
	"github.com/strongdm/leash/internal/transpiler"
)

// Test that ProposedCedar from suggestions parses and transpiles without error
// and yields at least one enforceable rule for each suggestion kind we emit
// Cedar for today (directory, domain, http.rewrite).
func TestSuggestionsProduceValidCedar(t *testing.T) {
	// 1) Directory suggestions (files under same dir)
	dirPS := &lsm.PolicySet{}
	dirPS.Open = append(dirPS.Open,
		allowFileRule("/etc/ssh/sshd_config", lsm.OpOpen),
		allowFileRule("/etc/ssh/ssh_config", lsm.OpOpenRO),
		allowFileRule("/etc/ssh/ssh_known_hosts", lsm.OpOpenRO),
	)

	// 2) Domain suggestions (multiple hosts under same base)
	domPS := &lsm.PolicySet{}
	domPS.Connect = append(domPS.Connect,
		allowConnectRule("api.openai.com", 443),
		allowConnectRule("files.openai.com", 443),
		allowConnectRule("chat.openai.com", 443),
	)

	// 3) HTTP suggestions (rewrite rules under same base)
	rewrites := []proxy.HeaderRewriteRule{
		{Host: "api.openai.com", Header: "X-Test", Value: "one"},
		{Host: "files.openai.com", Header: "X-Test", Value: "two"},
	}

	in := Inputs{
		LSMPolicies:    mergePolicySets(dirPS, domPS),
		HTTPRewrites:   rewrites,
		EventSequences: nil,
	}

	res := Analyze(in, Options{MinDirectoryGroup: 2, MinDomainGroup: 3, MinHTTPGroup: 2})
	if len(res.Suggestions) == 0 {
		t.Fatalf("expected suggestions")
	}

	for _, s := range res.Suggestions {
		cedar := strings.TrimSpace(s.ProposedCedar)
		if cedar == "" {
			// Some suggestions may not carry Cedar in the future; today these three do.
			t.Fatalf("suggestion %s missing ProposedCedar", s.Kind)
		}

		tr := transpiler.NewCedarToLeashTranspiler()
		ps, httpRules, err := tr.TranspileFromString(cedar)
		if err != nil {
			t.Fatalf("transpile failed for %s: %v\nCedar:\n%s", s.Kind, err, cedar)
		}

		switch s.Kind {
		case SuggestDirectory:
			if ps == nil || len(ps.Open) == 0 {
				t.Fatalf("directory suggestion produced no file rules")
			}
		case SuggestDomain:
			if ps == nil || len(ps.Connect) == 0 {
				t.Fatalf("domain suggestion produced no connect rules\nCedar:\n%s", cedar)
			}
		case SuggestHTTPHost:
			if len(httpRules) == 0 {
				t.Fatalf("http suggestion produced no rewrite rules")
			}
		}
	}
}

// mergePolicySets is a tiny helper to combine LSM rules for testing.
func mergePolicySets(a, b *lsm.PolicySet) *lsm.PolicySet {
	out := &lsm.PolicySet{}
	if a != nil {
		out.Open = append(out.Open, a.Open...)
		out.Exec = append(out.Exec, a.Exec...)
		out.Connect = append(out.Connect, a.Connect...)
	}
	if b != nil {
		out.Open = append(out.Open, b.Open...)
		out.Exec = append(out.Exec, b.Exec...)
		out.Connect = append(out.Connect, b.Connect...)
	}
	return out
}
