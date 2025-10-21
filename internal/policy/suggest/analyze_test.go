package suggest

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
)

func TestAnalyzeDirectorySuggestions(t *testing.T) {
	ps := &lsm.PolicySet{}
	ps.Open = append(ps.Open,
		allowFileRule("/etc/ssh/sshd_config", lsm.OpOpen),
		allowFileRule("/etc/ssh/ssh_config", lsm.OpOpenRO),
		allowFileRule("/etc/ssh/ssh_known_hosts", lsm.OpOpenRO),
	)

	result := Analyze(Inputs{LSMPolicies: ps}, Options{MinDirectoryGroup: 2})
	if len(result.Suggestions) == 0 {
		t.Fatalf("expected at least one suggestion")
	}

	found := false
	for _, s := range result.Suggestions {
		if s.Kind == SuggestDirectory {
			found = true
			if s.Metadata["directory"] != "/etc/ssh" {
				t.Fatalf("unexpected directory: %s", s.Metadata["directory"])
			}
			if s.PolicyCount != 3 {
				t.Fatalf("unexpected policy count: %d", s.PolicyCount)
			}
			break
		}
	}
	if !found {
		t.Fatalf("did not find directory suggestion")
	}
}

func TestAnalyzeDomainSuggestions(t *testing.T) {
	ps := &lsm.PolicySet{}
	ps.Connect = append(ps.Connect,
		allowConnectRule("api.openai.com", 443),
		allowConnectRule("files.openai.com", 443),
		allowConnectRule("chat.openai.com", 443),
	)

	result := Analyze(Inputs{LSMPolicies: ps}, Options{MinDomainGroup: 3})
	if len(result.Suggestions) == 0 {
		t.Fatalf("expected suggestions")
	}

	found := false
	for _, s := range result.Suggestions {
		if s.Kind == SuggestDomain {
			found = true
			if s.Metadata["base_domain"] != "openai.com" {
				t.Fatalf("expected base domain openai.com, got %s", s.Metadata["base_domain"])
			}
		}
	}
	if !found {
		t.Fatalf("did not find domain suggestion")
	}
}

func TestAnalyzeHTTPSuggestions(t *testing.T) {
	rewrites := []proxy.HeaderRewriteRule{
		{Host: "api.openai.com", Header: "X-Test", Value: "one"},
		{Host: "files.openai.com", Header: "X-Test", Value: "two"},
	}

	result := Analyze(Inputs{HTTPRewrites: rewrites}, Options{MinHTTPGroup: 2})
	if len(result.Suggestions) == 0 {
		t.Fatalf("expected http suggestions")
	}

	found := false
	for _, s := range result.Suggestions {
		if s.Kind == SuggestHTTPHost {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not find http suggestion")
	}
}

// Helpers -----------------------------------------------------------------

func allowFileRule(path string, op int32) lsm.PolicyRule {
	var rule lsm.PolicyRule
	rule.Action = lsm.PolicyAllow
	rule.Operation = op
	rule.PathLen = int32(copy(rule.Path[:], path))
	if strings.HasSuffix(path, "/") {
		rule.IsDirectory = 1
	}
	return rule
}

func allowConnectRule(host string, port uint16) lsm.PolicyRule {
	var rule lsm.PolicyRule
	rule.Action = lsm.PolicyAllow
	rule.Operation = lsm.OpConnect
	rule.HostnameLen = int32(copy(rule.Hostname[:], host))
	rule.DestPort = port
	return rule
}
