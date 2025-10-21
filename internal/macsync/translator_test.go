package macsync

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/transpiler"
)

func TestConvertPolicyToMacRules_PropagatesAllowOverrides(t *testing.T) {
	const cedar = `
permit (
    principal,
    action == Action::"FileOpen",
    resource
) when {
    resource in [ File::"/tmp/allowed.txt" ]
};

forbid (
    principal,
    action == Action::"FileOpen",
    resource
) when {
    resource in [ Dir::"/tmp" ]
};

permit (
    principal,
    action == Action::"ProcessExec",
    resource
) when {
    resource in [ File::"/usr/bin/python3" ]
};

forbid (
    principal,
    action == Action::"ProcessExec",
    resource
) when {
    resource in [ Dir::"/usr/bin" ]
};

permit (
    principal,
    action == Action::"NetworkConnect",
    resource
) when {
    resource in [ Host::"allowed.example.com" ]
};

forbid (
    principal,
    action == Action::"NetworkConnect",
    resource
) when {
    resource in [ Host::"*.example.com" ]
};
`

	trans := transpiler.NewCedarToLeashTranspiler()
	policy, _, err := trans.TranspileFromString(cedar)
	if err != nil {
		t.Fatalf("transpile: %v", err)
	}

	fileRules, networkRules := ConvertPolicyToMacRules(policy)

	if len(fileRules) == 0 {
		t.Fatalf("expected file rules, got none")
	}

	var (
		foundAllowFile bool
		foundDenyDir   bool
		foundAllowExec bool
		foundDenyExec  bool
	)

	for _, rule := range fileRules {
		switch {
		case rule.Action == "allow" && rule.Kind == "fileAccess" && rule.FilePath == "/tmp/allowed.txt":
			foundAllowFile = true
		case rule.Action == "deny" && rule.Kind == "fileAccess" && rule.Directory == "/tmp/":
			foundDenyDir = true
		case rule.Action == "allow" && rule.Kind == "processExec" && rule.ExecutablePath == "/usr/bin/python3":
			foundAllowExec = true
		case rule.Action == "deny" && rule.Kind == "processExec" && strings.HasPrefix(rule.ExecutablePath, "/usr/bin"):
			foundDenyExec = true
		}
	}

	if !foundAllowFile {
		t.Errorf("expected allow rule for /tmp/allowed.txt")
	}
	if !foundDenyDir {
		t.Errorf("expected deny directory rule for /tmp/")
	}
	if !foundAllowExec {
		t.Errorf("expected allow exec rule for /usr/bin/python3")
	}
	if !foundDenyExec {
		t.Errorf("expected deny exec rule under /usr/bin")
	}

	if len(networkRules) == 0 {
		t.Fatalf("expected network rules, got none")
	}

	var (
		foundAllowHost bool
		foundDenyHost  bool
	)

	for _, rule := range networkRules {
		switch {
		case rule.Action == "allow" && rule.TargetType == "domain" && rule.TargetValue == "allowed.example.com":
			foundAllowHost = true
		case rule.Action == "deny" && rule.TargetType == "domain" && rule.TargetValue == "*.example.com":
			foundDenyHost = true
		}
	}

	if !foundAllowHost {
		t.Errorf("expected allow network rule for allowed.example.com")
	}
	if !foundDenyHost {
		t.Errorf("expected deny network rule for *.example.com")
	}
}
