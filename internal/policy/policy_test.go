package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
)

func TestParseValidCedar(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
    principal,
    action == Action::"FileOpen",
    resource == Dir::"/tmp"
);

forbid (
    principal,
    action == Action::"ProcessExec",
    resource == File::"/bin/sh"
);
`
	path := writeTempCedar(t, cedar)
	cfg, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.LSMPolicies == nil {
		t.Fatal("expected LSMPolicies to be populated")
	}
	if len(cfg.LSMPolicies.Open) != 1 {
		t.Fatalf("expected one open rule, got %d", len(cfg.LSMPolicies.Open))
	}
	if len(cfg.LSMPolicies.Exec) != 1 {
		t.Fatalf("expected one exec rule, got %d", len(cfg.LSMPolicies.Exec))
	}
	if len(cfg.LSMPolicies.Connect) != 0 {
		t.Fatalf("expected no connect rules, got %d", len(cfg.LSMPolicies.Connect))
	}
}

func TestParseUnknownIdentifier(t *testing.T) {
	t.Parallel()

	cedar := `
permit (
    principal,
    action == Action::"FileOpen",
    resource
)
when { missingVar == true };
`
	path := writeTempCedar(t, cedar)
	_, err := Parse(path)
	if err == nil {
		t.Fatal("expected Parse to fail for unknown identifier")
	}
	detail, ok := err.(*cedarutil.ErrorDetail)
	if !ok {
		t.Fatalf("expected *cedar.ErrorDetail error, got %T", err)
	}
	if !strings.Contains(strings.ToLower(detail.Message), "invalid primary") {
		t.Fatalf("expected invalid primary message, got %q", detail.Message)
	}
	if strings.TrimSpace(detail.Suggestion) == "" {
		t.Fatal("expected suggestion to be populated")
	}
}

func writeTempCedar(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.cedar")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp Cedar file: %v", err)
	}
	return path
}

func TestManagerDedupeConnectRules(t *testing.T) {
	t.Parallel()

	mgr := NewManager(nil, func(*lsm.PolicySet, []proxy.HeaderRewriteRule) {})

	allowAny := lsm.PolicyRule{Action: lsm.PolicyAllow, Operation: lsm.OpConnect}
	copy(allowAny.Hostname[:], "*")
	allowAny.HostnameLen = 1

	denyHost := lsm.PolicyRule{Action: lsm.PolicyDeny, Operation: lsm.OpConnect}
	copy(denyHost.Hostname[:], "www.facebook.com")
	denyHost.HostnameLen = int32(len("www.facebook.com"))

	fileSet := &lsm.PolicySet{Connect: []lsm.PolicyRule{allowAny, allowAny}}
	runtimeSet := &lsm.PolicySet{Connect: []lsm.PolicyRule{denyHost, denyHost}}

	if err := mgr.UpdateFileRules(fileSet, nil); err != nil {
		t.Fatalf("UpdateFileRules: %v", err)
	}
	if err := mgr.SetRuntimeRules(runtimeSet, nil); err != nil {
		t.Fatalf("SetRuntimeRules: %v", err)
	}

	active, _ := mgr.GetActiveRules()
	if len(active.Connect) != 2 {
		t.Fatalf("expected 2 connect rules after dedupe, got %d", len(active.Connect))
	}
	if active.Connect[0].Action != lsm.PolicyDeny {
		t.Fatalf("expected deny rule first, got action %d", active.Connect[0].Action)
	}
	if host := string(active.Connect[0].Hostname[:active.Connect[0].HostnameLen]); host != "www.facebook.com" {
		t.Fatalf("unexpected host %q", host)
	}
	if active.Connect[1].Action != lsm.PolicyAllow {
		t.Fatalf("expected allow rule second, got action %d", active.Connect[1].Action)
	}
	if host := string(active.Connect[1].Hostname[:active.Connect[1].HostnameLen]); host != "*" {
		t.Fatalf("unexpected host %q", host)
	}
}
