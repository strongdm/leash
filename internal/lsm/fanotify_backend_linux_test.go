//go:build linux

package lsm

import "testing"

func TestFanotifyBackendAllowOpen(t *testing.T) {
	backend, err := newFanotifyBackend("/sys/fs/cgroup/test", nil)
	if err != nil {
		t.Fatalf("newFanotifyBackend: %v", err)
	}

	policies := &PolicySet{
		Open: []PolicyRule{
			mustPolicyRule(t, "deny file.open /"),
			mustPolicyRule(t, "allow file.open /workspace/project"),
		},
	}
	if err := backend.UpdatePolicies(policies); err != nil {
		t.Fatalf("UpdatePolicies: %v", err)
	}

	if !backend.allowOpen("/workspace/project/README.md") {
		t.Fatalf("expected allow for matching allow rule")
	}
	if backend.allowOpen("/etc/passwd") {
		t.Fatalf("expected deny from root default rule")
	}
}

func TestFanotifyBackendAllowExecArgumentBlacklist(t *testing.T) {
	backend, err := newFanotifyBackend("/sys/fs/cgroup/test", nil)
	if err != nil {
		t.Fatalf("newFanotifyBackend: %v", err)
	}

	policies := &PolicySet{
		Exec: []PolicyRule{
			mustPolicyRule(t, "allow proc.exec /usr/bin/"),
			mustPolicyRule(t, "deny proc.exec /usr/bin/curl --insecure"),
		},
	}
	if err := backend.UpdatePolicies(policies); err != nil {
		t.Fatalf("UpdatePolicies: %v", err)
	}

	if !backend.allowExec("/usr/bin/curl", []string{"curl", "--silent"}) {
		t.Fatalf("expected allow for non-blacklisted args")
	}
	if backend.allowExec("/usr/bin/curl", []string{"curl", "--insecure"}) {
		t.Fatalf("expected deny for blacklisted arg")
	}
}

func mustPolicyRule(t *testing.T, line string) PolicyRule {
	t.Helper()
	rule, err := ParseRuleString(line)
	if err != nil {
		t.Fatalf("ParseRuleString(%q): %v", line, err)
	}
	return *rule
}
