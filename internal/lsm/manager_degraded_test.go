package lsm

import "testing"

// In degraded mode the LSM manager has no scopable cgroup (e.g. Docker Desktop
// Kubernetes, where the container's private cgroup namespace reports "0::/").
// It must skip kernel enforcement entirely rather than attempt to attach
// cgroup-scoped BPF programs (which would either fail to load or govern the
// whole host). See issue #67.
func TestUpdateRuntimeRulesSkippedWithoutCgroup(t *testing.T) {
	m := NewLSMManager("", nil)

	// A non-empty policy set: without the degraded-mode guard this would drive
	// updateOpenLSM into a real BPF attach.
	policies := &PolicySet{Open: []PolicyRule{{}}}
	if !policies.HasOpenPolicies() {
		t.Fatal("test setup: expected open policies")
	}

	if err := m.UpdateRuntimeRules(policies); err != nil {
		t.Fatalf("empty cgroup should skip LSM attach and return nil, got: %v", err)
	}
}
