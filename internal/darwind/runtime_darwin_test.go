package darwind

import "testing"

func TestRunExecRequiresCommand(t *testing.T) {
	t.Parallel()

	if err := runExec(nil); err == nil {
		t.Fatalf("expected error when command missing")
	}
}
