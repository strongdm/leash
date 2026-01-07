package openflag

import "testing"

func TestIsTruthy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value    string
		expected bool
	}{
		{value: "", expected: false},
		{value: "0", expected: false},
		{value: "false", expected: false},
		{value: "nope", expected: false},
		{value: "1", expected: true},
		{value: "t", expected: true},
		{value: "T", expected: true},
		{value: "true", expected: true},
		{value: "TRUE", expected: true},
		{value: " True ", expected: true},
	}

	for _, tt := range tests {
		if got := IsTruthy(tt.value); got != tt.expected {
			t.Fatalf("IsTruthy(%q) = %v, want %v", tt.value, got, tt.expected)
		}
	}
}

func TestEnabledReadsEnvironment(t *testing.T) {
	// Avoid t.Parallel because environment variables are process-wide.
	t.Setenv("OPEN", "1")
	if !Enabled() {
		t.Fatalf("Enabled() = false with OPEN=1")
	}

	t.Setenv("OPEN", "t")
	if !Enabled() {
		t.Fatalf("Enabled() = false with OPEN=t")
	}

	t.Setenv("OPEN", "True")
	if !Enabled() {
		t.Fatalf("Enabled() = false with OPEN=True")
	}

	t.Setenv("OPEN", "0")
	if Enabled() {
		t.Fatalf("Enabled() = true with OPEN=0")
	}
}
