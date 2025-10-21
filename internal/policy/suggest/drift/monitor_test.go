package drift

import "testing"

func TestDetectFlagsDriftWhenPSIHigh(t *testing.T) {
	expected := map[string]float64{
		"filesystem:open": 0.4,
		"network:connect": 0.4,
		"process:exec":    0.2,
	}
	observed := map[string]float64{
		"filesystem:open": 0.1,
		"network:connect": 0.7,
		"process:exec":    0.2,
	}

	result := Detect(expected, observed, 0.2)
	if !result.IsDrift {
		t.Fatalf("expected drift detection, PSI %.3f", result.PSI)
	}
	if len(result.TopContributors) == 0 {
		t.Fatalf("expected contributors")
	}
}
