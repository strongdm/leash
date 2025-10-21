package configstore

import "testing"

func TestMergeEnvLayersPrecedence(t *testing.T) {
	t.Parallel()

	layers := []EnvLayer{
		{
			Specs: map[string]string{"FOO": "FOO=auto", "BAR": "BAR=auto"},
			Order: []string{"FOO", "BAR"},
		},
		{
			Specs: map[string]string{"BAR": "BAR=global", "BAZ": "BAZ=global"},
			Order: []string{"BAR", "BAZ"},
		},
		{
			Specs: map[string]string{"BAR": "BAR=project"},
			Order: []string{"BAR"},
		},
		{
			Specs: map[string]string{"FOO": "FOO=cli", "ZED": "ZED=cli"},
			Order: []string{"FOO", "ZED"},
		},
	}

	got := MergeEnvLayers(layers...)
	want := []string{"BAZ=global", "BAR=project", "FOO=cli", "ZED=cli"}

	if len(got) != len(want) {
		t.Fatalf("result length mismatch: got %d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("spec %d mismatch: got %q want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}
