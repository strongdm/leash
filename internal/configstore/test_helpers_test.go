package configstore

import (
	"os"
	"testing"
)

func testSetEnv(t *testing.T, key, value string) {
	t.Helper()
	prev, existed := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("set env %s: %v", key, err)
	}
	t.Cleanup(func() {
		if !existed {
			_ = os.Unsetenv(key)
			return
		}
		if err := os.Setenv(key, prev); err != nil {
			t.Fatalf("restore env %s: %v", key, err)
		}
	})
}
