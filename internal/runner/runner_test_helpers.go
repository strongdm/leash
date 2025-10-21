package runner

import (
	"context"
	"io"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	origDockerExec := dockerExecWithInput
	dockerExecWithInput = func(context.Context, string, string, io.Reader) error {
		return nil
	}
	code := m.Run()
	dockerExecWithInput = origDockerExec
	os.Exit(code)
}
