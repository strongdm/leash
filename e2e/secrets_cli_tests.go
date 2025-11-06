package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSecretsCLIRegistersPlaceholders(t *testing.T) {
	t.Parallel()
	skipUnlessE2E(t)

	leashBin := ensureLeashBinary(t)
	repoRoot, err := moduleRoot()
	if err != nil {
		t.Fatalf("determine module root: %v", err)
	}

	uiPort := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, leashBin,
		"-I",
		"--listen", fmt.Sprintf("127.0.0.1:%s", uiPort),
		"-s", "API_TOKEN=supersecret",
		"-s", "FOO=topsecret",
		"--", "sleep", "300",
	)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("LEASH_E2E=%s", os.Getenv("LEASH_E2E")),
	)

	buf := newSafeBuffer()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	go io.Copy(buf, stdout)
	go io.Copy(buf, stderr)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start leash runner: %v", err)
	}

	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	defer func() {
		_ = cmd.Process.Kill()
		select {
		case <-cmdDone:
		case <-time.After(5 * time.Second):
		}
		names := parseContainerNames(buf.String())
		if names.target != "" {
			_ = exec.Command("docker", "rm", "-f", names.target).Run()
		}
		if names.leash != "" {
			_ = exec.Command("docker", "rm", "-f", names.leash).Run()
		}
	}()

	controlPort, err := waitForControlPort(ctx, buf, cmdDone)
	if err != nil {
		t.Fatalf("wait for control port: %v\noutput:\n%s", err, buf.String())
	}

	apiBase := fmt.Sprintf("http://127.0.0.1:%d", controlPort)
	if err := waitForAPI(ctx, apiBase); err != nil {
		t.Fatalf("wait for API readiness: %v\noutput:\n%s", err, buf.String())
	}

	secretsResp := fetchSecrets(t, apiBase)
	apiToken := secretsResp["API_TOKEN"]
	fooSecret := secretsResp["FOO"]
	if apiToken.Placeholder == "" || fooSecret.Placeholder == "" {
		t.Fatalf("expected non-empty placeholders from API, got %+v", secretsResp)
	}
	if apiToken.Placeholder == "supersecret" || fooSecret.Placeholder == "topsecret" {
		t.Fatal("placeholders must not match raw secret values")
	}

	names := waitForContainerNames(ctx, buf, cmdDone)
	if names.target == "" {
		t.Fatalf("target container not detected\noutput:\n%s", buf.String())
	}

	envOutput := execContainerEnv(t, ctx, names.target)
	if strings.Contains(envOutput, "supersecret") || strings.Contains(envOutput, "topsecret") {
		t.Fatalf("env output leaked raw secrets:\n%s", envOutput)
	}

	expect := map[string]string{
		"API_TOKEN": apiToken.Placeholder,
		"FOO":       fooSecret.Placeholder,
	}
	for key, placeholder := range expect {
		line := fmt.Sprintf("%s=%s", key, placeholder)
		if !strings.Contains(envOutput, line) {
			t.Fatalf("expected env output to contain %q; output:\n%s", line, envOutput)
		}
	}
}

func fetchSecrets(t *testing.T, base string) map[string]secretEntry {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/api/secrets", base))
	if err != nil {
		t.Fatalf("fetch secrets: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("fetch secrets status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var decoded map[string]secretEntry
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode secrets response: %v", err)
	}
	return decoded
}

func waitForContainerNames(ctx context.Context, buf *safeBuffer, done <-chan error) containerNames {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if names := parseContainerNames(buf.String()); names.target != "" && names.leash != "" {
			return names
		}
		select {
		case <-ctx.Done():
			return containerNames{}
		case err := <-done:
			if err != nil {
				return containerNames{}
			}
			return containerNames{}
		case <-ticker.C:
		}
	}
}

func execContainerEnv(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", "exec", container, "bash", "-lc",
		". /etc/profile.d/000-leash_env.sh && printf 'API_TOKEN=%s\\nFOO=%s\\n' \"$API_TOKEN\" \"$FOO\"",
	)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker exec env probe failed: %v\noutput:\n%s", err, buf.String())
	}
	return buf.String()
}
