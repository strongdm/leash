package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/entrypoint"
)

var (
	buildOnce   sync.Once
	leashBinary string
	buildErr    error
	bundleOnce  sync.Once // Run the bundle generation task at most one time.
	bundleErr   error
)

func ensureLeashBinary(t *testing.T) string {
	t.Helper()

	ensureEntrypointBundles(t)

	buildOnce.Do(func() {
		tmp := os.TempDir()
		out := filepath.Join(tmp, fmt.Sprintf("leash-e2e-%d", time.Now().UnixNano()))
		cmd := exec.Command("go", "build", "-o", out, "../cmd/leash")
		cmd.Env = append(os.Environ(), "GOFLAGS=-vet=off")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		buildErr = cmd.Run()
		if buildErr == nil {
			leashBinary = out
		} else {
			buildErr = fmt.Errorf("build leash binary: %w\n%s", buildErr, stderr.String())
		}
	})

	if buildErr != nil {
		t.Fatalf("failed to build leash binary: %v", buildErr)
	}
	return leashBinary
}

// ensureEntrypointBundles guarantees the daemon has embedded leash-entry blobs
// available. Clean checkouts omit the generated files, so we auto-run go
// generate and log a loud message explaining what is going on.
func ensureEntrypointBundles(t *testing.T) {
	t.Helper()

	bundleOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			bundleErr = err
			return
		}

		missing := missingBundleFiles(root)
		if len(missing) == 0 {
			return
		}

		var logMessage strings.Builder
		fmt.Fprintf(&logMessage, "NOTICE: entrypoint embed artifacts missing (%s);\nrunning `go generate ./internal/entrypoint` so e2e bootstrap can inflate leash-entry binaries", strings.Join(missing, ", "))

		cmd := exec.Command("go", "generate", "./internal/entrypoint")
		cmd.Env = os.Environ()
		cmd.Dir = root
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			bundleErr = fmt.Errorf("failed to generate entrypoint bundles: %w\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
			return
		}

		if followup := missingBundleFiles(root); len(followup) > 0 {
			bundleErr = fmt.Errorf("entrypoint bundles still missing after go generate: %v", followup)
			return
		}

		if stdout.Len() > 0 || stderr.Len() > 0 {
			fmt.Fprintf(&logMessage, "\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}

		t.Log(logMessage.String())
	})

	if bundleErr != nil {
		t.Fatalf("prepare entrypoint bundles: %v", bundleErr)
	}
}

func TestBootstrapHappyPath(t *testing.T) {
	skipUnlessE2E(t)
	bin := ensureLeashBinary(t)

	shareDir := t.TempDir()
	t.Logf("share dir: %s", shareDir)
	mustWrite(t, filepath.Join(shareDir, entrypoint.ReadyFileName), []byte("1\n"))

	cgroupDir := filepath.Join(t.TempDir(), "cgroup")
	mustCreateDir(t, cgroupDir)
	mustWrite(t, filepath.Join(cgroupDir, "cgroup.controllers"), []byte("memory\n"))

	policyPath := filepath.Join(t.TempDir(), "policy.cedar")
	mustWrite(t, policyPath, []byte(`permit (principal, action == Action::"FileOpen", resource)
when { resource in [ Dir::"/" ] };`))

	uiPort := freePort(t)
	proxyPort := freePort(t)

	cfg := daemonConfig{
		shareDir:   shareDir,
		cgroupDir:  cgroupDir,
		policyPath: policyPath,
		listenAddr: ":" + uiPort,
		proxyPort:  proxyPort,
		timeout:    15 * time.Second,
	}
	cmd, stdout, stderr := startDaemon(t, bin, cfg)
	defer terminateProcess(t, cmd, stdout, stderr)

	policyURL := fmt.Sprintf("http://127.0.0.1:%s/health/policy", uiPort)

	waitForPolicyStatus(t, policyURL, http.StatusServiceUnavailable, 10*time.Second)

	writeBootstrapMarker(t, shareDir, map[string]any{
		"pid":       os.Getpid(),
		"hostname":  "e2e-test",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
	assertFileExists(t, filepath.Join(shareDir, entrypoint.BootstrapReadyFileName))

	waitForPolicyStatus(t, policyURL, http.StatusOK, cfg.timeout+5*time.Second)
}

func TestBootstrapIgnoresStaleMarker(t *testing.T) {
	skipUnlessE2E(t)

	bin := ensureLeashBinary(t)

	shareDir := t.TempDir()
	mustWrite(t, filepath.Join(shareDir, entrypoint.ReadyFileName), []byte("1\n"))
	writeBootstrapMarker(t, shareDir, map[string]any{
		"pid":       1234,
		"hostname":  "stale-node",
		"timestamp": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
	})

	cgroupDir := filepath.Join(t.TempDir(), "cgroup")
	mustCreateDir(t, cgroupDir)
	mustWrite(t, filepath.Join(cgroupDir, "cgroup.controllers"), []byte("memory\n"))

	policyPath := filepath.Join(t.TempDir(), "policy.cedar")
	mustWrite(t, policyPath, []byte(`permit (principal, action == Action::"FileOpen", resource)
when { resource in [ Dir::"/" ] };`))

	uiPort := freePort(t)
	proxyPort := freePort(t)

	cfg := daemonConfig{
		shareDir:   shareDir,
		cgroupDir:  cgroupDir,
		policyPath: policyPath,
		listenAddr: ":" + uiPort,
		proxyPort:  proxyPort,
		timeout:    10 * time.Second,
	}
	cmd, stdout, stderr := startDaemon(t, bin, cfg)
	defer terminateProcess(t, cmd, stdout, stderr)

	policyURL := fmt.Sprintf("http://127.0.0.1:%s/health/policy", uiPort)

	waitForPolicyStatus(t, policyURL, http.StatusServiceUnavailable, 10*time.Second)

	time.Sleep(2 * time.Second)
	status, err := currentPolicyStatus(policyURL)
	if err != nil {
		t.Fatalf("failed to query policy status: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("expected daemon to remain in staging, got status %d", status)
	}

	writeBootstrapMarker(t, shareDir, map[string]any{
		"pid":       os.Getpid(),
		"hostname":  "fresh-node",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})

	waitForPolicyStatus(t, policyURL, http.StatusOK, cfg.timeout+5*time.Second)
}

func TestBootstrapTimeout(t *testing.T) {
	skipUnlessE2E(t)

	bin := ensureLeashBinary(t)

	shareDir := t.TempDir()
	mustWrite(t, filepath.Join(shareDir, entrypoint.ReadyFileName), []byte("1\n"))

	cgroupDir := filepath.Join(t.TempDir(), "cgroup")
	mustCreateDir(t, cgroupDir)
	mustWrite(t, filepath.Join(cgroupDir, "cgroup.controllers"), []byte("memory\n"))

	policyPath := filepath.Join(t.TempDir(), "policy.cedar")
	mustWrite(t, policyPath, []byte(`permit (principal, action == Action::"FileOpen", resource)
when { resource in [ Dir::"/" ] };`))

	uiPort := freePort(t)
	proxyPort := freePort(t)

	cmd, stdout, stderr := startDaemon(t, bin, daemonConfig{
		shareDir:   shareDir,
		cgroupDir:  cgroupDir,
		policyPath: policyPath,
		listenAddr: ":" + uiPort,
		proxyPort:  proxyPort,
		timeout:    2 * time.Second,
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-waitCtx.Done():
		terminateProcess(t, cmd, stdout, stderr)
		t.Fatalf("daemon did not exit within timeout; stdout=%s stderr=%s", stdout.String(), stderr.String())
	case err := <-done:
		if err == nil {
			t.Fatalf("expected bootstrap timeout to produce non-zero exit; stdout=%s stderr=%s", stdout.String(), stderr.String())
		}
	}
}

func TestRunnerPrivateMountIsolation(t *testing.T) {
	skipUnlessE2E(t)

	bin := ensureLeashBinary(t)
	shareDir := t.TempDir()
	policyPath := filepath.Join(t.TempDir(), "policy.cedar")
	mustWrite(t, policyPath, []byte(`permit (principal, action == Action::"ProcessLaunch", resource)
when { resource in [ Process::"/bin/sh" ] };`))

	targetName := fmt.Sprintf("leash-e2e-target-%d", time.Now().UnixNano())
	leashName := fmt.Sprintf("leash-e2e-manager-%d", time.Now().UnixNano())

	cmd := exec.Command("timeout", "135", bin, "--", "sleep", "40")
	cmd.Env = append(os.Environ(),
		"TARGET_CONTAINER="+targetName,
		"LEASH_CONTAINER="+leashName,
		"LEASH_SHARE_DIR="+shareDir,
		"LEASH_POLICY_FILE="+policyPath,
		"LEASH_BOOTSTRAP_TIMEOUT=30s",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start leash runner: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}

	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
		case <-done:
		}
		dockerRmForced(t, targetName, leashName)
	}()

	waitForContainerRunning(t, targetName, 60*time.Second)
	waitForContainerRunning(t, leashName, 60*time.Second)

	bootstrapMarker := filepath.Join(shareDir, entrypoint.BootstrapReadyFileName)
	waitForHostFile(t, bootstrapMarker, 30*time.Second)

	envOutput := dockerExecOutput(t, targetName, "env")
	if strings.Contains(envOutput, "LEASH_PRIVATE_DIR=") {
		t.Fatalf("target container unexpectedly received LEASH_PRIVATE_DIR env; env=%q", envOutput)
	}
	if !strings.Contains(envOutput, "LEASH_DIR=/leash") {
		t.Fatalf("target container missing LEASH_DIR env; env=%q", envOutput)
	}

	if exitCode := dockerExecExitCode(t, targetName, "sh", "-c", "test -d /leash-private"); exitCode == 0 {
		t.Fatalf("expected /leash-private to be absent from target container")
	}
	if exitCode := dockerExecExitCode(t, targetName, "sh", "-c", "test -f /leash/ca-key.pem"); exitCode == 0 {
		t.Fatalf("expected /leash/ca-key.pem to be inaccessible in target container")
	}

	if exitCode := dockerExecExitCode(t, leashName, "sh", "-c", "test -f /leash-private/ca-key.pem"); exitCode != 0 {
		t.Fatalf("manager container missing private key; exit=%d", exitCode)
	}

	if exitCode := dockerExecExitCode(t, targetName, "curl", "-sS", "https://example.com", "-o", "/dev/null"); exitCode != 0 {
		t.Fatalf("curl inside target container failed; exit=%d", exitCode)
	}

	waitForManagerLog(t, leashName, "event=http.request", 30*time.Second)
}

func TestDaemonFailsWhenPrivateDirIsNotDirectory(t *testing.T) {
	skipUnlessE2E(t)

	bin := ensureLeashBinary(t)

	shareDir := t.TempDir()
	mustWrite(t, filepath.Join(shareDir, entrypoint.ReadyFileName), []byte("1\n"))

	privateFile := filepath.Join(t.TempDir(), "private-file")
	mustWrite(t, privateFile, []byte("nope"))

	cgroupDir := filepath.Join(t.TempDir(), "cgroup")
	mustCreateDir(t, cgroupDir)
	mustWrite(t, filepath.Join(cgroupDir, "cgroup.controllers"), []byte("memory\n"))

	policyPath := filepath.Join(t.TempDir(), "policy.cedar")
	mustWrite(t, policyPath, []byte(`permit (principal, action == Action::"FileOpen", resource)
when { resource in [ Dir::"/" ] };`))

	cmd, stdout, stderr := startDaemon(t, bin, daemonConfig{
		shareDir:   shareDir,
		privateDir: privateFile,
		cgroupDir:  cgroupDir,
		policyPath: policyPath,
		listenAddr: ":" + freePort(t),
		proxyPort:  freePort(t),
		timeout:    5 * time.Second,
	})

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-time.After(15 * time.Second):
		terminateProcess(t, cmd, stdout, stderr)
		t.Fatalf("daemon did not exit despite invalid private dir; stdout=%s stderr=%s", stdout.String(), stderr.String())
	case err := <-done:
		if err == nil {
			t.Fatalf("expected daemon to fail when private dir is file; stdout=%s stderr=%s", stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "LEASH_PRIVATE_DIR") {
			t.Fatalf("expected stderr to mention LEASH_PRIVATE_DIR; stderr=%s", stderr.String())
		}
	}
}

type daemonConfig struct {
	shareDir   string
	privateDir string
	cgroupDir  string
	policyPath string
	listenAddr string
	proxyPort  string
	timeout    time.Duration
}

func startDaemon(t *testing.T, bin string, cfg daemonConfig) (*exec.Cmd, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()

	if cfg.privateDir == "" {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatalf("failed to chmod private dir: %v", err)
		}
		cfg.privateDir = dir
	}

	logPath := filepath.Join(t.TempDir(), "daemon.log")
	cmd := exec.Command(
		bin,
		"--daemon",
		"--policy", cfg.policyPath,
		"--cgroup", cfg.cgroupDir,
		"--proxy-port", cfg.proxyPort,
		"--listen", cfg.listenAddr,
	)

	env := append(os.Environ(),
		"LEASH_DIR="+cfg.shareDir,
		"LEASH_PRIVATE_DIR="+cfg.privateDir,
		"LEASH_BOOTSTRAP_SKIP_ENFORCE=1",
		"LEASH_E2E=1",
		fmt.Sprintf("LEASH_BOOTSTRAP_TIMEOUT=%s", cfg.timeout),
		"LEASH_LOG="+logPath,
		fmt.Sprintf("LEASH_LISTEN=%s", cfg.listenAddr),
	)
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start daemon: %v (stdout=%s stderr=%s)", err, stdout.String(), stderr.String())
	}

	t.Cleanup(func() {
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Logf("daemon stdout:\n%s", stdout.String())
			t.Logf("daemon stderr:\n%s", stderr.String())
			t.Logf("daemon log:\n%s", string(data))
			entries, _ := os.ReadDir(cfg.shareDir)
			for _, e := range entries {
				info := ""
				if stat, err := e.Info(); err == nil {
					info = fmt.Sprintf(" (size=%d mod=%s)", stat.Size(), stat.ModTime().UTC().Format(time.RFC3339Nano))
				}
				t.Logf("share file: %s%s", e.Name(), info)
			}
		}
	})

	return cmd, &stdout, &stderr
}

func terminateProcess(t *testing.T, cmd *exec.Cmd, stdout, stderr *bytes.Buffer) {
	t.Helper()
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("process did not exit gracefully; stdout=%s stderr=%s", stdout.String(), stderr.String())
	case <-done:
	}
}

func waitForPolicyStatus(t *testing.T, url string, want int, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{Timeout: 1 * time.Second}
	defer client.CloseIdleConnections()

	readinessCheck := func() bool {
		resp, err := client.Get(url) // #nosec G107 -- local test server
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == want
	}

	if err := pollReadiness(ctx, timeout, readinessCheck); err != nil {
		t.Fatalf("timed out waiting for status %d at %s", want, url)
	}
}

func currentPolicyStatus(url string) (int, error) {
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	return strconv.Itoa(port)
}

func writeBootstrapMarker(t *testing.T, shareDir string, payload map[string]any) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal bootstrap payload: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(shareDir, entrypoint.BootstrapReadyFileName)
	tmp, err := os.CreateTemp(shareDir, "bootstrap.ready.*")
	if err != nil {
		t.Fatalf("create temp marker: %v", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		t.Fatalf("write temp marker: %v", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		t.Fatalf("sync temp marker: %v", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		t.Fatalf("close temp marker: %v", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		t.Fatalf("rename marker: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("bootstrap marker not found after write: %v", err)
	}
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("expected file %s to exist: %v", path, err)
	} else {
		t.Logf("observed file %s (size=%d mod=%s)", path, info.Size(), info.ModTime().UTC().Format(time.RFC3339Nano))
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustCreateDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func skipUnlessE2E(t *testing.T) {
	t.Helper()
	if !envTruthy(os.Getenv("LEASH_E2E")) {
		t.Skip("set LEASH_E2E=1 to run end-to-end tests")
	}
}

func envTruthy(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("determine working directory: %w", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate module root containing go.mod (start=%s)", dir)
		}
		dir = parent
	}
}

func missingBundleFiles(root string) []string {
	targets := []string{
		filepath.Join("internal", "entrypoint", "bundled_linux_amd64_gen.go"),
		filepath.Join("internal", "entrypoint", "bundled_linux_arm64_gen.go"),
	}

	var missing []string
	for _, rel := range targets {
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			missing = append(missing, rel)
		}
	}
	return missing
}

func runDockerCommand(t *testing.T, timeout time.Duration, args ...string) ([]byte, int, error) {
	t.Helper()
	seconds := int(timeout / time.Second)
	if seconds <= 0 {
		seconds = 1
	}
	cmdArgs := append([]string{fmt.Sprintf("%d", seconds), "docker"}, args...)
	cmd := exec.Command("timeout", cmdArgs...)
	output, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return output, -1, err
		}
	}
	return output, exitCode, err
}

func dockerExecOutput(t *testing.T, container string, args ...string) string {
	cmdArgs := append([]string{"exec", container}, args...)
	out, exit, err := runDockerCommand(t, 30*time.Second, cmdArgs...)
	if err != nil && exit != 0 {
		t.Fatalf("docker exec %s failed: %v (output=%s)", strings.Join(cmdArgs, " "), err, string(out))
	}
	return string(out)
}

func dockerExecExitCode(t *testing.T, container string, args ...string) int {
	cmdArgs := append([]string{"exec", container}, args...)
	_, exit, err := runDockerCommand(t, 30*time.Second, cmdArgs...)
	if err != nil && exit == -1 {
		t.Fatalf("docker exec %s returned error: %v", strings.Join(cmdArgs, " "), err)
	}
	return exit
}

func dockerRmForced(t *testing.T, names ...string) {
	if len(names) == 0 {
		return
	}
	args := append([]string{"rm", "-f"}, names...)
	_, _, _ = runDockerCommand(t, 30*time.Second, args...)
}

func waitForContainerRunning(t *testing.T, name string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	readinessCheck := func() bool {
		out, exit, err := runDockerCommand(t, 10*time.Second, "inspect", "-f", "{{.State.Status}}", name)
		if err == nil && exit == 0 {
			status := strings.TrimSpace(string(out))
			if status == "running" {
				return true
			}
		}
		return false
	}

	if err := pollReadiness(ctx, timeout, readinessCheck); err != nil {
		t.Fatalf("container %s did not reach running state within %s", name, timeout)
	}
}

func waitForHostFile(t *testing.T, path string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	readinessCheck := func() bool {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return true
		}
		return false
	}

	if err := pollReadiness(ctx, timeout, readinessCheck); err != nil {
		t.Fatalf("timed out waiting for host file %s", path)
	}
}

func waitForManagerLog(t *testing.T, container, needle string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	readinessCheck := func() bool {
		_, exit, _ := runDockerCommand(t, 10*time.Second, "exec", container, "sh", "-c", fmt.Sprintf("grep -q %q /log/events.log", needle))
		return exit == 0
	}

	if err := pollReadiness(ctx, timeout, readinessCheck); err != nil {
		t.Fatalf("timed out waiting for %q in manager logs", needle)
	}
}
