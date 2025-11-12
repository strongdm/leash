//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/entrypoint"
)

// TestControlUIHostAccessTargetDenied verifies that once the loopback policy is
// applied, a curl from the target container cannot reach the Control UI. The
// test intentionally waits for enforcement to take effect (curl retries until
// the connection is actually blocked) instead of relying on sleeps or assuming
// the policy is ready as soon as /healthz responds. Readiness polling removes
// the race that used to make the test flaky when the firewall rules were
// slightly delayed.
func TestControlUIHostAccessTargetDenied(t *testing.T) {
	skipUnlessE2E(t)

	bin := ensureLeashBinary(t)
	t.Logf("leash binary: %s", bin)

	shareDir := t.TempDir()
	mustWrite(t, filepath.Join(shareDir, entrypoint.ReadyFileName), []byte("1\n"))

	cgroupDir := filepath.Join(t.TempDir(), "cgroup")
	mustCreateDir(t, cgroupDir)
	mustWrite(t, filepath.Join(cgroupDir, "cgroup.controllers"), []byte("memory\n"))

	uiPort := freePort(t)
	proxyPort := freePort(t)
	listenAddr := ":" + uiPort

	policyPath := filepath.Join(t.TempDir(), "policy.cedar")
	policyBody := fmt.Sprintf(`permit (principal, action == Action::"ProcessLaunch", resource)
when { resource in [ Process::"/bin/sh" , Process::"/usr/bin/curl" ] };

permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"127.0.0.1:%s" ] };`, uiPort)
	mustWrite(t, policyPath, []byte(policyBody))

	targetName := fmt.Sprintf("leash-e2e-target-%d", time.Now().UnixNano())
	leashName := fmt.Sprintf("leash-e2e-manager-%d", time.Now().UnixNano())

	cmd := exec.Command("timeout", "135", bin, "--", "sleep", "60")
	cmd.Env = append(os.Environ(),
		"TARGET_CONTAINER="+targetName,
		"LEASH_CONTAINER="+leashName,
		"LEASH_SHARE_DIR="+shareDir,
		"LEASH_POLICY_FILE="+policyPath,
		"LEASH_BOOTSTRAP_TIMEOUT=45s",
		"LEASH_PROXY_PORT="+proxyPort,
		"LEASH_LISTEN="+listenAddr,
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

	healthURL := fmt.Sprintf("http://127.0.0.1:%s/healthz", uiPort)
	client := &http.Client{Timeout: 5 * time.Second}
	waitCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	readinessCheck := func() bool {
		resp, err := client.Get(healthURL)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}

	if err := pollReadiness(waitCtx, 60*time.Second, readinessCheck); err != nil {
		iptablesDump := dockerExecOutput(t, leashName, "sh", "-c", "iptables-save -t filter")
		t.Logf("manager filter table:\n%s", iptablesDump)
		iptablesOutput := dockerExecOutput(t, leashName, "sh", "-c", "iptables -w -S OUTPUT")
		t.Logf("iptables -S OUTPUT:\n%s", iptablesOutput)
		logOut, _, _ := runDockerCommand(t, 30*time.Second, "logs", leashName)
		t.Logf("manager logs:\n%s", string(logOut))
		t.Fatalf("timed out waiting for Control UI health at %s", healthURL)
	}

	curlCmd := fmt.Sprintf("curl --max-time 5 -sS -o /dev/null %s", healthURL)
	enforced := false
	start := time.Now()
	for time.Since(start) < 15*time.Second {
		_, exit, _ := runDockerCommand(t, 10*time.Second, "exec", targetName, "sh", "-c", curlCmd)
		if exit != 0 {
			enforced = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !enforced {
		iptablesDump := dockerExecOutput(t, leashName, "sh", "-c", "iptables-save -t filter")
		t.Logf("manager filter table:\n%s", iptablesDump)
		iptablesOutput := dockerExecOutput(t, leashName, "sh", "-c", "iptables -w -S OUTPUT")
		t.Logf("iptables -S OUTPUT:\n%s", iptablesOutput)
		logOut, _, _ := runDockerCommand(t, 30*time.Second, "logs", leashName)
		t.Logf("manager logs:\n%s", string(logOut))
		loopbackEvents := dockerExecOutput(t, leashName, "sh", "-c", "grep -n loopback /log/events.log || true")
		t.Logf("loopback events:\n%s", loopbackEvents)
		nftRules := dockerExecOutput(t, leashName, "sh", "-c", "nft list chain inet leash_loopback out_filter || true")
		t.Logf("nft loopback chain:\n%s", nftRules)
		t.Fatalf("control UI remained reachable after %s", 15*time.Second)
	}

	iptablesDump := dockerExecOutput(t, leashName, "sh", "-c", "iptables-save -t filter")
	t.Logf("manager filter table:\n%s", iptablesDump)
	iptablesOutput := dockerExecOutput(t, leashName, "sh", "-c", "iptables -w -S OUTPUT")
	t.Logf("iptables -S OUTPUT:\n%s", iptablesOutput)
	logOut, _, _ := runDockerCommand(t, 30*time.Second, "logs", leashName)
	t.Logf("manager logs:\n%s", string(logOut))
	loopbackEvents := dockerExecOutput(t, leashName, "sh", "-c", "grep -n loopback /log/events.log || true")
	t.Logf("loopback events:\n%s", loopbackEvents)
	nftRules := dockerExecOutput(t, leashName, "sh", "-c", "nft list chain inet leash_loopback out_filter || true")
	t.Logf("nft loopback chain:\n%s", nftRules)

	targetArgs := []string{"exec", targetName, "sh", "-c", fmt.Sprintf("curl --max-time 5 -sS -o /dev/null %s", healthURL)}
	out, exitCode, err := runDockerCommand(t, 30*time.Second, targetArgs...)
	if err == nil && exitCode == 0 {
		t.Fatalf("target container unexpectedly reached Control UI (output=%s)", string(out))
	}
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code from target curl, got 0 (output=%s)", string(out))
	}
}
