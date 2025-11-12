package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/strongdm/leash/internal/entrypoint"
)

const (
	shareRoot       = "/leash"
	readyFilePath   = shareRoot + "/" + entrypoint.ReadyFileName
	cgroupPathFile  = shareRoot + "/cgroup-path"
	selfCgroupPath  = "/proc/self/cgroup"
	bootstrapPath   = shareRoot + "/" + entrypoint.BootstrapReadyFileName
	daemonReadyPath = shareRoot + "/" + entrypoint.DaemonReadyFileName
	caCertPath      = shareRoot + "/ca-cert.pem"
)

func main() {
	_ = os.Remove(bootstrapPath)
	_ = os.Remove(daemonReadyPath)

	for {
		if _, err := os.Stat(readyFilePath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Check for /leash root directory
	if _, err := os.Stat(shareRoot); os.IsNotExist(err) {
		os.Stderr.WriteString("leash-error: /leash root directory does not exist\n")
		os.Exit(1)
	}

	if err := emitCgroupPath(); err != nil {
		os.Stderr.WriteString("leash-error: failed to record cgroup path: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		// Check if sudo is available
		if _, err := exec.LookPath("sudo"); err != nil {
			os.Stderr.WriteString("leash-error: must run as root or have sudo available\n")
			os.Exit(1)
		}
	}

	// Check if update-ca-certificates/update-ca-trust is available
	var updateCommand string = "update-ca-certificates"
	var certBasePath string = "/usr/local/share/ca-certificates"
	if _, err := exec.LookPath("update-ca-certificates"); err != nil {
		if _, err := exec.LookPath("update-ca-trust"); err != nil {
			os.Stderr.WriteString("leash-error: update-ca-trust or update-ca-certificates not found\n")
			os.Exit(1)
		}
		updateCommand = "update-ca-trust"
		certBasePath = "/etc/pki/ca-trust/source/anchors"
	}

	os.Stderr.WriteString("leash-entry: waiting for leash certificate\n")

	// Poll for CA certificate
	caCertFile := caCertPath
	for {
		if _, err := os.Stat(caCertFile); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// TODO: install cert as call to self with sudo
	// TODO: support more than alpine

	// Copy CA cert to system certificates directory
	os.Stderr.WriteString("leash-entry: installing CA certificate\n")
	var copyCmd *exec.Cmd
	if os.Geteuid() == 0 {
		copyCmd = exec.Command("cp", caCertFile, filepath.Join(certBasePath, "leash-ca.crt"))
	} else {
		copyCmd = exec.Command("sudo", "cp", caCertFile, filepath.Join(certBasePath, "leash-ca.crt"))
	}
	copyCmd.Stdout = os.Stdout
	copyCmd.Stderr = os.Stderr
	if err := copyCmd.Run(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Stderr.WriteString("leash-error: failed to copy CA certificate\n")
		os.Exit(1)
	}

	// Run update-ca-certificates
	os.Stderr.WriteString("leash-entry: updating CA certificates\n")
	var updateCmd *exec.Cmd
	if os.Geteuid() == 0 {
		updateCmd = exec.Command(updateCommand)
	} else {
		updateCmd = exec.Command("sudo", updateCommand)
	}
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr
	if err := updateCmd.Run(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Stderr.WriteString("leash-error: failed to update CA certificates\n")
		os.Exit(1)
	}

	if err := writeBootstrapMarker(); err != nil {
		os.Stderr.WriteString("leash-error: failed to signal bootstrap completion: " + err.Error() + "\n")
		os.Exit(1)
	}

	os.Stderr.WriteString("leash-entry: waiting for daemon activation\n")
	if err := waitForDaemonReady(); err != nil {
		os.Stderr.WriteString("leash-error: daemon activation did not complete: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Get command arguments (skip the program name)
	targetArgs := resolveTargetArgs(os.Args[1:])

	// If no arguments provided, exit
	if len(targetArgs) == 0 {
		runIdleLoop()
		return
	}

	os.Stderr.WriteString("leash-entry: command exec\n")

	// Resolve the executable path
	execPath, err := exec.LookPath(targetArgs[0])
	if err != nil {
		os.Stderr.WriteString("leash-error: failed to find executable: " + err.Error() + "\n")
		os.Exit(1)
	}
	targetArgs[0] = execPath

	// Use syscall.Exec to replace current process with the target command
	err = syscall.Exec(targetArgs[0], targetArgs, os.Environ())
	if err != nil {
		os.Stderr.WriteString("leash-error: failed to exec: " + err.Error() + "\n")
		os.Exit(1)
	}
}

func resolveTargetArgs(fallback []string) []string {
	if raw := strings.TrimSpace(os.Getenv("LEASH_ENTRY_COMMAND_B64")); raw != "" {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err == nil {
			var parts []string
			if json.Unmarshal(decoded, &parts) == nil && len(parts) > 0 {
				return parts
			}
		}
	}
	return fallback
}

func runIdleLoop() {
	// Stay idle inside this process so policy rules that deny shell binaries do
	// not terminate the container.
	os.Stderr.WriteString("leash-entry: entering idle wait\n")
	for {
		time.Sleep(24 * time.Hour)
	}
}

func writeBootstrapMarker() error {
	host, _ := os.Hostname()
	payload := map[string]any{
		"pid":       os.Getpid(),
		"hostname":  host,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal bootstrap payload: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(bootstrapPath)
	if err := os.MkdirAll(dir, 0o755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("ensure bootstrap dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "bootstrap.ready.*")
	if err != nil {
		return fmt.Errorf("create temp marker: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write marker: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync marker: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close marker: %w", err)
	}
	if err := os.Rename(tmpName, bootstrapPath); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("commit marker: %w", err)
	}
	return nil
}

func waitForDaemonReady() error {
	timeout := daemonReadyTimeout()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(daemonReadyPath); err == nil {
			return nil
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s", timeout, daemonReadyPath)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func daemonReadyTimeout() time.Duration {
	const defaultTimeout = 30 * time.Second
	raw := strings.TrimSpace(os.Getenv("LEASH_BOOTSTRAP_TIMEOUT"))
	if raw == "" {
		return defaultTimeout
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return defaultTimeout
}

func emitCgroupPath() error {
	data, err := os.ReadFile(selfCgroupPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", selfCgroupPath, err)
	}

	lines := strings.Split(string(data), "\n")
	var resolved string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		var raw string
		switch len(parts) {
		case 0:
			continue
		case 1:
			raw = parts[0]
		default:
			raw = parts[len(parts)-1]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" || raw == "/" || raw == "." {
			continue
		}
		if !strings.HasPrefix(raw, "/") {
			raw = "/" + raw
		}
		var candidate string
		if strings.HasPrefix(raw, "/sys/") {
			candidate = filepath.Clean(raw)
		} else {
			candidate = filepath.Clean(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(raw, "/")))
		}
		if candidate != "" {
			resolved = candidate
			break
		}
	}

	if resolved == "" {
		return fmt.Errorf("cgroup path not detected; ensure container runs with --cgroupns host")
	}

	if err := os.WriteFile(cgroupPathFile, []byte(resolved+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", cgroupPathFile, err)
	}

	return nil
}
