package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type capturedRequest struct {
	path          string
	authorization string
	err           error
}

// TestSecretsProxyReplacesPlaceholders exercises the Leash
// HTTP proxy secrets placeholder replacement functionality.
func TestSecretsProxyReplacesPlaceholders(t *testing.T) {
	t.Parallel()
	skipUnlessE2E(t)

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("determine repo root: %v", err)
	}

	leashBin := filepath.Join(repoRoot, "bin", "leash")
	if _, err := os.Stat(leashBin); err != nil {
		t.Fatalf("leash binary not found at %s", leashBin)
	}

	hostIP, err := detectHostIP(t)
	if err != nil {
		t.Fatalf("detect host IP: %v", err)
	}

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen for proxy request: %v", err)
	}
	defer listener.Close()
	proxyPort := listener.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, leashBin, "-I", "sleep", "300")
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
		t.Fatalf("start leash: %v", err)
	}

	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	defer func() {
		_ = cmd.Process.Kill()
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
		t.Fatalf("detect control port: %v\noutput:\n%s", err, buf.String())
	}
	apiBase := fmt.Sprintf("http://127.0.0.1:%d", controlPort)

	if err := waitForAPI(ctx, apiBase); err != nil {
		t.Fatalf("waiting for API ready: %v\noutput:\n%s", err, buf.String())
	}

	secretID := "e2e_secret"
	secretValue := "12345678901234567890"
	placeholder, err := createSecret(apiBase, secretID, secretValue)
	if err != nil {
		t.Fatalf("create secret: %v\noutput:\n%s", err, buf.String())
	}

	names := parseContainerNames(buf.String())
	if names.target == "" {
		t.Fatalf("failed to detect target container name in output:\n%s", buf.String())
	}

	captureCh := make(chan capturedRequest, 1)
	go captureHTTP(listener, captureCh)

	curlCmd := exec.CommandContext(ctx,
		"docker", "exec", names.target,
		"bash", "-lc",
		fmt.Sprintf("timeout 60 curl -sv http://%s:%d/%s -H 'Authorization: %s'",
			hostIP, proxyPort, placeholder, placeholder),
	)
	var curlBuf bytes.Buffer
	curlCmd.Stdout = &curlBuf
	curlCmd.Stderr = &curlBuf
	if err := curlCmd.Run(); err != nil {
		t.Fatalf("proxy request failed: %v\ncurl output:\n%s", err, curlBuf.String())
	}

	var capture capturedRequest
	select {
	case capture = <-captureCh:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for listener capture")
	}
	if capture.err != nil {
		t.Fatalf("capture error: %v", capture.err)
	}
	if want := "/" + secretValue; capture.path != want {
		t.Fatalf("expected path %q, got %q", want, capture.path)
	}
	if capture.authorization != secretValue {
		t.Fatalf("expected authorization %q, got %q", secretValue, capture.authorization)
	}

	entry, err := fetchSecret(apiBase, secretID)
	if err != nil {
		t.Fatalf("fetch secret info: %v", err)
	}
	if entry.Value != secretValue {
		t.Fatalf("expected stored value %q, got %q", secretValue, entry.Value)
	}
	if entry.Activations < 2 {
		t.Fatalf("expected activations >= 2, got %d", entry.Activations)
	}
}

func TestNetConnectDecisionAllowedWithoutHTTPResponse(t *testing.T) {
	t.Parallel()
	skipUnlessE2E(t)

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("determine repo root: %v", err)
	}

	leashBin := filepath.Join(repoRoot, "bin", "leash")
	if _, err := os.Stat(leashBin); err != nil {
		t.Fatalf("leash binary not found at %s", leashBin)
	}

	workspaceDir, err := os.MkdirTemp("", "leash-e2e-net-*")
	if err != nil {
		t.Fatalf("create workspace dir: %v", err)
	}
	defer os.RemoveAll(workspaceDir)

	projectName := fmt.Sprintf("e2e-net-%d", time.Now().UnixNano())

	hostIP, err := detectHostIP(t)
	if err != nil {
		t.Fatalf("detect host IP: %v", err)
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(hostIP, "0"))
	if err != nil {
		t.Fatalf("listen for tcp test server: %v", err)
	}
	defer listener.Close()
	tcpPort := listener.Addr().(*net.TCPAddr).Port

	connAccepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
		select {
		case connAccepted <- struct{}{}:
		default:
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, leashBin, "-I", "sleep", "300")
	cmd.Dir = workspaceDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("LEASH_E2E=%s", os.Getenv("LEASH_E2E")),
		fmt.Sprintf("LEASH_PROJECT=%s", projectName),
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
		t.Fatalf("start leash: %v", err)
	}

	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	defer func() {
		_ = cmd.Process.Kill()
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
		t.Fatalf("detect control port: %v\noutput:\n%s", err, buf.String())
	}
	apiBase := fmt.Sprintf("http://127.0.0.1:%d", controlPort)

	if err := waitForAPI(ctx, apiBase); err != nil {
		t.Fatalf("waiting for API ready: %v\noutput:\n%s", err, buf.String())
	}

	names := parseContainerNames(buf.String())
	if names.target == "" || names.leash == "" {
		t.Fatalf("failed to detect container names from output:\n%s", buf.String())
	}

	curlCmd := exec.CommandContext(ctx,
		"docker", "exec", names.target,
		"sh", "-c",
		fmt.Sprintf("curl --max-time 5 -sS http://%s:%d/ || true", hostIP, tcpPort),
	)
	var curlBuf bytes.Buffer
	curlCmd.Stdout = &curlBuf
	curlCmd.Stderr = &curlBuf
	if err := curlCmd.Run(); err != nil {
		t.Fatalf("curl execution failed: %v\noutput:\n%s", err, curlBuf.String())
	}

	select {
	case <-connAccepted:
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for TCP listener to receive connection")
	}

	time.Sleep(1 * time.Second)

	logContent := readEventLog(t, names.leash)
	logLine, found := findHTTPLogLine(logContent, hostIP, tcpPort)
	if !found {
		t.Fatalf("no event log entry found for addr=\"%s:%d\".\nrecent log tail:\n%s", hostIP, tcpPort, tailLines(logContent, 200))
	}
	if !strings.Contains(logLine, "decision=allowed") {
		t.Fatalf("expected decision=allowed in log entry, got: %s", logLine)
	}
}

func TestNetConnectDecisionDeniedWhenPolicyBlocks(t *testing.T) {
	t.Parallel()
	skipUnlessE2E(t)

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("determine repo root: %v", err)
	}

	leashBin := filepath.Join(repoRoot, "bin", "leash")
	if _, err := os.Stat(leashBin); err != nil {
		t.Fatalf("leash binary not found at %s", leashBin)
	}

	workspaceDir, err := os.MkdirTemp("", "leash-e2e-net-deny-*")
	if err != nil {
		t.Fatalf("create workspace dir: %v", err)
	}
	defer os.RemoveAll(workspaceDir)

	projectName := fmt.Sprintf("e2e-net-deny-%d", time.Now().UnixNano())

	hostIP, err := detectHostIP(t)
	if err != nil {
		t.Fatalf("detect host IP: %v", err)
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(hostIP, "0"))
	if err != nil {
		t.Fatalf("listen for tcp test server: %v", err)
	}
	defer listener.Close()
	tcpPort := listener.Addr().(*net.TCPAddr).Port

	connAccepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
		select {
		case connAccepted <- struct{}{}:
		default:
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, leashBin, "-I", "sleep", "300")
	cmd.Dir = workspaceDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("LEASH_E2E=%s", os.Getenv("LEASH_E2E")),
		fmt.Sprintf("LEASH_PROJECT=%s", projectName),
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
		t.Fatalf("start leash: %v", err)
	}

	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	defer func() {
		_ = cmd.Process.Kill()
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
		t.Fatalf("detect control port: %v\noutput:\n%s", err, buf.String())
	}
	apiBase := fmt.Sprintf("http://127.0.0.1:%d", controlPort)

	if err := waitForAPI(ctx, apiBase); err != nil {
		t.Fatalf("waiting for API ready: %v\noutput:\n%s", err, buf.String())
	}

	names := parseContainerNames(buf.String())
	if names.target == "" || names.leash == "" {
		t.Fatalf("failed to detect container names from output:\n%s", buf.String())
	}

	cedar := fmt.Sprintf(`
permit (principal, action == Action::"ProcessExec", resource);
permit (principal, action == Action::"NetworkConnect", resource);
forbid (principal, action == Action::"NetworkConnect", resource == Host::"%s:%d");`, hostIP, tcpPort)
	applyPolicy(t, apiBase, cedar)

	time.Sleep(500 * time.Millisecond)

	curlCmd := exec.CommandContext(ctx,
		"docker", "exec", names.target,
		"sh", "-c",
		fmt.Sprintf("curl --fail --max-time 5 -sS -o /dev/null http://%s:%d/", hostIP, tcpPort),
	)
	var curlBuf bytes.Buffer
	curlCmd.Stdout = &curlBuf
	curlCmd.Stderr = &curlBuf
	err = curlCmd.Run()
	if err == nil {
		t.Fatalf("expected curl to fail due to policy denial, but exit was success (output=%s)", curlBuf.String())
	}

	select {
	case <-connAccepted:
		t.Fatalf("expected no TCP connection to be accepted when policy forbids host")
	case <-time.After(5 * time.Second):
	}

	logContent := readEventLog(t, names.leash)
	logLine, found := findHTTPLogLine(logContent, hostIP, tcpPort)
	if !found {
		t.Fatalf("no event log entry found for addr=\"%s:%d\" after policy deny.\nrecent log tail:\n%s", hostIP, tcpPort, tailLines(logContent, 200))
	}
	if !strings.Contains(logLine, "decision=denied") {
		t.Fatalf("expected decision=denied in log entry, got: %s", logLine)
	}
}

func applyPolicy(t *testing.T, apiBase, cedar string) {
	t.Helper()
	payload := fmt.Sprintf(`{"cedar":%q}`, cedar)
	resp, err := http.Post(apiBase+"/api/policies", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("apply policy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("apply policy unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

func readEventLog(t *testing.T, container string) string {
	t.Helper()
	cmd := exec.Command("docker", "exec", container, "sh", "-c", "cat /log/events.log 2>/dev/null || true")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("read events.log from %s: %v (output=%s)", container, err, string(output))
	}
	return string(output)
}

func findHTTPLogLine(logContent, host string, port int) (string, bool) {
	lines := strings.Split(logContent, "\n")
	hostNeedle := fmt.Sprintf(`addr="%s`, host)
	portNeedle := fmt.Sprintf(":%d", port)
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.Contains(line, "event=http.request") &&
			strings.Contains(line, hostNeedle) &&
			strings.Contains(line, portNeedle) {
			return line, true
		}
	}
	return "", false
}

func tailLines(content string, limit int) string {
	if limit <= 0 {
		return ""
	}
	lines := strings.Split(content, "\n")
	if len(lines) <= limit {
		return strings.TrimRight(content, "\n")
	}
	return strings.Join(lines[len(lines)-limit:], "\n")
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}

func detectHostIP(t *testing.T) (string, error) {
	if ip := strings.TrimSpace(os.Getenv("HOST_IP")); ip != "" {
		return ip, nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			t.Logf("Detected Host IP: %s", ip4.String())
			return ip4.String(), nil
		}
	}
	return "", errors.New("no non-loopback IPv4 address found")
}

func waitForControlPort(ctx context.Context, buf *safeBuffer, done <-chan error) (int, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case err := <-done:
			if err != nil {
				return 0, fmt.Errorf("leash runner exited early: %w", err)
			}
			return 0, errors.New("leash runner exited before reporting control port")
		case <-ticker.C:
			if port := parseControlPort(buf.String()); port != 0 {
				return port, nil
			}
		}
	}
}

func waitForAPI(ctx context.Context, base string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("%s/api/secrets", base)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func createSecret(base, id, value string) (string, error) {
	payload := map[string]string{"id": id, "value": value}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	resp, err := http.Post(fmt.Sprintf("%s/api/secrets/%s", base, id), "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create secret status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		Placeholder string `json:"placeholder"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Placeholder == "" {
		return "", errors.New("blank placeholder returned")
	}
	return out.Placeholder, nil
}

type secretEntry struct {
	Value       string `json:"value"`
	Placeholder string `json:"placeholder"`
	Activations int    `json:"activations"`
}

func fetchSecret(base, id string) (secretEntry, error) {
	resp, err := http.Get(fmt.Sprintf("%s/api/secrets", base))
	if err != nil {
		return secretEntry{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return secretEntry{}, fmt.Errorf("fetch secrets status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var raw map[string]secretEntry
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return secretEntry{}, err
	}
	entry, ok := raw[id]
	if !ok {
		return secretEntry{}, fmt.Errorf("secret %s not found", id)
	}
	return entry, nil
}

func captureHTTP(ln net.Listener, ch chan<- capturedRequest) {
	conn, err := ln.Accept()
	if err != nil {
		ch <- capturedRequest{err: err}
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		ch <- capturedRequest{err: err}
		return
	}
	if req.Body != nil {
		io.Copy(io.Discard, req.Body)
		req.Body.Close()
	}
	response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
	_, _ = conn.Write([]byte(response))
	ch <- capturedRequest{
		path:          req.URL.Path,
		authorization: req.Header.Get("Authorization"),
	}
}

type containerNames struct {
	target string
	leash  string
}

var (
	stopEverythingRE = regexp.MustCompile(`Stop everything with:\s+docker rm -f ([^\s]+)\s+([^\s]+)`)
	selectedRE       = regexp.MustCompile(`selected ([^/\s]+)/([^\s]+) instead`)
	controlPortRE    = regexp.MustCompile(`Leash UI \(Control UI\): http://[^:]+:(\d+)/`)
)

func parseContainerNames(output string) containerNames {
	if matches := stopEverythingRE.FindStringSubmatch(output); len(matches) == 3 {
		return containerNames{target: matches[1], leash: matches[2]}
	}
	if matches := selectedRE.FindStringSubmatch(output); len(matches) == 3 {
		return containerNames{target: matches[1], leash: matches[2]}
	}
	var target, leash string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if target == "" && strings.HasPrefix(line, "Target logs: docker logs -f ") {
			target = strings.TrimPrefix(line, "Target logs: docker logs -f ")
		}
		if leash == "" && strings.HasPrefix(line, "Leash logs: docker logs -f ") {
			leash = strings.TrimPrefix(line, "Leash logs: docker logs -f ")
		}
	}
	if target != "" || leash != "" {
		return containerNames{target: target, leash: leash}
	}
	return containerNames{}
}

func parseControlPort(output string) int {
	if matches := controlPortRE.FindStringSubmatch(output); len(matches) == 2 {
		if port, err := strconv.Atoi(matches[1]); err == nil {
			return port
		}
	}
	return 0
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func newSafeBuffer() *safeBuffer {
	return &safeBuffer{}
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
