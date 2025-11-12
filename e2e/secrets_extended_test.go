//go:build e2e

package e2e

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

/*
The examples add end-to-end scenarios not covered by ./e2e/secrets_proxy_test.go.

- Body replacement (identity): docs/examples/secrets/e2e/main.go posts JSON with the placeholder in the body and verifies the echo server receives the real secret value (Control UI side is not involved). The e2e test only checks URL path and Authorization header, not body content (e2e/secrets_proxy_test.go:139, 168).
- Compressed bodies: docs/examples/secrets/requestgen/main.go exercises replacement through Content-Encoding gzip, deflate, and brotli, re-encoding on the way out, and verifies both header and body substitution. The ./e2e test doesn’t cover encodings; only unit tests do (internal/proxy/secrets_test.go).
- Header variety: examples use X-Secret-Token, while the e2e test uses Authorization. Replacement is generic but the examples prove multiple headers work.
- Activation totals via API: examples fetch and print activations from GET /api/secrets after requests; e2e asserts a lower bound but doesn’t exercise multiple content-encoding cases against totals.
- Optional explicit proxy: examples allow routing via LEASH_HTTP_PROXY, whereas ./e2e relies on transparent interception; this mode isn’t exercised by the e2e test.

References:
- docs/examples/secrets/e2e/main.go, docs/examples/secrets/requestgen/main.go
- e2e/secrets_proxy_test.go
- internal/proxy/secrets_test.go
*/

func TestSecretsExtendedBodyReplacement(t *testing.T) {
	t.Parallel()
	skipUnlessE2E(t)

	session := startLeashRunner(t)

	capture, server := newRequestCaptureServer(`{"ok":true}`)
	defer server.Close()

	secretID := "e2e_demo_secret"
	secretValue := "this-is-ultra-secret"

	placeholder, err := createSecret(session.apiBase, secretID, secretValue)
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}

	addr := server.Listener.Addr().(*net.TCPAddr)
	hostURL := fmt.Sprintf("http://%s:%d", session.hostIP, addr.Port)
	payload := fmt.Sprintf(`{"message":"demo-%s"}`, placeholder)
	cmd := fmt.Sprintf("timeout 30 curl -sS -o /dev/null -H 'Content-Type: application/json' -H 'X-Secret-Token: %s' -d '%s' %s",
		placeholder, payload, hostURL)
	if out, code, err := runDockerCommand(t, 60*time.Second, "exec", session.targetContainer, "bash", "-lc", cmd); err != nil || code != 0 {
		t.Logf("container curl warnings (code=%d, err=%v, output=%s)", code, err, string(out))
	}

	header, body := capture.waitForSnapshot(t, 10*time.Second)
	if len(body) == 0 {
		t.Fatalf("echo server did not receive body payload")
	}
	if header.Get("X-Secret-Token") != secretValue {
		t.Fatalf("header placeholder was not replaced: got %q", header.Get("X-Secret-Token"))
	}
	if !bytes.Contains(body, []byte(secretValue)) {
		t.Fatalf("echo body does not contain secret value: %s", string(body))
	}

	entry, err := fetchSecret(session.apiBase, secretID)
	if err != nil {
		t.Fatalf("fetch secret info: %v", err)
	}
	if entry.Activations < 2 {
		t.Fatalf("expected activations >= 2, got %d", entry.Activations)
	}
}

func TestSecretsExtendedCompressedBodies(t *testing.T) {
	t.Parallel()
	skipUnlessE2E(t)

	session := startLeashRunner(t)

	capture, server := newRequestCaptureServer(`{"status":"ok"}`)
	defer server.Close()

	clientPath := buildSecretsClient(t)
	targetPath := "/tmp/secrets-client"
	dockerCopy(t, clientPath, fmt.Sprintf("%s:%s", session.targetContainer, targetPath))

	secretID := "generator_demo_secret"
	secretValue := "value-from-generator"

	placeholder, err := createSecret(session.apiBase, secretID, secretValue)
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}

	addr := server.Listener.Addr().(*net.TCPAddr)
	hostURL := fmt.Sprintf("http://%s:%d", session.hostIP, addr.Port)

	cases := []struct {
		name     string
		encoding string
	}{
		{name: "uncompressed-json", encoding: "identity"},
		{name: "gzip-json", encoding: "gzip"},
		{name: "deflate-json", encoding: "deflate"},
		{name: "brotli-json", encoding: "br"},
	}

	for i, cas := range cases {
		capture.reset()

		args := []string{"exec", session.targetContainer, targetPath,
			"--url", hostURL,
			"--placeholder", placeholder,
			"--encoding", cas.encoding,
			"--header", "X-Secret-Token",
		}
		if out, code, err := runDockerCommand(t, 60*time.Second, args...); err != nil || code != 0 {
			t.Fatalf("%s client run failed (code=%d, err=%v, output=%s)", cas.name, code, err, string(out))
		}

		header, observed := capture.waitForSnapshot(t, 10*time.Second)
		if header.Get("X-Secret-Token") != secretValue {
			t.Fatalf("%s header mismatch: got %q", cas.name, header.Get("X-Secret-Token"))
		}
		decoded, err := decodeBody(observed, cas.encoding)
		if err != nil {
			t.Fatalf("%s decode body: %v", cas.name, err)
		}
		if !bytes.Contains(decoded, []byte(secretValue)) {
			t.Fatalf("%s body missing secret value: %s", cas.name, string(decoded))
		}
		t.Logf("[%d/%d] %s ✓", i+1, len(cases), cas.name)
	}

	entry, err := fetchSecret(session.apiBase, secretID)
	if err != nil {
		t.Fatalf("fetch secret info: %v", err)
	}
	if entry.Activations < len(cases) {
		t.Fatalf("expected activations >= %d, got %d", len(cases), entry.Activations)
	}
}

type leashRunner struct {
	cmd              *exec.Cmd
	cancel           context.CancelFunc
	buf              *safeBuffer
	apiBase          string
	targetContainer  string
	managerContainer string
	hostIP           string
}

func startLeashRunner(t *testing.T) *leashRunner {
	t.Helper()

	bin := locatePrebuiltLeashBinary(t)
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}

	hostIP, err := detectHostIP(t)
	if err != nil {
		t.Fatalf("detect host IP: %v", err)
	}

	baseName := sanitizeName(t.Name())
	targetName := fmt.Sprintf("leash-e2e-target-%s", baseName)
	managerName := fmt.Sprintf("leash-e2e-manager-%s", baseName)

	t.Logf("starting leash: target=%s manager=%s", targetName, managerName)

	_ = exec.Command("docker", "rm", "-f", targetName).Run()
	_ = exec.Command("docker", "rm", "-f", managerName).Run()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	cmd := exec.CommandContext(ctx, bin, "-I", "sleep", "300")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TARGET_CONTAINER=%s", targetName),
		fmt.Sprintf("LEASH_CONTAINER=%s", managerName),
	)

	buf := newSafeBuffer()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		t.Fatalf("stderr pipe: %v", err)
	}
	go io.Copy(buf, stdout)
	go io.Copy(buf, stderr)

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start leash: %v", err)
	}

	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	session := &leashRunner{
		cmd:              cmd,
		cancel:           cancel,
		buf:              buf,
		hostIP:           hostIP,
		targetContainer:  targetName,
		managerContainer: managerName,
	}

	t.Cleanup(func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		if session.targetContainer != "" {
			_ = exec.Command("docker", "rm", "-f", session.targetContainer).Run()
		}
		if session.managerContainer != "" {
			_ = exec.Command("docker", "rm", "-f", session.managerContainer).Run()
		}
	})

	controlPort, err := waitForControlPort(ctx, buf, cmdDone)
	if err != nil {
		t.Fatalf("detect control port: %v\noutput:\n%s", err, buf.String())
	}
	session.apiBase = fmt.Sprintf("http://127.0.0.1:%d", controlPort)
	t.Logf("control port detected: %d", controlPort)

	if err := waitForAPI(ctx, session.apiBase); err != nil {
		t.Fatalf("waiting for API ready: %v\noutput:\n%s", err, buf.String())
	}
	t.Log("API responded OK")

	if names := parseContainerNames(buf.String()); names.target != "" && names.leash != "" {
		session.targetContainer = names.target
		session.managerContainer = names.leash
	}

	return session
}

type requestCapture struct {
	mu     sync.Mutex
	header http.Header
	body   []byte
}

func newRequestCaptureServer(response string) (*requestCapture, *httptest.Server) {
	capture := &requestCapture{}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		panic(fmt.Errorf("listen for capture server: %w", err))
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	server.Listener = ln
	server.Start()
	return capture, server
}

func (c *requestCapture) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.header = r.Header.Clone()
	c.body = append([]byte(nil), body...)
}

func (c *requestCapture) waitForSnapshot(t *testing.T, timeout time.Duration) (http.Header, []byte) {
	t.Helper()
	var header http.Header
	var body []byte
	readinessCheck := func() bool {
		header, body = c.snapshot()
		return len(body) > 0 || len(header) > 0
	}
	waitForReadinessWithin(t, "captured request", timeout, readinessCheck)
	return header, body
}

func (c *requestCapture) snapshot() (http.Header, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	header := make(http.Header, len(c.header))
	for k, v := range c.header {
		header[k] = append([]string(nil), v...)
	}
	body := append([]byte(nil), c.body...)
	return header, body
}

func (c *requestCapture) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.header = make(http.Header)
	c.body = nil
}

func decodeBody(body []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	case "deflate":
		reader, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	case "br":
		reader := brotli.NewReader(bytes.NewReader(body))
		return io.ReadAll(reader)
	default:
		return nil, fmt.Errorf("unsupported encoding %q", encoding)
	}
}

func buildSecretsClient(t *testing.T) string {
	t.Helper()

	source := `package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/andybalholm/brotli"
)

func main() {
	url := flag.String("url", "", "target URL")
	placeholder := flag.String("placeholder", "", "placeholder token")
	encoding := flag.String("encoding", "identity", "content encoding")
	headerName := flag.String("header", "X-Secret-Token", "header to set")
	flag.Parse()

	if strings.TrimSpace(*url) == "" || strings.TrimSpace(*placeholder) == "" {
		fmt.Fprintln(os.Stderr, "url and placeholder are required")
		os.Exit(2)
	}

	raw := []byte(fmt.Sprintf("{\"payload\":\"body-%s\"}", *placeholder))

	var body []byte
	switch strings.ToLower(strings.TrimSpace(*encoding)) {
	case "", "identity":
		body = raw
	case "gzip":
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(raw); err != nil {
			panic(err)
		}
		if err := gz.Close(); err != nil {
			panic(err)
		}
		body = buf.Bytes()
	case "deflate":
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(raw); err != nil {
			panic(err)
		}
		if err := zw.Close(); err != nil {
			panic(err)
		}
		body = buf.Bytes()
	case "br":
		var buf bytes.Buffer
		bw := brotli.NewWriter(&buf)
		if _, err := bw.Write(raw); err != nil {
			panic(err)
		}
		if err := bw.Close(); err != nil {
			panic(err)
		}
		body = buf.Bytes()
	default:
		fmt.Fprintf(os.Stderr, "unsupported encoding %q\n", *encoding)
		os.Exit(2)
	}

	req, err := http.NewRequest(http.MethodPost, *url, bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if enc := strings.ToLower(strings.TrimSpace(*encoding)); enc != "" && enc != "identity" {
		req.Header.Set("Content-Encoding", enc)
	}
	req.Header.Set(*headerName, *placeholder)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "unexpected status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}`

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		t.Fatalf("write client source: %v", err)
	}

	target := filepath.Join(dir, "secrets-client")
	cmd := exec.Command("go", "build", "-o", target, srcPath)
	cmd.Env = append(os.Environ(),
		"GOOS=linux",
		"GOARCH=amd64",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build secrets client: %v\n%s", err, stderr.String())
	}
	return target
}

func dockerCopy(t *testing.T, src, dest string) {
	t.Helper()
	cmd := exec.Command("docker", "cp", src, dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker cp %s %s failed: %v\n%s", src, dest, err, string(out))
	}
}

func locatePrebuiltLeashBinary(t *testing.T) string {
	t.Helper()
	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("determine module root: %v", err)
	}
	candidate := filepath.Join(root, "bin", "leash")
	if info, err := os.Stat(candidate); err == nil && info.Mode().Perm()&0o111 != 0 {
		return candidate
	}
	path, err := exec.LookPath("leash")
	if err == nil {
		return path
	}
	t.Fatalf("leash binary not found at %s or in PATH", candidate)
	return ""
}

func sanitizeName(name string) string {
	replacer := strings.NewReplacer("/", "-", " ", "-", ":", "-", ".", "-")
	return replacer.Replace(strings.ToLower(name))
}
