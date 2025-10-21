package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type stubPolicyChecker struct {
	allowConnect bool
	allowMCP     bool
	mcp          bool
}

func (s stubPolicyChecker) CheckConnect(hostname string, ip string, port uint16) bool {
	return s.allowConnect
}

func (s stubPolicyChecker) CheckMCPCall(server string, tool string) bool {
	if !s.mcp {
		return true
	}
	return s.allowMCP
}

func (s stubPolicyChecker) HasMCPPolicies() bool {
	return s.mcp
}

// toolOnlyPolicyChecker denies MCP calls when the tool matches the configured value.
type toolOnlyPolicyChecker struct {
	tool string
}

func (t toolOnlyPolicyChecker) CheckConnect(hostname string, ip string, port uint16) bool {
	return true
}
func (t toolOnlyPolicyChecker) HasMCPPolicies() bool { return true }
func (t toolOnlyPolicyChecker) CheckMCPCall(server string, tool string) bool {
	return strings.TrimSpace(strings.ToLower(tool)) != strings.TrimSpace(strings.ToLower(t.tool))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func setTempLeashDir(t *testing.T) {
	t.Helper()
	old := os.Getenv("LEASH_DIR")
	temp := t.TempDir()
	if err := os.Setenv("LEASH_DIR", temp); err != nil {
		t.Fatalf("failed to set LEASH_DIR: %v", err)
	}
	t.Cleanup(func() {
		if old == "" {
			_ = os.Unsetenv("LEASH_DIR")
		} else {
			_ = os.Setenv("LEASH_DIR", old)
		}
	})
}

func generateTestCertificate(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}

func TestHandleTransparentHTTPDeniedReturns403(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: deny.example.com\r\n\r\n"
	initialData := []byte(req)[:len(req)/2]
	remaining := []byte(req)[len(initialData):]
	proxy := &MITMProxy{
		certCache:      make(map[string]*tls.Certificate),
		headerRewriter: NewHeaderRewriter(),
		policyChecker:  stubPolicyChecker{allowConnect: false},
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("unexpected forward")
		})},
	}
	proxy.SetPolicyChecker(proxy.policyChecker)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverConn.Close()
		proxy.handleTransparentHTTP(serverConn, "deny.example.com:80", initialData)
	}()

	if _, err := clientConn.Write(remaining); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	response := string(buf[:n])
	if !strings.Contains(response, "403 Forbidden") {
		t.Fatalf("expected 403 response, got %q", response)
	}

	wg.Wait()
}

func TestHandleTransparentHTTPMCPPolicyDeniesToolsCall(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"resolve-library-id"}}`
	req := fmt.Sprintf("POST /jsonrpc HTTP/1.1\r\nHost: mcp.context7.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	initialData := []byte(req)[:len(req)/2]
	remaining := []byte(req)[len(initialData):]
	proxy := &MITMProxy{
		certCache:      make(map[string]*tls.Certificate),
		headerRewriter: NewHeaderRewriter(),
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("unexpected forward")
		})},
		mcpObserver: newMCPObserver(MCPConfig{}, nil),
	}
	proxy.SetPolicyChecker(stubPolicyChecker{allowConnect: true, allowMCP: false, mcp: true})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverConn.Close()
		proxy.handleTransparentHTTP(serverConn, "mcp.context7.com:80", initialData)
	}()

	if _, err := clientConn.Write(remaining); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	response := string(buf[:n])
	if !strings.Contains(response, "403 Forbidden") {
		t.Fatalf("expected 403 response, got %q", response)
	}
	if !strings.Contains(response, "policy") {
		t.Fatalf("expected policy message, got %q", response)
	}

	wg.Wait()
}

func TestHandleTransparentHTTPMCPPolicyDeniesByToolOnly(t *testing.T) {
	// Real JSON-RPC payload with a tool name; denial should trigger based on tool match only
	body := `{"jsonrpc":"2.0","id":"42","method":"tools/call","params":{"name":"get_library_docs"}}`
	req := fmt.Sprintf("POST /jsonrpc HTTP/1.1\r\nHost: mcp.example.org\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	initialData := []byte(req)[:len(req)/2]
	remaining := []byte(req)[len(initialData):]

	proxy := &MITMProxy{
		certCache:      make(map[string]*tls.Certificate),
		headerRewriter: NewHeaderRewriter(),
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("unexpected forward")
		})},
		mcpObserver: newMCPObserver(MCPConfig{}, nil),
	}
	// Deny only when the tool name matches get_library_docs, regardless of server host
	proxy.SetPolicyChecker(toolOnlyPolicyChecker{tool: "get_library_docs"})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverConn.Close()
		proxy.handleTransparentHTTP(serverConn, "mcp.example.org:80", initialData)
	}()

	if _, err := clientConn.Write(remaining); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	response := string(buf[:n])
	if !strings.Contains(response, "403 Forbidden") {
		t.Fatalf("expected 403 response, got %q", response)
	}
	if !strings.Contains(response, "tools/call denied") {
		t.Fatalf("expected denial reason, got %q", response)
	}

	wg.Wait()
}

func TestHandleTransparentHTTPAllowedForwardsResponse(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: allow.example.com\r\n\r\n"
	initialData := []byte(req)[:len(req)/2]
	remaining := []byte(req)[len(initialData):]
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    200,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          io.NopCloser(strings.NewReader("OK")),
			ContentLength: 2,
			Header:        http.Header{"Content-Length": []string{"2"}},
			Request:       req,
		}, nil
	})
	proxy := &MITMProxy{
		certCache:      make(map[string]*tls.Certificate),
		headerRewriter: NewHeaderRewriter(),
		policyChecker:  stubPolicyChecker{allowConnect: true},
		httpClient:     &http.Client{Transport: transport},
	}
	proxy.SetPolicyChecker(proxy.policyChecker)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverConn.Close()
		proxy.handleTransparentHTTP(serverConn, "allow.example.com:80", initialData)
	}()

	writeErr := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(remaining)
		writeErr <- err
	}()

	var respBuf strings.Builder
	buf := make([]byte, 256)
	deadline := time.Now().Add(2 * time.Second)
	for {
		_ = clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := clientConn.Read(buf)
		if n > 0 {
			respBuf.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("failed to read response: %v", err)
			}
		}
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("failed to write request: %v", err)
	}
	response := respBuf.String()
	if strings.Contains(response, "403 Forbidden") {
		t.Fatalf("unexpected 403 response: %q", response)
	}
	if !strings.Contains(response, "200 OK") {
		t.Fatalf("expected 200 response, got %q", response)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
}

func TestHandleTransparentHTTPSDeniedReturns403(t *testing.T) {
	setTempLeashDir(t)
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}
	proxy := &MITMProxy{
		ca:             ca,
		certCache:      make(map[string]*tls.Certificate),
		headerRewriter: NewHeaderRewriter(),
		policyChecker:  stubPolicyChecker{allowConnect: false},
	}
	proxy.SetPolicyChecker(proxy.policyChecker)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverConn.Close()
		proxy.handleTransparentHTTPS(serverConn, "deny.example.com:443", nil)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "deny.example.com"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	_ = clientTLS.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := clientTLS.Read(buf)
	if err != nil {
		t.Fatalf("failed to read TLS response: %v", err)
	}
	response := string(buf[:n])
	if !strings.Contains(response, "403 Forbidden") {
		t.Fatalf("expected 403 response, got %q", response)
	}

	_ = clientTLS.Close()
	wg.Wait()
}

func TestHandleTransparentHTTPSAllowedForwardsResponse(t *testing.T) {
	setTempLeashDir(t)
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}
	proxy := &MITMProxy{
		ca:             ca,
		certCache:      make(map[string]*tls.Certificate),
		headerRewriter: NewHeaderRewriter(),
		policyChecker:  stubPolicyChecker{allowConnect: true},
	}
	proxy.SetPolicyChecker(proxy.policyChecker)

	targetClient, targetServer := net.Pipe()
	serverCert := generateTestCertificate(t, "allow.example.com")
	targetServerTLS := tls.Server(targetServer, &tls.Config{Certificates: []tls.Certificate{serverCert}})
	targetClientTLS := tls.Client(targetClient, &tls.Config{InsecureSkipVerify: true, ServerName: "allow.example.com"})

	handshakeErr := make(chan error, 1)
	go func() {
		handshakeErr <- targetClientTLS.Handshake()
	}()
	if err := targetServerTLS.Handshake(); err != nil {
		t.Fatalf("target handshake failed: %v", err)
	}
	if err := <-handshakeErr; err != nil {
		t.Fatalf("client handshake with target failed: %v", err)
	}

	dialOnce := sync.Once{}
	proxy.tlsDialer = func(string) (*tls.Conn, error) {
		var conn *tls.Conn
		dialOnce.Do(func() {
			conn = targetClientTLS
		})
		if conn == nil {
			return nil, fmt.Errorf("tls dialer invoked more than once")
		}
		return conn, nil
	}

	go func() {
		defer targetServerTLS.Close()
		buf := make([]byte, 1024)
		if _, err := targetServerTLS.Read(buf); err != nil {
			return
		}
		_, _ = targetServerTLS.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverConn.Close()
		proxy.handleTransparentHTTPS(serverConn, "allow.example.com:443", nil)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "allow.example.com"})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	if _, err := clientTLS.Write([]byte("GET / HTTP/1.1\r\nHost: allow.example.com\r\n\r\n")); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	_ = clientTLS.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := clientTLS.Read(buf)
	if err != nil {
		t.Fatalf("failed to read TLS response: %v", err)
	}
	response := string(buf[:n])
	if strings.Contains(response, "403 Forbidden") {
		t.Fatalf("unexpected 403 response: %q", response)
	}
	if !strings.Contains(response, "200 OK") {
		t.Fatalf("expected 200 response, got %q", response)
	}

	_ = clientTLS.Close()
	wg.Wait()
}
