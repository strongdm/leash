package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/strongdm/leash/internal/lsm"
)

// PolicyChecker interface for connect policy enforcement
type PolicyChecker interface {
	CheckConnect(hostname string, ip string, port uint16) bool
	CheckMCPCall(server string, tool string) bool
	HasMCPPolicies() bool
}

// Socket marking constants for iptables
const (
	// SO_MARK socket option for marking packets
	SO_MARK = 36
	// PROXY_MARK is the mark value we'll use for proxy outgoing connections
	PROXY_MARK = 0x2000 // Use mark 8192 (0x2000) to identify proxy traffic
)

type MITMProxy struct {
	ca             *CertificateAuthority
	certCache      map[string]*tls.Certificate
	certCacheMux   sync.RWMutex
	port           string
	headerRewriter *HeaderRewriter
	logMutex       sync.Mutex
	sharedLogger   *lsm.SharedLogger // Shared event logger
	policyChecker  PolicyChecker     // Connect policy enforcement
	httpClient     *http.Client      // Custom HTTP client with marked connections
	tlsDialer      func(string) (*tls.Conn, error)
	mcpObserver    *mcpObserver
}

// sockaddr_in structure for SO_ORIGINAL_DST
type sockaddrIn struct {
	family uint16
	port   uint16
	addr   [4]byte
	zero   [8]uint8
}

// sockaddr_in6 structure for IPv6 SO_ORIGINAL_DST (IP6T_SO_ORIGINAL_DST)
type sockaddrIn6 struct {
	family   uint16
	port     uint16
	flowinfo uint32
	addr     [16]byte
	scope_id uint32
}

// createMarkedDialer creates a dialer that marks outgoing connections to avoid proxy loops
func createMarkedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				// Set SO_MARK on the socket to mark proxy traffic
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_MARK, PROXY_MARK)
				if err != nil {
					log.Printf("Warning: Failed to set SO_MARK on socket: %v", err)
				}
			})
			return err
		},
	}
}

// createMarkedTLSConnection creates a TLS connection with marked socket to avoid proxy loops
func (p *MITMProxy) createMarkedTLSConnection(targetHost string) (*tls.Conn, error) {
	markedDialer := createMarkedDialer()

	conn, err := markedDialer.DialContext(context.Background(), "tcp", targetHost)
	if err != nil {
		return nil, err
	}

	// Extract hostname for SNI; handle IPv6 [addr]:port correctly
	serverName := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		serverName = h
	}
	// Trim brackets for IPv6 literals
	serverName = strings.Trim(serverName, "[]")

	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})

	return tlsConn, nil
}

func NewMITMProxy(port string, headerRewriter *HeaderRewriter, policyChecker PolicyChecker, sharedLogger *lsm.SharedLogger, mcpCfg MCPConfig) (*MITMProxy, error) {
	ca, err := NewCertificateAuthority()
	if err != nil {
		return nil, fmt.Errorf("failed to create CA: %w", err)
	}

	// Create marked dialer for outgoing connections
	markedDialer := createMarkedDialer()

	// Create custom HTTP client with marked transport
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: markedDialer.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	proxy := &MITMProxy{
		ca:             ca,
		certCache:      make(map[string]*tls.Certificate),
		port:           port,
		headerRewriter: headerRewriter,
		sharedLogger:   sharedLogger,
		httpClient:     httpClient,
		mcpObserver:    newMCPObserver(mcpCfg, sharedLogger),
	}
	proxy.tlsDialer = proxy.createMarkedTLSConnection
	proxy.SetPolicyChecker(policyChecker)
	return proxy, nil
}

// SnapshotMCPHints returns the most recently observed MCP servers and tools.
func (p *MITMProxy) SnapshotMCPHints() (servers []string, tools []string) {
	if p == nil || p.mcpObserver == nil {
		return nil, nil
	}
	return p.mcpObserver.SnapshotServers(), p.mcpObserver.SnapshotTools()
}

// getOriginalDest gets the original destination using SO_ORIGINAL_DST
func getOriginalDest(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}

	file, err := tcpConn.File()
	if err != nil {
		return "", err
	}
	defer file.Close()

	fd := int(file.Fd())

	// SO_ORIGINAL_DST (v4) and IP6T_SO_ORIGINAL_DST (v6) share value 80
	const SO_ORIGINAL_DST = 80

	// Try IPv4 first
	{
		const SOL_IP = 0
		var sin sockaddrIn
		size := uint32(unsafe.Sizeof(sin))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			uintptr(fd),
			SOL_IP,
			SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&sin)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno == 0 {
			ip := fmt.Sprintf("%d.%d.%d.%d", sin.addr[0], sin.addr[1], sin.addr[2], sin.addr[3])
			port := (uint16(sin.port&0xFF) << 8) | (uint16(sin.port&0xFF00) >> 8)
			return fmt.Sprintf("%s:%d", ip, port), nil
		}
	}

	// Fallback to IPv6
	{
		lvl := uintptr(syscall.IPPROTO_IPV6) // SOL_IPV6
		var sin6 sockaddrIn6
		size := uint32(unsafe.Sizeof(sin6))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			uintptr(fd),
			lvl,
			SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&sin6)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno == 0 {
			ip := net.IP(sin6.addr[:]).String()
			port := (uint16(sin6.port&0xFF) << 8) | (uint16(sin6.port&0xFF00) >> 8)
			// Bracket IPv6 literal for host:port format
			return fmt.Sprintf("[%s]:%d", ip, port), nil
		}
		return "", fmt.Errorf("SO_ORIGINAL_DST (v4/v6) failed: %v", errno)
	}
}

func (p *MITMProxy) Run() error {
	listener, err := net.Listen("tcp", ":"+p.port)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	log.Printf("Starting transparent MITM proxy on port %s", p.port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go p.handleTransparentConnection(conn)
	}
}

// SetPolicyChecker updates the policy checker used for connect enforcement.
func (p *MITMProxy) SetPolicyChecker(pc PolicyChecker) {
	p.policyChecker = pc
	if p.mcpObserver != nil {
		p.mcpObserver.setForceParse(pc != nil && pc.HasMCPPolicies())
	}
}

func (p *MITMProxy) handleTransparentConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Get the original destination
	originalDest, err := getOriginalDest(clientConn)
	if err != nil {
		log.Printf("Failed to get original destination: %v", err)
		return
	}

	// Peek at the first few bytes to determine if it's HTTP or HTTPS
	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		log.Printf("Error reading initial data: %v", err)
		return
	}

	// Check if it looks like HTTP
	if isHTTPRequest(buf[:n]) {
		p.handleTransparentHTTP(clientConn, originalDest, buf[:n])
	} else {
		// Assume HTTPS/TLS
		p.handleTransparentHTTPS(clientConn, originalDest, buf[:n])
	}
}

// checkConnectPolicy validates if a connection should be allowed based on hostname/IP policy
func (p *MITMProxy) checkConnectPolicy(hostname, destIP string, port uint16) bool {
	if p.policyChecker == nil {
		return true // No policy checker, allow all
	}

	return p.policyChecker.CheckConnect(hostname, destIP, port)
}

// blockConnection sends a policy violation response and closes the connection
func (p *MITMProxy) blockConnection(clientConn net.Conn, isHTTPS bool, hostname, destIP string, port uint16, path, query, authHeader string) {
	// Determine protocol and port string for logging
	protocol := "http"
	portStr := fmt.Sprintf("%d", port)
	if isHTTPS {
		protocol = "https"
	}

	// Create policy denial error for logging
	policyErr := fmt.Errorf("connection denied by security policy")

	// Log the denied request to shared logger
	p.logRequest(protocol, hostname, portStr, path, query, authHeader, 403, policyErr)

	body := "Connection denied by security policy: " + hostname
	response := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\n"+
		"Content-Type: text/plain\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n"+
		"%s", len(body), body)
	if _, err := clientConn.Write([]byte(response)); err != nil {
		log.Printf("failed to write policy denial response: %v", err)
	}
	if closer, ok := clientConn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	_ = clientConn.Close()
	if isHTTPS {
		log.Printf("Connect policy DENIED: HTTPS connection to %s (%s:%d)", hostname, destIP, port)
	} else {
		log.Printf("Connect policy DENIED: HTTP connection to %s (%s:%d)", hostname, destIP, port)
	}
}

func (p *MITMProxy) enforceMCPCall(conn net.Conn, ctx *mcpRequestContext, serverHost string, logHost string, logPort string, path string, query string, authHeader string, scheme string) bool {
	if p.policyChecker == nil || ctx == nil {
		return false
	}
	if !strings.EqualFold(ctx.method, "tools/call") {
		return false
	}
	if serverHost == "" {
		serverHost = logHost
	}
	if !p.policyChecker.CheckMCPCall(serverHost, ctx.tool) {
		status := http.StatusForbidden
		ctx.server = serverHost
		ctx.responseOutcome = "denied"
		ctx.responseError = "policy_denied"
		description := "MCP tools/call denied by policy"
		if serverHost != "" {
			description += fmt.Sprintf(" (server=%s)", escapeQuotes(serverHost))
		}
		if ctx.tool != "" {
			description += fmt.Sprintf(" (tool=%s)", escapeQuotes(ctx.tool))
		}
		description = strings.ReplaceAll(description, "\"", "'")
		idField := "null"
		if ctx.id != "" {
			idField = fmt.Sprintf("\"%s\"", escapeQuotes(ctx.id))
		}
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"%s"}}`, idField, description)
		response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			status, http.StatusText(status), len(body), body)
		if _, err := conn.Write([]byte(response)); err != nil {
			log.Printf("failed to write MCP denial response: %v", err)
		}
		if closer, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		_ = conn.Close()
		if p.mcpObserver != nil {
			p.mcpObserver.logHTTPRequest(ctx, status, "denied", "", nil)
		}
		p.logRequest(scheme, logHost, logPort, path, query, authHeader, status, fmt.Errorf("mcp tools/call denied by policy"))
		return true
	}
	return false
}

func isHTTPRequest(data []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE "}
	dataStr := string(data)
	for _, method := range methods {
		if strings.HasPrefix(dataStr, method) {
			return true
		}
	}
	return false
}

func (p *MITMProxy) handleTransparentHTTP(clientConn net.Conn, originalDest string, initialData []byte) {
	// Create a reader that includes the initial data
	reader := io.MultiReader(strings.NewReader(string(initialData)), clientConn)
	bufferedReader := bufio.NewReader(reader)

	// Parse HTTP request
	req, err := http.ReadRequest(bufferedReader)
	if err != nil {
		log.Printf("Error parsing HTTP request: %v", err)
		// Log error to logfmt
		host, port, _ := net.SplitHostPort(originalDest)
		if port == "" {
			port = "80"
		}
		p.logRequest("http", host, port, "", "", "", 0, err)
		return
	}

	// Set the proper URL
	req.URL.Scheme = "http"
	req.URL.Host = originalDest
	req.RequestURI = ""

	// Extract request details for logging
	host, port, err := net.SplitHostPort(originalDest)
	if err != nil {
		host = originalDest
		port = "80"
	}

	// Check connect policy for HTTP connections
	portNum, _ := strconv.ParseUint(port, 10, 16)
	hostname := req.Host // Use Host header if available, otherwise use originalDest host
	if hostname == "" {
		hostname = host
	}

	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	query := req.URL.RawQuery
	authHeader := req.Header.Get("Authorization")

	if !p.checkConnectPolicy(hostname, host, uint16(portNum)) {
		p.blockConnection(clientConn, false, hostname, host, uint16(portNum), path, query, authHeader)
		return
	}

	// Unique request logging removed

	// Apply header rewriting rules
	p.headerRewriter.ApplyRules(req)

	var mcpCtx *mcpRequestContext
	if p.mcpObserver != nil {
		if ctx, sniffErr := p.mcpObserver.inspectHTTPRequest(req, host); sniffErr == nil {
			mcpCtx = ctx
		} else {
			log.Printf("mcp sniff (http) error: %v", sniffErr)
		}
	}
	serverForPolicy := req.URL.Hostname()
	if serverForPolicy == "" {
		serverForPolicy = strings.TrimSpace(req.Host)
	}
	if serverForPolicy == "" {
		serverForPolicy = hostname
	}
	if p.enforceMCPCall(clientConn, mcpCtx, serverForPolicy, hostname, port, path, query, authHeader, "http") {
		return
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		log.Printf("Error forwarding request: %v", err)
		p.logRequest("http", host, port, path, query, authHeader, 0, err)
		if mcpCtx != nil {
			p.mcpObserver.logHTTPRequest(mcpCtx, 0, "error", "", err)
		}
		return
	}
	defer resp.Body.Close()

	sessionHeader := resp.Header.Get("Mcp-Session-Id")
	contentType := resp.Header.Get("Content-Type")
	transport := transportFromHeader(contentType)
	serverHost := req.URL.Hostname()
	if serverHost == "" {
		serverHost = req.Host
	}
	if serverHost == "" {
		serverHost = host
	}

	if mcpCtx != nil && mcpCtx.sampled {
		mcpCtx.transport = transport
		if transport == "sse" {
			resp.Body = p.mcpObserver.wrapSSEBody(mcpCtx, resp.Body)
		} else {
			p.mcpObserver.inspectHTTPResponse(mcpCtx, resp)
		}
		p.mcpObserver.registerSession(sessionHeader, mcpCtx)
	} else if p.mcpObserver != nil && transport == "sse" {
		protoHeader := strings.TrimSpace(req.Header.Get("MCP-Protocol-Version"))
		resp.Body = p.mcpObserver.wrapSessionSSE(sessionHeader, serverHost, protoHeader, resp.Body)
	}

	writeErr := resp.Write(clientConn)
	if writeErr != nil {
		log.Printf("Error writing response: %v", writeErr)
	}

	outcome := classifyOutcome(resp.StatusCode, writeErr)
	if mcpCtx != nil {
		p.mcpObserver.logHTTPRequest(mcpCtx, resp.StatusCode, outcome, sessionHeader, writeErr)
	}

	p.logRequest("http", host, port, path, query, authHeader, resp.StatusCode, writeErr)
}

// connWrapper wraps a net.Conn with additional reader for prepending data
type connWrapper struct {
	net.Conn
	reader io.Reader
}

func (c *connWrapper) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (p *MITMProxy) handleTransparentHTTPS(clientConn net.Conn, originalDest string, initialData []byte) {
	// Create a connection wrapper that includes the initial data
	reader := io.MultiReader(strings.NewReader(string(initialData)), clientConn)
	wrappedConn := &connWrapper{
		Conn:   clientConn,
		reader: reader,
	}

	var actualHostname string

	// Wrap the connection with TLS using dynamic certificate generation
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Use the SNI (Server Name Indication) to get the correct hostname
			actualHostname = hello.ServerName
			if actualHostname == "" {
				// Fallback to IP if no SNI; parse host:port safely (IPv6 aware)
				host, _, err := net.SplitHostPort(originalDest)
				if err != nil {
					actualHostname = originalDest
				} else {
					actualHostname = strings.Trim(host, "[]")
				}
			}

			return p.getCertificate(actualHostname)
		},
	}

	tlsConn := tls.Server(wrappedConn, tlsConfig)
	defer tlsConn.Close()

	// Handle the TLS connection
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error for %s: %v", originalDest, err)
		return
	}

	// Use the hostname from SNI if available, otherwise fall back to originalDest
	targetHost := actualHostname
	if targetHost == "" || net.ParseIP(targetHost) != nil {
		targetHost = originalDest
	} else {
		// For hostname, preserve port from originalDest
		_, port, err := net.SplitHostPort(originalDest)
		if err == nil {
			targetHost = net.JoinHostPort(targetHost, port)
		}
	}

	// Check connect policy for HTTPS connections
	destHost, destPort, err := net.SplitHostPort(originalDest)
	if err != nil {
		destHost = originalDest
		destPort = "443"
	}
	portNum, _ := strconv.ParseUint(destPort, 10, 16)

	// Use SNI hostname if available, otherwise use destination host
	hostname := actualHostname
	if hostname == "" {
		hostname = destHost
	}

	if !p.checkConnectPolicy(hostname, destHost, uint16(portNum)) {
		// For HTTPS connection denials, we don't have specific path/query/auth info yet
		p.blockConnection(tlsConn, true, hostname, destHost, uint16(portNum), "/", "", "")
		return
	}

	// Handle HTTP requests over the TLS connection
	bufferedReader := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(bufferedReader)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading HTTPS request: %v", err)
			}
			break
		}

		// Set the proper URL using the hostname
		req.URL.Scheme = "https"
		req.URL.Host = targetHost
		req.RequestURI = ""

		// Extract request details for logging
		host, port, err := net.SplitHostPort(targetHost)
		if err != nil {
			host = targetHost
			port = "443"
		}
		path := req.URL.Path
		if path == "" {
			path = "/"
		}
		query := req.URL.RawQuery
		authHeader := req.Header.Get("Authorization")

		// Unique request logging removed

		var mcpCtx *mcpRequestContext
		if p.mcpObserver != nil {
			if ctx, sniffErr := p.mcpObserver.inspectHTTPRequest(req, host); sniffErr == nil {
				mcpCtx = ctx
			} else {
				log.Printf("mcp sniff (https) error: %v", sniffErr)
			}
		}
		serverForPolicy := req.URL.Hostname()
		if serverForPolicy == "" {
			serverForPolicy = host
		}
		if p.enforceMCPCall(tlsConn, mcpCtx, serverForPolicy, host, port, path, query, authHeader, "https") {
			break
		}

		// Apply header rewriting rules
		p.headerRewriter.ApplyRules(req)

		responseCode, _, sessionHeader, forwardErr := p.forwardTransparentHTTPS(tlsConn, req, targetHost, mcpCtx)

		if mcpCtx != nil {
			outcome := classifyOutcome(responseCode, forwardErr)
			p.mcpObserver.logHTTPRequest(mcpCtx, responseCode, outcome, sessionHeader, forwardErr)
		}

		// Log request to logfmt
		p.logRequest("https", host, port, path, query, authHeader, responseCode, forwardErr)
	}
}

func (p *MITMProxy) forwardTransparentHTTPS(clientConn net.Conn, req *http.Request, targetHost string, mcpCtx *mcpRequestContext) (int, string, string, error) {
	// Create marked TLS connection to target to avoid proxy loops
	dialer := p.tlsDialer
	if dialer == nil {
		dialer = p.createMarkedTLSConnection
	}
	targetConn, err := dialer(targetHost)
	if err != nil {
		log.Printf("Error connecting to target %s: %v", targetHost, err)
		return 0, "", "", err
	}
	defer targetConn.Close()

	// Forward the request
	if err := req.Write(targetConn); err != nil {
		log.Printf("Error writing request to target: %v", err)
		return 0, "", "", err
	}

	// Read the response
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		return 0, "", "", err
	}
	defer resp.Body.Close()

	sessionHeader := resp.Header.Get("Mcp-Session-Id")
	contentType := resp.Header.Get("Content-Type")
	transport := transportFromHeader(contentType)
	serverHost := req.URL.Hostname()
	if serverHost == "" {
		serverHost = req.Host
	}
	if serverHost == "" {
		serverHost = targetHost
	}

	if mcpCtx != nil && mcpCtx.sampled {
		mcpCtx.transport = transport
		if transport == "sse" {
			resp.Body = p.mcpObserver.wrapSSEBody(mcpCtx, resp.Body)
		} else {
			p.mcpObserver.inspectHTTPResponse(mcpCtx, resp)
		}
		p.mcpObserver.registerSession(sessionHeader, mcpCtx)
	} else if p.mcpObserver != nil && transport == "sse" {
		protoHeader := strings.TrimSpace(req.Header.Get("MCP-Protocol-Version"))
		resp.Body = p.mcpObserver.wrapSessionSSE(sessionHeader, serverHost, protoHeader, resp.Body)
	}

	// Forward the response to client
	writeErr := resp.Write(clientConn)
	if writeErr != nil {
		log.Printf("Error writing response to client: %v", writeErr)
		return resp.StatusCode, contentType, sessionHeader, writeErr
	}

	return resp.StatusCode, contentType, sessionHeader, nil
}

func (p *MITMProxy) getCertificate(host string) (*tls.Certificate, error) {
	p.certCacheMux.RLock()
	if cert, ok := p.certCache[host]; ok {
		p.certCacheMux.RUnlock()
		return cert, nil
	}
	p.certCacheMux.RUnlock()

	p.certCacheMux.Lock()
	defer p.certCacheMux.Unlock()

	// Double-check after acquiring write lock
	if cert, ok := p.certCache[host]; ok {
		return cert, nil
	}

	// Generate new certificate
	cert, err := p.ca.GenerateCertificate(host)
	if err != nil {
		return nil, err
	}

	p.certCache[host] = cert
	return cert, nil
}

// logRequest logs a request in logfmt format to the shared event log
func (p *MITMProxy) logRequest(reqType, host, port, path, query, authHeader string, responseCode int, err error) {
	// Log to shared logger
	if p.sharedLogger != nil {
		timestamp := time.Now().Format(time.RFC3339) // ISO 8601 format

		// Determine result
		resultStr := "allowed"
		if err != nil {
			resultStr = "denied"
		}

		// Build destination
		destStr := host
		if port != "" && port != "80" && port != "443" {
			destStr = fmt.Sprintf("%s:%s", host, port)
		}

		// Build path with query
		fullPath := path
		if query != "" {
			fullPath = fmt.Sprintf("%s?%s", path, query)
		}

		// Create compact logfmt entry matching LSM style
		logEntry := fmt.Sprintf("time=%s event=http.request protocol=%s addr=\"%s\" path=\"%s\" decision=%s",
			timestamp, reqType, destStr, fullPath, resultStr)

		if responseCode > 0 {
			logEntry += fmt.Sprintf(" status=%d", responseCode)
		}

		if authHeader != "" {
			logEntry += fmt.Sprintf(" auth=\"%s\"", authHeader[:min(len(authHeader), 20)]) // Truncate for security
		}

		if err != nil {
			logEntry += fmt.Sprintf(" error=\"%s\"", err.Error())
		}

		_ = p.sharedLogger.Write(logEntry)
	}

}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func transportFromHeader(contentType string) string {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if strings.Contains(contentType, "text/event-stream") {
		return "sse"
	}
	if strings.Contains(contentType, "json") {
		return "json"
	}
	return ""
}

func classifyOutcome(status int, err error) string {
	if err != nil {
		return "error"
	}
	if status >= 400 && status != 0 {
		return "error"
	}
	return "success"
}
