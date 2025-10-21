package lsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

// Connect policy rule structure - must match BPF code
type ConnectPolicyRule struct {
	Action      int32     // 0 = deny, 1 = allow
	Operation   int32     // Always OP_CONNECT (4) for this program
	DestIP      uint32    // IPv4 destination (0 = any IP, for hostname rules)
	DestPort    uint16    // Destination port (0 = any port)
	Hostname    [128]byte // Hostname pattern (empty for IP-only rules)
	HostnameLen int32     // Length of hostname for efficient matching
	IsWildcard  int32     // 1 if hostname starts with *.
}

// String returns a human-readable representation of a ConnectPolicyRule
func (rule *ConnectPolicyRule) String() string {
	var parts []string

	// Action
	action := "deny"
	if rule.Action == 1 {
		action = "allow"
	}
	parts = append(parts, fmt.Sprintf("action=%s", action))

	// Operation (should always be OP_CONNECT for this rule type)
	parts = append(parts, fmt.Sprintf("operation=%d", rule.Operation))

	// Destination IP
	if rule.DestIP == 0 {
		parts = append(parts, "dest_ip=any")
	} else {
		// Convert uint32 to IP address
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, rule.DestIP)
		parts = append(parts, fmt.Sprintf("dest_ip=%s", ip.String()))
	}

	// Destination Port
	if rule.DestPort == 0 {
		parts = append(parts, "dest_port=any")
	} else {
		parts = append(parts, fmt.Sprintf("dest_port=%d", rule.DestPort))
	}

	// Hostname
	if rule.HostnameLen > 0 && rule.Hostname[0] != '*' {
		hostname := string(bytes.TrimRight(rule.Hostname[:rule.HostnameLen], "\x00"))
		if rule.IsWildcard == 1 {
			parts = append(parts, fmt.Sprintf("hostname=%s (wildcard)", hostname))
		} else {
			parts = append(parts, fmt.Sprintf("hostname=%s", hostname))
		}
	} else {
		if rule.IsWildcard == 1 {
			// shouldn't happen but for debugging
			parts = append(parts, "hostname=any (wildcard)")
		} else {
			parts = append(parts, "hostname=any")
		}
	}

	return fmt.Sprintf("ConnectPolicyRule{%s}", strings.Join(parts, ", "))
}

// ConnectPolicyRuleBPF matches struct connect_policy_rule in BPF exactly (152 bytes)
type ConnectPolicyRuleBPF struct {
	Action      uint32
	Operation   uint32
	DestIP      uint32
	DestPort    uint16
	_pad0       [2]byte
	Hostname    [128]byte
	HostnameLen uint32
	IsWildcard  uint32
}

// Connect event structure - must match BPF code
type ConnectEvent struct {
	PID          uint32
	TGID         uint32
	Timestamp    uint64
	CgroupID     uint64
	Comm         [16]byte
	Family       uint32    // AF_INET, AF_INET6
	Protocol     uint32    // IPPROTO_TCP, IPPROTO_UDP
	DestIP       uint32    // IPv4 destination (network byte order)
	DestPort     uint16    // Destination port (network byte order)
	Result       int32     // Result of the connect operation (0 = allowed, -EACCES = denied)
	DestHostname [128]byte // Resolved hostname if available
}

const (
	MaxConnectPolicyRules = 256
	// Note: OpConnect is defined in common.go
)

type ConnectLsmLoader func() (*ebpf.CollectionSpec, error)

type ConnectLsm struct {
	cgroupPath string
	logger     *SharedLogger

	policyRules         []ConnectPolicyRuleBPF
	numPolicyRules      int
	defaultPolicyResult bool       // Default policy result: false=deny, true=allow
	logMutex            sync.Mutex // Protect concurrent writes to stdout and log file

	// DNS cache for hostname resolution
	dnsCache    map[uint32]string // IP -> hostname mapping
	dnsCacheMux sync.RWMutex

	// BPF program state
	ebpfCollection *ebpf.Collection
}

func NewConnectLsm(cgroupPath string, logger *SharedLogger) (*ConnectLsm, error) {
	if cgroupPath == "" {
		return nil, fmt.Errorf("cgroup path is required")
	}

	l := &ConnectLsm{
		cgroupPath: cgroupPath,
		logger:     logger,

		dnsCache:            make(map[uint32]string),
		defaultPolicyResult: false, // Default to deny (false)
	}

	// Note: Policy loading is now done separately via LoadPolicies()
	return l, nil
}

// Interface methods for LSMModule

func (l *ConnectLsm) getCgroupPath() string {
	return l.cgroupPath
}

func (l *ConnectLsm) setEbpfCollection(coll *ebpf.Collection) {
	l.ebpfCollection = coll
}

// LoadPolicies loads connect policy rules into the LSM
func (l *ConnectLsm) LoadPolicies(policies []ConnectPolicyRule, defaultOverride *bool) error {
	// Convert hostname-based rules to IP-based rules so kernel enforces IP+port only
	var expanded []ConnectPolicyRuleBPF
	var skippedWildcard, failedResolves int

	// Reset DNS cache before repopulating
	l.dnsCacheMux.Lock()
	l.dnsCache = make(map[uint32]string)
	l.dnsCacheMux.Unlock()

	allowAny := false
	explicitDefault := defaultOverride != nil
	if explicitDefault {
		l.defaultPolicyResult = *defaultOverride
	} else {
		l.defaultPolicyResult = false
	}
	for _, rule := range policies {
		// If rule already has an IP (non-zero), keep as-is
		if rule.DestIP != 0 {
			expanded = append(expanded, ConnectPolicyRuleBPF{
				Action:      uint32(rule.Action),
				Operation:   uint32(rule.Operation),
				DestIP:      rule.DestIP,
				DestPort:    rule.DestPort,
				Hostname:    [128]byte{},
				HostnameLen: 0,
				IsWildcard:  0,
			})
			continue
		}

		// Hostname-based rule
		if rule.HostnameLen == 0 {
			// No IP and no hostname means "any"; keep as-is
			expanded = append(expanded, ConnectPolicyRuleBPF{
				Action:      uint32(rule.Action),
				Operation:   uint32(rule.Operation),
				DestIP:      0,
				DestPort:    rule.DestPort,
				Hostname:    [128]byte{},
				HostnameLen: 0,
				IsWildcard:  0,
			})
			continue
		}

		// Skip wildcards in kernel; enforce via userspace proxy
		if rule.IsWildcard == 1 {
			skippedWildcard++
			continue
		}

		hostname := string(bytes.TrimRight(rule.Hostname[:], "\x00"))
		// Special case: "*" means allow any destination via default allow policy
		if hostname == "*" && rule.Action == PolicyAllow {
			if !explicitDefault {
				allowAny = true
			}
			continue
		}
		ips, err := net.LookupIP(hostname)
		if err != nil {
			failedResolves++
			continue
		}

		// Create IP rules for each resolved IPv4
		for _, ip := range ips {
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			ipNum := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
			var newRule ConnectPolicyRuleBPF
			newRule.Action = uint32(rule.Action)
			newRule.Operation = uint32(rule.Operation)
			newRule.DestIP = ipNum
			newRule.DestPort = rule.DestPort
			newRule.Hostname = [128]byte{}
			newRule.HostnameLen = 0
			newRule.IsWildcard = 0
			expanded = append(expanded, newRule)

			// Populate DNS cache for logging/BPF map
			l.dnsCacheMux.Lock()
			l.dnsCache[ipNum] = hostname
			l.dnsCacheMux.Unlock()
		}
	}

	l.policyRules = expanded
	l.numPolicyRules = len(expanded)

	// Sort by port then IP for readability (optional)
	sort.Slice(l.policyRules, func(i, j int) bool {
		if l.policyRules[i].DestPort == l.policyRules[j].DestPort {
			return l.policyRules[i].DestIP < l.policyRules[j].DestIP
		}
		return l.policyRules[i].DestPort < l.policyRules[j].DestPort
	})

	if !explicitDefault {
		// Check if root path "/" is allowed to set default policy result
		l.checkRootConnectPolicy()

		// If we saw "allow net.send *", set default allow in the kernel
		if allowAny {
			l.defaultPolicyResult = true
		}
	}

	fmt.Printf("Loaded %d connect IP rules (skipped %d wildcard, %d unresolved)\n", l.numPolicyRules, skippedWildcard, failedResolves)
	if explicitDefault {
		if l.defaultPolicyResult {
			fmt.Printf("Default connect policy result: ALLOW (configured override)\n")
		} else {
			fmt.Printf("Default connect policy result: DENY (configured override)\n")
		}
	} else {
		if l.defaultPolicyResult {
			fmt.Printf("Default connect policy result: ALLOW (wildcard '*' is allowed)\n")
		} else {
			fmt.Printf("Default connect policy result: DENY (no wildcard rule found)\n")
		}
	}

	// If eBPF collection is already loaded, update the BPF maps
	if l.ebpfCollection != nil {
		if err := l.loadPolicyIntoBPF(l.ebpfCollection); err != nil {
			return fmt.Errorf("failed to update BPF maps: %w", err)
		}

		// Also update the DNS cache in BPF
		if err := l.updateDNSCacheInBPF(l.ebpfCollection); err != nil {
			fmt.Printf("Warning: failed to update DNS cache in BPF: %v\n", err)
		}

		fmt.Printf("Updated BPF maps with new connect policies\n")
	}

	return nil
}

// checkRootConnectPolicy checks if there's a wildcard rule that allows all connections
func (l *ConnectLsm) checkRootConnectPolicy() {
	// Default is false (deny)
	l.defaultPolicyResult = false

	// For connect policies, we consider a rule that allows all IPs/hostnames as permissive
	for _, rule := range l.policyRules {
		if rule.Action == PolicyAllow && rule.DestIP == 0 && rule.HostnameLen == 0 {
			l.defaultPolicyResult = true
			break
		}
	}
}

func (l *ConnectLsm) LoadAndAttach(loader func() (*ebpf.CollectionSpec, error)) error {
	config := BPFConfig{
		ProgramNames:      []string{"lsm_connect", "lsm_sendmsg"},
		EventMapName:      "connect_events",
		AllowedCgroupsMap: "connect_allowed_cgroups",
		TargetCgroupMap:   "connect_target_cgroup",
		StartMessage:      "Successfully started monitoring network connections and sendmsg operations",
		ShutdownMessage:   "Shutting down connect LSM tracker",
	}

	// Custom setup for DNS cache
	customSetup := func(coll *ebpf.Collection) error {
		// Load DNS cache into BPF maps
		if err := l.updateDNSCacheInBPF(coll); err != nil {
			fmt.Printf("Warning: failed to load DNS cache into BPF: %v\n", err)
		}
		return nil
	}

	return LoadAndAttachBPFWithSetup(l, loader, config, customSetup)
}

func (l *ConnectLsm) loadPolicyIntoBPF(coll *ebpf.Collection) error {
	// Always load the default policy result into BPF map
	key := uint32(0)
	defaultResult := uint32(0) // Default to deny
	if l.defaultPolicyResult {
		defaultResult = uint32(1) // Allow
	}
	if err := coll.Maps["connect_default_policy"].Put(&key, &defaultResult); err != nil {
		return fmt.Errorf("failed to update connect_default_policy map: %w", err)
	}

	if l.numPolicyRules == 0 {
		fmt.Printf("No connect policy rules to load, using default policy result: %v\n", l.defaultPolicyResult)
		return nil
	}

	// Load the number of rules
	numRules := int32(l.numPolicyRules)
	if err := coll.Maps["connect_num_rules"].Put(&key, &numRules); err != nil {
		return fmt.Errorf("failed to update connect_num_rules map: %w", err)
	}

	fmt.Printf("Loading %d connect policy rules into BPF maps...\n", l.numPolicyRules)

	// Load each policy rule
	for i := 0; i < l.numPolicyRules; i++ {
		if err := coll.Maps["connect_policy_rules"].Put(uint32(i), &l.policyRules[i]); err != nil {
			return fmt.Errorf("failed to update connect_policy_rules map for rule %d: %w", i, err)
		}

		// actionStr := "deny"
		// if l.policyRules[i].Action == PolicyAllow {
		// 	actionStr = "allow"
		// }

		// var targetStr string
		// if l.policyRules[i].DestIP != 0 {
		// 	// IP-based rule
		// 	ip := make(net.IP, 4)
		// 	binary.BigEndian.PutUint32(ip, l.policyRules[i].DestIP)
		// 	targetStr = ip.String()
		// } else if l.policyRules[i].HostnameLen > 0 {
		// 	// Hostname-based rule
		// 	hostname := string(bytes.TrimRight(l.policyRules[i].Hostname[:], "\x00"))
		// 	targetStr = hostname
		// } else {
		// 	targetStr = "*" // Any destination
		// }

		// portStr := ""
		// if l.policyRules[i].DestPort != 0 {
		// 	portStr = fmt.Sprintf(":%d", l.policyRules[i].DestPort)
		// }

		// wildcardStr := ""
		// if l.policyRules[i].IsWildcard == 1 {
		// 	wildcardStr = " (wildcard)"
		// }

		// fmt.Printf("Loaded connect rule %d: %s connect %s%s%s\n", i, actionStr, targetStr, portStr, wildcardStr)
	}

	// fmt.Printf("Successfully loaded all connect policy rules into BPF\n")
	return nil
}

// validateConnectEvent checks if the event data is properly formed
func validateConnectEvent(event *ConnectEvent) bool {
	return validateEventArrays(event.Comm[:], event.DestHostname[:])
}

func (l *ConnectLsm) handleEvent(data []byte) {
	if len(data) < int(unsafe.Sizeof(ConnectEvent{})) {
		fmt.Fprintf(os.Stderr, "Error: received incomplete connect event\n")
		return
	}

	var event ConnectEvent
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to parse connect event: %v\n", err)
		return
	}

	// Validate event data to prevent corruption
	if !validateConnectEvent(&event) {
		fmt.Fprintf(os.Stderr, "Error: received corrupted connect event data\n")
		return
	}

	// Extract strings from byte arrays with safe conversion
	comm := safeString(event.Comm[:])
	hostname := safeString(event.DestHostname[:])

	// Additional validation
	if len(comm) == 0 {
		fmt.Fprintf(os.Stderr, "Error: received connect event with empty comm\n")
		return
	}

	// Convert destination IP from network byte order
	destIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(destIP, event.DestIP)

	// Convert port from network byte order
	destPort := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&event.DestPort))[:])

	// Use current time for ISO 8601 format (BPF timestamp is kernel boot time, not Unix time)
	timestamp := time.Now().Format(time.RFC3339)

	// Format result string
	resultStr := "allowed"
	if event.Result != 0 {
		resultStr = "denied"
	}

	// Determine protocol string
	protocolStr := "unknown"
	switch event.Protocol {
	case 6: // IPPROTO_TCP
		protocolStr = "tcp"
	case 17: // IPPROTO_UDP
		protocolStr = "udp"
	}

	// Create destination string
	destStr := destIP.String()
	if destPort != 0 {
		destStr = fmt.Sprintf("%s:%d", destStr, destPort)
	}

	// Add hostname if available
	hostnameStr := ""
	if len(hostname) > 0 {
		hostnameStr = fmt.Sprintf(" hostname=\"%s\"", hostname)
	}

	// Format in logfmt (key=value pairs)
	logEntry := fmt.Sprintf("time=%s event=net.send pid=%d cgroup=%d exe=\"%s\" protocol=%s addr=\"%s\"%s decision=%s",
		timestamp, event.PID, event.CgroupID, comm, protocolStr, destStr, hostnameStr, resultStr)

	// Protect concurrent writes with mutex
	l.logMutex.Lock()
	defer l.logMutex.Unlock()

	// Write to shared logger if configured
	if l.logger != nil {
		_ = l.logger.Write(logEntry)
	}

	// Unique connect logging removed

	// Update DNS cache if hostname is provided
	if len(hostname) > 0 {
		l.dnsCacheMux.Lock()
		l.dnsCache[event.DestIP] = hostname
		l.dnsCacheMux.Unlock()
	}
}

// UpdateDNSCache allows external components (like DNS monitoring) to update the hostname cache
func (l *ConnectLsm) UpdateDNSCache(ip uint32, hostname string) {
	l.dnsCacheMux.Lock()
	defer l.dnsCacheMux.Unlock()
	l.dnsCache[ip] = hostname
}

// GetDNSCache returns the current DNS cache for integration with BPF maps
func (l *ConnectLsm) GetDNSCache() map[uint32]string {
	l.dnsCacheMux.RLock()
	defer l.dnsCacheMux.RUnlock()

	cache := make(map[uint32]string)
	for ip, hostname := range l.dnsCache {
		cache[ip] = hostname
	}
	return cache
}

// SimplePolicyChecker implements a basic policy checker for MITMProxy integration
type SimplePolicyChecker struct {
	rules         []ConnectPolicyRule
	defaultPolicy bool // true = allow, false = deny
	mcpRules      []MCPPolicyRule
}

// NewSimplePolicyChecker creates a new policy checker with the given rules
func NewSimplePolicyChecker(rules []ConnectPolicyRule, defaultPolicy bool, mcpRules []MCPPolicyRule) *SimplePolicyChecker {
	return &SimplePolicyChecker{
		rules:         rules,
		defaultPolicy: defaultPolicy,
		mcpRules:      normalizeMCPRules(mcpRules),
	}
}

// CheckConnect implements the PolicyChecker interface for MITMProxy
func (pc *SimplePolicyChecker) CheckConnect(hostname string, ip string, port uint16) bool {
	// Convert IP string to uint32 for comparison
	var ipNum uint32
	if net.ParseIP(ip) != nil {
		ipAddr := net.ParseIP(ip).To4()
		if ipAddr != nil {
			ipNum = uint32(ipAddr[0])<<24 | uint32(ipAddr[1])<<16 | uint32(ipAddr[2])<<8 | uint32(ipAddr[3])
		}
	}

	// Check each rule (rules should be sorted by specificity)
	for _, rule := range pc.rules {
		matches := false

		// Check IP match (0 means any IP, for hostname-only rules)
		if rule.DestIP != 0 && rule.DestIP != ipNum {
			continue
		}

		// Check port match (0 means any port)
		if rule.DestPort != 0 && rule.DestPort != port {
			continue
		}

		// Check hostname match if hostname is provided and rule has hostname restriction
		if rule.HostnameLen > 0 {
			ruleHostname := string(bytes.TrimRight(rule.Hostname[:], "\x00"))

			if rule.IsWildcard == 1 {
				// Wildcard matching (*.example.com)
				if len(ruleHostname) >= 2 && ruleHostname[:2] == "*." {
					suffix := ruleHostname[2:]
					if strings.HasSuffix(hostname, suffix) {
						// Ensure it's a proper subdomain match
						if len(hostname) > len(suffix) {
							matches = true
						}
					}
				}
			} else {
				// Exact hostname match
				if hostname == ruleHostname || ruleHostname == "*" {
					matches = true
				}
			}
		} else {
			// No hostname restriction, matches if IP and port match
			matches = true
		}

		if matches {
			return rule.Action == PolicyAllow
		}
	}

	log.Printf("CheckConnect: no rule matched, using default policy: %v", pc.defaultPolicy)

	// No rule matched, use default policy
	return pc.defaultPolicy
}

// CheckMCPCall evaluates whether an MCP tools/call should be allowed, matching on server and tool.
func (pc *SimplePolicyChecker) CheckMCPCall(server string, tool string) bool {
	if len(pc.mcpRules) == 0 {
		return true
	}
	host := normalizeServer(server)
	toolName := strings.ToLower(strings.TrimSpace(tool))
	for _, rule := range pc.mcpRules {
		if rule.Server != "" && host != rule.Server {
			continue
		}
		if rule.Tool != "" && toolName != rule.Tool {
			continue
		}
		return rule.Action == PolicyAllow
	}
	return true
}

// HasMCPPolicies indicates whether any MCP rules are configured.
func (pc *SimplePolicyChecker) HasMCPPolicies() bool {
	return len(pc.mcpRules) > 0
}

func normalizeMCPRules(rules []MCPPolicyRule) []MCPPolicyRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]MCPPolicyRule, 0, len(rules))
	seen := make(map[string]struct{})
	for _, rule := range rules {
		server := normalizeServer(rule.Server)
		tool := strings.ToLower(strings.TrimSpace(rule.Tool))
		key := fmt.Sprintf("%d|%s|%s", rule.Action, server, tool)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, MCPPolicyRule{
			Action: rule.Action,
			Server: server,
			Tool:   tool,
		})
	}
	return out
}

func normalizeServer(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			if host := u.Hostname(); host != "" {
				s = host
			}
		}
	}
	if strings.Contains(s, "/") {
		s = strings.SplitN(s, "/", 2)[0]
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	}
	return strings.TrimSpace(s)
}

// resolveHostnamesFromPolicies proactively resolves hostnames from connect policies
func (l *ConnectLsm) resolveHostnamesFromPolicies() error {
	var resolveErrors []string
	resolvedCount := 0

	for _, rule := range l.policyRules {
		if rule.HostnameLen == 0 {
			continue // IP-only rule, skip
		}

		hostname := string(bytes.TrimRight(rule.Hostname[:], "\x00"))

		// Skip wildcard hostnames - we can't resolve *.example.com
		if rule.IsWildcard == 1 {
			continue
		}

		// Resolve hostname to IP addresses
		ips, err := net.LookupIP(hostname)
		if err != nil {
			resolveErrors = append(resolveErrors, fmt.Sprintf("%s: %v", hostname, err))
			continue
		}

		// Add all resolved IPs to our DNS cache
		l.dnsCacheMux.Lock()
		for _, ip := range ips {
			ipv4 := ip.To4()
			if ipv4 != nil {
				// Convert to uint32 in network byte order
				ipNum := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
				l.dnsCache[ipNum] = hostname
				resolvedCount++
			}
		}
		l.dnsCacheMux.Unlock()
	}

	if resolvedCount > 0 {
		fmt.Printf("Resolved %d hostname entries for connect policies\n", resolvedCount)
	}

	if len(resolveErrors) > 0 {
		return fmt.Errorf("failed to resolve %d hostnames: %s", len(resolveErrors), strings.Join(resolveErrors, "; "))
	}

	return nil
}

// updateDNSCacheInBPF updates the BPF DNS cache map with current hostname mappings
func (l *ConnectLsm) updateDNSCacheInBPF(coll *ebpf.Collection) error {
	dnsMap := coll.Maps["dns_cache"]
	if dnsMap == nil {
		return fmt.Errorf("dns_cache map not found")
	}

	l.dnsCacheMux.RLock()
	defer l.dnsCacheMux.RUnlock()

	// Clear existing cache entries first
	// Note: We could iterate and delete, but for simplicity, we'll just overwrite

	updatedCount := 0
	for ip, hostname := range l.dnsCache {
		var hostnameBytes [128]byte
		copy(hostnameBytes[:], hostname)

		if err := dnsMap.Put(&ip, &hostnameBytes); err != nil {
			fmt.Printf("Warning: failed to update DNS cache for %s (%d): %v\n", hostname, ip, err)
			continue
		}
		updatedCount++
	}

	if updatedCount > 0 {
		fmt.Printf("Updated %d DNS cache entries in BPF map\n", updatedCount)
	}

	return nil
}
