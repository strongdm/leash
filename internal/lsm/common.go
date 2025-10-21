package lsm

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Common policy rule structure that can be converted to specific types
type PolicyRule struct {
	Action      int32 // 0 = deny, 1 = allow
	Operation   int32 // 0 = open, 1 = open:ro, 2 = open:rw, 3 = exec, 4 = connect
	PathLen     int32
	Path        [256]byte
	IsDirectory int32 // 1 if path ends with /

	// Argument matching (only used for exec operations)
	ArgCount    int32       // Number of args to match (0 = match any)
	HasWildcard int32       // 1 if rule ends with * (allow rules only)
	Args        [4][32]byte // Up to 4 args, 32 chars each
	ArgLens     [4]int32    // Length of each arg for efficient matching

	// Network connection matching (only used for connect operations)
	DestIP      uint32    // IPv4 destination (0 = any IP, for hostname rules)
	DestPort    uint16    // Destination port (0 = any port)
	Hostname    [128]byte // Hostname pattern (empty for IP-only rules)
	HostnameLen int32     // Length of hostname for efficient matching
	IsWildcard  int32     // 1 if hostname starts with *.
}

// MCPPolicyRule captures deny/allow semantics for MCP tools/call requests.
// Server and Tool are normalized to lowercase without schemes; empty values act as wildcards.
type MCPPolicyRule struct {
	Action int32  // 0 = deny, 1 = allow
	Server string // empty matches any server
	Tool   string // empty matches any tool
}

const (
	PolicyDeny  = 0
	PolicyAllow = 1

	// Operation types
	OpOpen    = 0 // open (any mode)
	OpOpenRO  = 1 // open:ro (read-only)
	OpOpenRW  = 2 // open:rw (any write mode)
	OpExec    = 3 // exec
	OpConnect = 4 // connect
)

// PolicySet holds separated policy rules by operation type
type PolicySet struct {
	Open    []PolicyRule
	Exec    []PolicyRule
	Connect []PolicyRule
	MCP     []MCPPolicyRule

	// ConnectDefaultAllow indicates whether the default net.send posture is allow (true) or deny (false).
	// ConnectDefaultExplicit tracks whether the default posture was explicitly configured in the policy file.
	ConnectDefaultAllow    bool
	ConnectDefaultExplicit bool
}

// String returns the canonical string representation of a PolicyRule
func (pr *PolicyRule) String() string {
	action := "deny"
	if pr.Action == PolicyAllow {
		action = "allow"
	}

	var operation string
	switch pr.Operation {
	case OpOpen:
		operation = "file.open"
	case OpOpenRO:
		operation = "file.open:ro"
	case OpOpenRW:
		operation = "file.open:rw"
	case OpExec:
		operation = "proc.exec"
	case OpConnect:
		operation = "net.send"
	}

	var target string
	if pr.Operation == OpConnect {
		// Use hostname or IP
		if pr.HostnameLen > 0 {
			hostname := string(pr.Hostname[:pr.HostnameLen])
			if pr.DestPort > 0 {
				target = fmt.Sprintf("%s:%d", hostname, pr.DestPort)
			} else {
				target = hostname
			}
		} else if pr.DestIP > 0 {
			ip := fmt.Sprintf("%d.%d.%d.%d",
				(pr.DestIP>>24)&0xFF, (pr.DestIP>>16)&0xFF,
				(pr.DestIP>>8)&0xFF, pr.DestIP&0xFF)
			if pr.DestPort > 0 {
				target = fmt.Sprintf("%s:%d", ip, pr.DestPort)
			} else {
				target = ip
			}
		}
	} else {
		// Use path
		target = string(bytes.TrimRight(pr.Path[:pr.PathLen], "\x00"))
	}

	result := fmt.Sprintf("%s %s %s", action, operation, target)

	// Add args for exec operations (blacklist only)
	if pr.Operation == OpExec && pr.ArgCount > 0 {
		var args []string
		for i := int32(0); i < pr.ArgCount; i++ {
			arg := string(bytes.TrimRight(pr.Args[i][:pr.ArgLens[i]], "\x00"))
			args = append(args, arg)
		}
		result += " " + strings.Join(args, " ")
	}

	return result
}

func (ps *PolicySet) HasOpenPolicies() bool { return len(ps.Open) > 0 }
func (ps *PolicySet) HasExecPolicies() bool { return len(ps.Exec) > 0 }
func (ps *PolicySet) HasConnectPolicies() bool {
	return len(ps.Connect) > 0 || ps.ConnectDefaultExplicit
}

// parsePolicyLine parses a single policy line into a PolicyRule
func parsePolicyLine(line string, lineNum int) (PolicyRule, error) {
	// Parse line: action operation path [args...]
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return PolicyRule{}, fmt.Errorf("invalid policy line: %s (expected: action operation path [args...])", line)
	}

	actionStr := parts[0]
	operation := parts[1]
	path := parts[2]
	args := parts[3:] // Arguments (only for exec operations)

	var rule PolicyRule

	// Parse action
	switch actionStr {
	case "allow":
		rule.Action = PolicyAllow
	case "deny":
		rule.Action = PolicyDeny
	default:
		return PolicyRule{}, fmt.Errorf("invalid action '%s' (must be 'allow' or 'deny')", actionStr)
	}

	// Parse operation type
	var opType int32
	switch operation {
	// File operations
	case "file.open":
		opType = OpOpen
	case "file.open:ro":
		opType = OpOpenRO
	case "file.open:rw":
		opType = OpOpenRW
	// Process operations
	case "proc.exec":
		opType = OpExec
	// Network operations
	case "net.send":
		opType = OpConnect
	// HTTP operations (handled separately by policy package)
	case "http.rewrite":
		// Skip HTTP rewrite rules - they're handled by the policy package
		return PolicyRule{}, fmt.Errorf("skip_http_rule")
	default:
		return PolicyRule{}, fmt.Errorf("unsupported operation '%s'", operation)
	}
	rule.Operation = opType

	// Handle operation-specific parsing
	if opType == OpConnect {
		// For connect operations, "path" is actually hostname/IP
		target := path

		// Parse hostname:port or IP:port
		var hostname string
		var port uint16

		if strings.Contains(target, ":") {
			parts := strings.SplitN(target, ":", 2)
			hostname = parts[0]
			if portNum, err := parsePort(parts[1]); err != nil {
				return PolicyRule{}, fmt.Errorf("invalid port '%s': %v", parts[1], err)
			} else {
				port = portNum
			}
		} else {
			hostname = target
			port = 0 // Any port
		}

		// Validate hostname length
		if len(hostname) >= 128 {
			return PolicyRule{}, fmt.Errorf("hostname too long (max 127 chars)")
		}

		// Check if it's an IP address or hostname
		if isIPAddress(hostname) {
			// Parse IP address
			ip, err := parseIPAddress(hostname)
			if err != nil {
				return PolicyRule{}, fmt.Errorf("invalid IP address '%s': %v", hostname, err)
			}
			rule.DestIP = ip
			rule.DestPort = port
			// Leave hostname empty for IP-only rules
		} else {
			// Hostname-based rule
			rule.DestIP = 0 // Any IP
			rule.DestPort = port

			// Check for wildcard
			if strings.HasPrefix(hostname, "*.") {
				rule.IsWildcard = 1
			}

			copy(rule.Hostname[:], hostname)
			rule.HostnameLen = int32(len(hostname))
		}

		// For connect rules, don't use Path field
		rule.PathLen = 0

	} else {
		// For non-connect operations, resolve symlinks so policy applies to the linked target.
		// Preserve trailing slash semantics for directory rules.
		hasTrailingSlash := strings.HasSuffix(path, "/")

		// Clean the path but operate without trailing slash during resolution
		cleaned := filepath.Clean(path)
		// Trim a single trailing slash for resolution (except root)
		trimmed := strings.TrimSuffix(cleaned, "/")
		if trimmed == "" {
			trimmed = "/"
		}

		// Try to resolve symlinks; if it fails, fall back to the cleaned path
		resolved := trimmed
		if r, err := filepath.EvalSymlinks(trimmed); err == nil && r != "" {
			resolved = r
		} else if err != nil {
			// Emit a warning so users understand why a non-existent path didn't resolve
			fmt.Fprintf(os.Stderr, "Warning on line %d: failed to resolve path '%s': %v; using as-is\n", lineNum, path, err)
		}

		// Re-append trailing slash for directory intent (except root)
		if hasTrailingSlash && resolved != "/" && !strings.HasSuffix(resolved, "/") {
			resolved += "/"
		}

		if len(resolved) >= 256 {
			return PolicyRule{}, fmt.Errorf("path too long (max 255 chars)")
		}

		copy(rule.Path[:], resolved)
		rule.PathLen = int32(len(resolved))
	}

	// Handle arguments (only for exec operations)
	if opType == OpExec && len(args) > 0 {
		// Only deny rules can have arguments (blacklist approach)
		if rule.Action == PolicyAllow {
			return PolicyRule{}, fmt.Errorf("allow rules cannot have arguments - use path-only allows with argument blacklist denies")
		}

		if len(args) > 4 {
			return PolicyRule{}, fmt.Errorf("too many arguments (max 4)")
		}

		// No wildcards for deny rules (blacklist)
		rule.ArgCount = int32(len(args))
		for i, arg := range args {
			if len(arg) >= 32 {
				return PolicyRule{}, fmt.Errorf("argument '%s' too long (max 31 chars)", arg)
			}
			copy(rule.Args[i][:], arg)
			rule.ArgLens[i] = int32(len(arg))
		}
	}

	return rule, nil
}

// ConvertToFileOpenRules converts PolicyRules to FileOpenLsm PolicyRules
func ConvertToFileOpenRules(rules []PolicyRule) []OpenPolicyRule {
	var converted []OpenPolicyRule
	for _, rule := range rules {
		converted = append(converted, OpenPolicyRule{
			Action:      uint32(rule.Action),
			Operation:   uint32(rule.Operation),
			PathLen:     uint32(rule.PathLen),
			Path:        rule.Path,
			IsDirectory: uint32(rule.IsDirectory),
		})
	}
	return converted
}

// ConvertToExecRules converts PolicyRules to ExecLsm ExecPolicyRules
func ConvertToExecRules(rules []PolicyRule) []ExecPolicyRule {
	var converted []ExecPolicyRule
	for _, rule := range rules {
		newRule := ExecPolicyRule{
			Action:      rule.Action,
			Operation:   rule.Operation,
			PathLen:     rule.PathLen,
			Path:        rule.Path,
			IsDirectory: rule.IsDirectory,
			ArgCount:    rule.ArgCount,
			Args:        rule.Args,
			ArgLens:     rule.ArgLens,
		}
		converted = append(converted, newRule)
	}
	return converted
}

// ConvertToConnectRules converts PolicyRules to ConnectLsm ConnectPolicyRules
func ConvertToConnectRules(rules []PolicyRule) []ConnectPolicyRule {
	var converted []ConnectPolicyRule
	for _, rule := range rules {
		newRule := ConnectPolicyRule{
			Action:      rule.Action,
			Operation:   rule.Operation,
			DestIP:      rule.DestIP,
			DestPort:    rule.DestPort,
			Hostname:    rule.Hostname,
			HostnameLen: rule.HostnameLen,
			IsWildcard:  rule.IsWildcard,
		}
		converted = append(converted, newRule)
	}
	return converted
}

// safeString converts byte array to string, handling invalid UTF-8 and ensuring proper termination
func safeString(data []byte) string {
	// Find null terminator
	nullPos := len(data)
	for i, b := range data {
		if b == 0 {
			nullPos = i
			break
		}
	}

	// Truncate at null terminator
	truncated := data[:nullPos]

	// Convert to valid UTF-8 string, replacing invalid sequences
	if len(truncated) == 0 {
		return ""
	}

	// Replace invalid UTF-8 sequences with replacement character
	return strings.ToValidUTF8(string(truncated), "�")
}

// Generic event validation functions

// hasNullTerminator checks if a byte array contains a null terminator
func hasNullTerminator(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

// validateEventArrays validates that required byte arrays in events are properly null-terminated
func validateEventArrays(arrays ...[]byte) bool {
	for _, array := range arrays {
		if !hasNullTerminator(array) {
			return false
		}
	}
	return true
}

// BPF loading configuration and shared functions

// BPFConfig holds configuration for BPF program attachment
type BPFConfig struct {
	ProgramNames      []string // Names of BPF programs to attach
	EventMapName      string   // Name of the event ring buffer map
	AllowedCgroupsMap string   // Name of the allowed cgroups map
	TargetCgroupMap   string   // Name of the target cgroup map
	StartMessage      string   // Success message to display
	ShutdownMessage   string   // Shutdown message to display
}

// LSMModule interface for modules that can load BPF programs
type LSMModule interface {
	loadPolicyIntoBPF(*ebpf.Collection) error
	getCgroupPath() string
	setEbpfCollection(*ebpf.Collection)
	handleEvent([]byte)
}

// LoadAndAttachBPF provides shared BPF loading logic for all LSM modules
func LoadAndAttachBPF(
	module LSMModule,
	loader func() (*ebpf.CollectionSpec, error),
	config BPFConfig,
) error {
	return LoadAndAttachBPFWithSetup(module, loader, config, nil)
}

// LoadAndAttachBPFWithSetup provides shared BPF loading logic with optional custom setup
func LoadAndAttachBPFWithSetup(
	module LSMModule,
	loader func() (*ebpf.CollectionSpec, error),
	config BPFConfig,
	customSetup func(*ebpf.Collection) error,
) error {
	// Load BPF program
	spec, err := loader()
	if err != nil {
		return fmt.Errorf("failed to load BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}
	defer coll.Close()

	// Store the eBPF collection for policy reloading
	module.setEbpfCollection(coll)

	// Load policy into BPF maps
	if err := module.loadPolicyIntoBPF(coll); err != nil {
		return fmt.Errorf("failed to load policy into BPF: %w", err)
	}

	// Run custom setup if provided (e.g., DNS cache updates)
	if customSetup != nil {
		if err := customSetup(coll); err != nil {
			return fmt.Errorf("failed to run custom setup: %w", err)
		}
	}

	// Populate the allowed_cgroups map with the target cgroup subtree
	if err := addDescendantCgroups(coll.Maps[config.AllowedCgroupsMap], module.getCgroupPath()); err != nil {
		return fmt.Errorf("failed to add descendant cgroups: %w", err)
	}

	// Set a non-zero value in target_cgroup to enable monitoring
	key := uint32(0)
	enable := uint64(1)
	if err := coll.Maps[config.TargetCgroupMap].Put(&key, &enable); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable monitoring: %v\n", err)
		os.Exit(1)
	}

	// Attach LSM programs
	var links []link.Link
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	for _, programName := range config.ProgramNames {
		lsmLink, err := link.AttachLSM(link.LSMOptions{
			Program: coll.Programs[programName],
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to attach %s LSM program: %v\n", programName, err)
			fmt.Fprintf(os.Stderr, "Note: LSM attachment requires proper kernel support\n")
			os.Exit(1)
		}
		links = append(links, lsmLink)
	}

	// Set up ring buffer
	rd, err := ringbuf.NewReader(coll.Maps[config.EventMapName])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ring buffer reader: %v\n", err)
		os.Exit(1)
	}
	defer rd.Close()

	// Set up signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	now := time.Now()
	startTime := now.Format("15:04:05")
	fmt.Printf("time=%s level=info msg=\"%s\"\n", startTime, config.StartMessage)

	// Poll for events
	eventChan := make(chan ringbuf.Record, 1000)
	errChan := make(chan error, 1)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				errChan <- err
				return
			}
			eventChan <- record
		}
	}()

	// Poll with timeout like C version: check for signal every 100ms
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Signal received, exit gracefully
			goto cleanup
		case err := <-errChan:
			if err != ringbuf.ErrClosed {
				fmt.Fprintf(os.Stderr, "Ring buffer error: %v\n", err)
			}
			goto cleanup
		case record := <-eventChan:
			module.handleEvent(record.RawSample)
		case <-ticker.C:
			// Timeout - just continue
			continue
		}
	}

cleanup:
	now = time.Now()
	endTime := now.Format("15:04:05")
	fmt.Printf("time=%s level=info msg=\"%s\"\n", endTime, config.ShutdownMessage)
	return nil
}

// ParseRuleString parses a rule string back into a PolicyRule
func ParseRuleString(ruleStr string) (*PolicyRule, error) {
	// Reuse existing parsePolicyLine logic
	rule, err := parsePolicyLine(ruleStr, 0)
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

// Helper functions for connect policy parsing

func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

func parseIPAddress(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address")
	}

	// Convert to IPv4
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("IPv6 not supported")
	}

	// Convert to uint32 in network byte order
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), nil
}

func parsePort(s string) (uint16, error) {
	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	if port == 0 || port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return uint16(port), nil
}
