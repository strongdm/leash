package lsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Note: PolicyRule is now defined in common.go

// OpenPolicyRule matches struct policy_rule in lsm_file_open.bpf.c exactly (272 bytes)
type OpenPolicyRule struct {
	Action      uint32
	Operation   uint32
	PathLen     uint32
	Path        [256]byte
	IsDirectory uint32
}

type openEventFingerprint struct {
	valid     bool
	timestamp uint64
	pid       uint32
	tgid      uint32
	cgroup    uint64
	operation uint32
	result    int32
	path      string
	comm      string
}

// File open event structure - must match BPF code
type OpenEvent struct {
	PID       uint32
	TGID      uint32
	Timestamp uint64
	CgroupID  uint64
	Comm      [16]byte
	Path      [256]byte
	Operation uint32
	Result    int32
}

const (
	MaxPolicyRules = 256
	// Note: Policy constants are now defined in common.go

	// duplicateSuppressionWindow limits how long we treat identical payloads as retries.
	duplicateSuppressionWindow = 50 * time.Millisecond
)

type LsmLoader func() (*ebpf.CollectionSpec, error)

type OpenLsm struct {
	cgroupPath string
	logger     *SharedLogger

	policyRules         []OpenPolicyRule
	numPolicyRules      int
	defaultPolicyResult bool       // Default policy result: false=deny, true=allow
	logMutex            sync.Mutex // Protect concurrent writes to stdout and log file

	// BPF program state
	ebpfCollection *ebpf.Collection

	lastEvent openEventFingerprint
}

func NewOpenLsm(cgroupPath string, logger *SharedLogger) (*OpenLsm, error) {
	if cgroupPath == "" {
		return nil, fmt.Errorf("cgroup path is required")
	}

	l := &OpenLsm{
		cgroupPath:          cgroupPath,
		logger:              logger,
		defaultPolicyResult: false, // Default to deny (false)
	}

	// Note: Policy loading is now done separately via LoadPolicies()
	return l, nil
}

// Interface methods for LSMModule

func (l *OpenLsm) getCgroupPath() string {
	return l.cgroupPath
}

func (l *OpenLsm) setEbpfCollection(coll *ebpf.Collection) {
	l.ebpfCollection = coll
}

// LoadPolicies loads file open policy rules into the LSM
func (l *OpenLsm) LoadPolicies(policies []OpenPolicyRule) error {
	l.policyRules = policies
	l.numPolicyRules = len(policies)

	// Sort policy rules by path length (longest first) for specificity
	sort.Slice(l.policyRules, func(i, j int) bool {
		return l.policyRules[i].PathLen > l.policyRules[j].PathLen
	})

	// Check if root path "/" is allowed to set default policy result
	l.checkRootPathPolicy()

	fmt.Printf("Loaded %d file open policy rules\n", l.numPolicyRules)
	if l.defaultPolicyResult {
		fmt.Printf("Default open policy result: ALLOW (root path '/' is allowed)\n")
	} else {
		fmt.Printf("Default open policy result: DENY (root path '/' is not explicitly allowed)\n")
	}

	// If eBPF collection is already loaded, update the BPF maps
	if l.ebpfCollection != nil {
		if err := l.loadPolicyIntoBPF(l.ebpfCollection); err != nil {
			return fmt.Errorf("failed to update BPF maps: %w", err)
		}
		fmt.Printf("Updated BPF maps with new policies\n")
	}

	return nil
}

func (l *OpenLsm) LoadAndAttach(loader func() (*ebpf.CollectionSpec, error)) error {
	config := BPFConfig{
		ProgramNames:      []string{"lsm_open"},
		EventMapName:      "events",
		AllowedCgroupsMap: "allowed_cgroups",
		TargetCgroupMap:   "target_cgroup",
		StartMessage:      "Successfully started monitoring file opens",
		ShutdownMessage:   "Shutting down open LSM tracker",
	}
	return LoadAndAttachBPF(l, loader, config)
}

// checkRootPathPolicy checks if the root path "/" is explicitly allowed in the policy rules
// and sets the default policy result accordingly
func (l *OpenLsm) checkRootPathPolicy() {
	// Default is false (deny)
	l.defaultPolicyResult = false

	// Check if any rule explicitly allows root path "/"
	for _, rule := range l.policyRules {
		pathStr := string(bytes.TrimRight(rule.Path[:rule.PathLen], "\x00"))
		if pathStr == "/" && rule.Action == PolicyAllow {
			l.defaultPolicyResult = true
			break
		}
	}
}

func (l *OpenLsm) loadPolicyIntoBPF(coll *ebpf.Collection) error {
	// Always load the default policy result into BPF map
	key := uint32(0)
	defaultResult := uint32(0) // Default to deny
	if l.defaultPolicyResult {
		defaultResult = uint32(1) // Allow
	}
	if err := coll.Maps["default_policy"].Put(&key, &defaultResult); err != nil {
		return fmt.Errorf("failed to update default_policy map: %w", err)
	}

	if l.numPolicyRules == 0 {
		fmt.Printf("No policy rules to load, using default policy result: %v\n", l.defaultPolicyResult)
		return nil
	}

	// Load the number of rules
	numRules := int32(l.numPolicyRules)
	if err := coll.Maps["num_rules"].Put(&key, &numRules); err != nil {
		return fmt.Errorf("failed to update num_rules map: %w", err)
	}

	fmt.Printf("Loading %d policy rules into BPF maps...\n", l.numPolicyRules)

	// Load each policy rule
	for i := 0; i < l.numPolicyRules; i++ {
		if err := coll.Maps["policy_rules"].Put(uint32(i), &l.policyRules[i]); err != nil {
			return fmt.Errorf("failed to update policy_rules map for rule %d: %w", i, err)
		}

		// pathStr := string(bytes.TrimRight(l.policyRules[i].Path[:], "\x00"))
		// actionStr := "deny"
		// if l.policyRules[i].Action == 1 {
		// 	actionStr = "allow"
		// }
		// dirStr := ""
		// if l.policyRules[i].IsDirectory == 1 {
		// 	dirStr = " (directory)"
		// }

		// fmt.Printf("Loaded rule %d: %s %s%s\n", i, actionStr, pathStr, dirStr)
	}

	// fmt.Printf("Successfully loaded all policy rules into BPF\n")
	return nil
}

// validateEvent checks if the event data is properly formed
func validateEvent(event *OpenEvent) bool {
	return validateEventArrays(event.Comm[:], event.Path[:])
}

// Note: safeString is now defined in common.go

func (l *OpenLsm) handleEvent(data []byte) {
	if len(data) < int(unsafe.Sizeof(OpenEvent{})) {
		fmt.Fprintf(os.Stderr, "Error: received incomplete event\n")
		return
	}

	var event OpenEvent
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to parse event: %v\n", err)
		return
	}

	// Validate event data to prevent corruption
	if !validateEvent(&event) {
		fmt.Fprintf(os.Stderr, "Error: received corrupted event data (missing null terminators)\n")
		return
	}

	// Extract strings from byte arrays with safe conversion
	comm := safeString(event.Comm[:])
	path := safeString(event.Path[:])

	// Additional validation - reject obviously corrupted data
	if len(comm) == 0 || len(path) == 0 {
		fmt.Fprintf(os.Stderr, "Error: received event with empty comm or path\n")
		return
	}

	// Use current time for ISO 8601 format (BPF timestamp is kernel boot time, not Unix time)
	timestamp := time.Now().Format(time.RFC3339)

	// Format result string (match C version)
	resultStr := "allowed"
	if event.Result != 0 {
		resultStr = "denied"
	}

	eventName := "file.open"
	switch event.Operation {
	case uint32(OpOpenRO):
		eventName = "file.open:ro"
	case uint32(OpOpenRW):
		eventName = "file.open:rw"
	case uint32(OpOpen):
		eventName = "file.open"
	}

	// Format in logfmt (key=value pairs) - matching C version format exactly
	logEntry := fmt.Sprintf("time=%s event=%s pid=%d cgroup=%d exe=\"%s\" path=\"%s\" decision=%s",
		timestamp, eventName, event.PID, event.CgroupID, comm, path, resultStr)

	// Protect concurrent writes with mutex
	l.logMutex.Lock()
	defer l.logMutex.Unlock()

	// The kernel occasionally re-runs the file_open LSM hook during path resolution,
	// emitting identical ring buffer samples for the same file descriptor. Without
	// filtering, these retries double-count in the UI stream and policy suggestions.
	// Track the most recent payload so we can drop byte-for-byte duplicates while
	// still forwarding genuine consecutive opens.
	if l.lastEvent.valid &&
		l.lastEvent.pid == event.PID &&
		l.lastEvent.tgid == event.TGID &&
		l.lastEvent.cgroup == event.CgroupID &&
		l.lastEvent.operation == event.Operation &&
		l.lastEvent.result == event.Result &&
		l.lastEvent.path == path &&
		l.lastEvent.comm == comm {
		var delta uint64
		if event.Timestamp >= l.lastEvent.timestamp {
			delta = event.Timestamp - l.lastEvent.timestamp
		} else {
			delta = l.lastEvent.timestamp - event.Timestamp
		}
		if time.Duration(delta) <= duplicateSuppressionWindow {
			return
		}
	}

	l.lastEvent = openEventFingerprint{
		valid:     true,
		timestamp: event.Timestamp,
		pid:       event.PID,
		tgid:      event.TGID,
		cgroup:    event.CgroupID,
		operation: event.Operation,
		result:    event.Result,
		path:      path,
		comm:      comm,
	}

	// Write to shared logger if configured
	if l.logger != nil {
		_ = l.logger.Write(logEntry)
	}

	// Unique path logging removed
}

func addDescendantCgroups(cgroupMap *ebpf.Map, cgroupPath string) error {
	value := uint8(1)

	// Add the current directory's cgroup ID (matching C version exactly)
	cgroupID, err := getCgroupID(cgroupPath)
	if err == nil {
		if err := cgroupMap.Put(&cgroupID, &value); err == nil {
			// fmt.Printf("Added cgroup ID %d: %s\n", cgroupID, cgroupPath)
		}
	}

	// Open the directory (matching C version logic)
	entries, err := os.ReadDir(cgroupPath)
	if err != nil {
		return nil // Return silently like C version
	}

	// Iterate through entries (matching C version)
	for _, entry := range entries {
		// Skip . and .. (matching C version)
		if entry.Name() == "." || entry.Name() == ".." {
			continue
		}

		// Build full path
		fullPath := filepath.Join(cgroupPath, entry.Name())

		// Check if it's a directory (matching C version)
		if entry.IsDir() {
			// Skip cgroup control files (matching C version exactly)
			name := entry.Name()
			if strings.HasPrefix(name, "cgroup.") ||
				strings.HasPrefix(name, "cpu.") ||
				strings.HasPrefix(name, "memory.") ||
				strings.HasPrefix(name, "io.") ||
				strings.HasPrefix(name, "pids.") ||
				strings.HasPrefix(name, "rdma.") ||
				strings.HasPrefix(name, "hugetlb.") ||
				strings.HasPrefix(name, "misc.") ||
				strings.HasPrefix(name, "irq.") {
				continue // Skip control files
			}

			// Recursively add subdirectory (matching C version)
			addDescendantCgroups(cgroupMap, fullPath)
		}
	}

	return nil
}

func getCgroupID(cgroupPath string) (uint64, error) {
	// Get the real cgroup ID using the inode number (matching C version)
	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		return 0, fmt.Errorf("failed to stat cgroup path %s: %w", cgroupPath, err)
	}

	// The cgroup ID is the inode number (same as C version)
	cgroupID := stat.Ino
	return cgroupID, nil
}

// addSingleCgroup adds only the exact cgroup ID to the allowed map (non-recursive scope)
func addSingleCgroup(cgroupMap *ebpf.Map, cgroupPath string) error {
	value := uint8(1)
	cgroupID, err := getCgroupID(cgroupPath)
	if err != nil {
		return err
	}
	if err := cgroupMap.Put(&cgroupID, &value); err != nil {
		return fmt.Errorf("failed to add cgroup ID %d: %w", cgroupID, err)
	}
	return nil
}

// Increase memory lock limits for BPF operations
func BumpMemlockRlimit() error {
	var rlim unix.Rlimit

	// Try to set unlimited first
	rlim.Cur = unix.RLIM_INFINITY
	rlim.Max = unix.RLIM_INFINITY

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
		// Try with a specific large value instead of INFINITY
		rlim.Cur = 512 * 1024 * 1024 // 512 MB
		rlim.Max = 512 * 1024 * 1024

		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to increase RLIMIT_MEMLOCK limit: %v\n", err)
			fmt.Fprintf(os.Stderr, "Continuing anyway - may fail if BPF maps are too large\n")
			// Don't return error - let it fail later if it's actually a problem
		}
	}
	return nil
}
