package lsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Exec policy rule structure - must match BPF code
type ExecPolicyRule struct {
	Action      int32 // 0 = deny, 1 = allow
	Operation   int32 // Always OP_EXEC (3) for this program
	PathLen     int32
	Path        [256]byte
	IsDirectory int32 // 1 if path ends with /

	// Argument matching
	ArgCount    int32       // Number of args to match (0 = match any)
	HasWildcard int32       // 1 if rule ends with * (allow rules only)
	Args        [4][32]byte // Up to 4 args, 32 chars each
	ArgLens     [4]int32    // Length of each arg for efficient matching
}

// Exec event structure - must match BPF code
type ExecEvent struct {
	PID          uint32
	_            uint32 // Padding for alignment
	Timestamp    uint64
	CgroupID     uint64
	Comm         [16]byte
	Path         [256]byte // Resolved path from LSM hook
	Result       int32
	Argc         int32
	DetailedArgs [6][24]byte // Individual args from tracepoint correlation (up to 6 args, 24 chars each)
}

const (
	MaxExecPolicyRules = 64
	// Note: OpExec is now defined in common.go
)

type ExecLsmLoader func() (*ebpf.CollectionSpec, error)

type ExecLsm struct {
	cgroupPath string
	logger     *SharedLogger

	policyRules         []ExecPolicyRule
	numPolicyRules      int
	defaultPolicyResult bool       // Default policy result: false=deny, true=allow
	logMutex            sync.Mutex // Protect concurrent writes to stdout and log file

	// BPF program state
	ebpfCollection *ebpf.Collection
	// Keep the tracepoint link alive for the lifetime of this module.
	tracepointLink link.Link
}

func NewExecLsm(cgroupPath string, logger *SharedLogger) (*ExecLsm, error) {
	if cgroupPath == "" {
		return nil, fmt.Errorf("cgroup path is required")
	}

	l := &ExecLsm{
		cgroupPath:          cgroupPath,
		logger:              logger,
		defaultPolicyResult: false, // Default to deny (false)
	}

	return l, nil
}

// Interface methods for LSMModule

func (l *ExecLsm) getCgroupPath() string {
	return l.cgroupPath
}

func (l *ExecLsm) setEbpfCollection(coll *ebpf.Collection) {
	l.ebpfCollection = coll
}

func (l *ExecLsm) LoadPolicies(policies []ExecPolicyRule) error {
	l.policyRules = policies
	l.numPolicyRules = len(policies)

	// Sort policy rules by path length (longest first) for specificity
	sort.Slice(l.policyRules, func(i, j int) bool {
		return l.policyRules[i].PathLen > l.policyRules[j].PathLen
	})

	// Check if root path "/" is allowed to set default policy result
	l.checkRootPathPolicy()

	fmt.Printf("Loaded %d exec policy rules\n", l.numPolicyRules)
	if l.defaultPolicyResult {
		fmt.Printf("Default exec policy result: ALLOW (root path '/' is allowed)\n")
	} else {
		fmt.Printf("Default exec policy result: DENY (root path '/' is not explicitly allowed)\n")
	}

	// If eBPF collection is already loaded, update the BPF maps
	if l.ebpfCollection != nil {
		if err := l.loadPolicyIntoBPF(l.ebpfCollection); err != nil {
			return fmt.Errorf("failed to update BPF maps: %w", err)
		}
		fmt.Printf("Updated BPF maps with new exec policies\n")
	}

	return nil
}

// checkRootPathPolicy checks if the root path "/" is explicitly allowed in the policy rules
func (l *ExecLsm) checkRootPathPolicy() {
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

func (l *ExecLsm) LoadAndAttach(loader func() (*ebpf.CollectionSpec, error)) error {
	config := BPFConfig{
		ProgramNames:      []string{"lsm_exec"}, // LSM program only
		EventMapName:      "exec_events",
		AllowedCgroupsMap: "exec_allowed_cgroups",
		TargetCgroupMap:   "exec_target_cgroup",
		StartMessage:      "Successfully started monitoring program execution",
		ShutdownMessage:   "Shutting down exec LSM tracker",
	}
	return LoadAndAttachBPFWithSetup(l, loader, config, l.attachTracepoint)
}

// attachTracepoint attaches the tracepoint hook for detailed argument capture
func (l *ExecLsm) attachTracepoint(coll *ebpf.Collection) error {
	// Attach tracepoint for detailed argument capture
	prog := coll.Programs["trace_sys_enter_execve"]
	if prog == nil {
		// Best-effort: continue without tracepoint if not present
		fmt.Fprintf(os.Stderr, "Warning: BPF program 'trace_sys_enter_execve' not found; proceeding without detailed argv capture\n")
		return nil
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		// Best-effort: do not fail LSM attach if tracepoint can't attach
		fmt.Fprintf(os.Stderr, "Warning: failed to attach exec tracepoint (argv capture disabled): %v\n", err)
		return nil
	}
	// Retain the link to prevent GC from closing it.
	l.tracepointLink = tp
	fmt.Printf("Attached tracepoint for detailed exec argument capture\n")
	return nil
}

func (l *ExecLsm) loadPolicyIntoBPF(coll *ebpf.Collection) error {
	// Always load the default policy result into BPF map
	key := uint32(0)
	defaultResult := uint32(0) // Default to deny
	if l.defaultPolicyResult {
		defaultResult = uint32(1) // Allow
	}
	if err := coll.Maps["exec_default_policy"].Put(&key, &defaultResult); err != nil {
		return fmt.Errorf("failed to update exec_default_policy map: %w", err)
	}

	if l.numPolicyRules == 0 {
		fmt.Printf("No exec policy rules to load, using default policy result: %v\n", l.defaultPolicyResult)
		return nil
	}

	// Load the number of rules
	numRules := int32(l.numPolicyRules)
	if err := coll.Maps["exec_num_rules"].Put(&key, &numRules); err != nil {
		return fmt.Errorf("failed to update exec_num_rules map: %w", err)
	}

	fmt.Printf("Loading %d exec policy rules into BPF maps...\n", l.numPolicyRules)

	// Load each policy rule
	for i := 0; i < l.numPolicyRules; i++ {
		if err := coll.Maps["exec_policy_rules"].Put(uint32(i), &l.policyRules[i]); err != nil {
			return fmt.Errorf("failed to update exec_policy_rules map for rule %d: %w", i, err)
		}

		// pathStr := string(bytes.TrimRight(l.policyRules[i].Path[:], "\x00"))
		// actionStr := "deny"
		// if l.policyRules[i].Action == PolicyAllow {
		// 	actionStr = "allow"
		// }

		// dirStr := ""
		// if l.policyRules[i].IsDirectory == 1 {
		// 	dirStr = " (directory)"
		// }

		// argsStr := ""
		// if l.policyRules[i].ArgCount > 0 {
		// 	var args []string
		// 	for j := 0; j < int(l.policyRules[i].ArgCount); j++ {
		// 		arg := string(bytes.TrimRight(l.policyRules[i].Args[j][:], "\x00"))
		// 		args = append(args, arg)
		// 	}
		// 	argsStr = fmt.Sprintf(" with args: %s", strings.Join(args, ", "))
		// }

		// fmt.Printf("Loaded exec rule %d: %s exec %s%s%s\n", i, actionStr, pathStr, dirStr, argsStr)
	}

	// fmt.Printf("Successfully loaded all exec policy rules into BPF\n")
	return nil
}

// validateExecEvent checks if the event data is properly formed
func validateExecEvent(event *ExecEvent) bool {
	return validateEventArrays(event.Comm[:], event.Path[:])
}

func (l *ExecLsm) handleEvent(data []byte) {
	if len(data) < int(unsafe.Sizeof(ExecEvent{})) {
		fmt.Fprintf(os.Stderr, "Error: received incomplete exec event\n")
		return
	}

	var event ExecEvent
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to parse exec event: %v\n", err)
		return
	}

	// Validate event data to prevent corruption
	if !validateExecEvent(&event) {
		fmt.Fprintf(os.Stderr, "Error: received corrupted exec event data\n")
		return
	}

	// Extract strings from byte arrays with safe conversion
	comm := safeString(event.Comm[:])
	path := safeString(event.Path[:])

	// Additional validation
	if len(comm) == 0 || len(path) == 0 {
		fmt.Fprintf(os.Stderr, "Error: received exec event with empty comm or path\n")
		return
	}

	// Extract detailed arguments
	var detailedArgs []string
	for i := int32(0); i < event.Argc && i < 6; i++ {
		arg := safeString(event.DetailedArgs[i][:])
		if arg != "" {
			detailedArgs = append(detailedArgs, arg)
		}
	}

	// Use current time for ISO 8601 format (BPF timestamp is kernel boot time, not Unix time)
	timestamp := time.Now().Format(time.RFC3339)

	// Format result string
	resultStr := "allowed"
	if event.Result != 0 {
		resultStr = "denied"
	}

	// Build detailed args string
	detailedArgsStr := ""
	if len(detailedArgs) > 0 {
		detailedArgsStr = strings.Join(detailedArgs, " ")
	}

	// Format as LSM policy event with full arguments
	var logEntry string
	if detailedArgsStr != "" {
		logEntry = fmt.Sprintf("time=%s event=proc.exec pid=%d cgroup=%d exe=\"%s\" path=\"%s\" argc=%d argv=\"%s\" decision=%s",
			timestamp, event.PID, event.CgroupID, comm, path, event.Argc, detailedArgsStr, resultStr)
	} else {
		// Fallback for events without correlated arguments
		logEntry = fmt.Sprintf("time=%s event=proc.exec pid=%d cgroup=%d exe=\"%s\" path=\"%s\" argc=%d decision=%s",
			timestamp, event.PID, event.CgroupID, comm, path, event.Argc, resultStr)
	}

	// Protect concurrent writes with mutex
	l.logMutex.Lock()
	defer l.logMutex.Unlock()

	// Write to shared logger if configured
	if l.logger != nil {
		_ = l.logger.Write(logEntry)
	}

	// Unique exec logging removed
}
