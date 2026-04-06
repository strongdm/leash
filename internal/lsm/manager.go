//go:generate bash -c "if [ \"$(uname -s)\" = 'Linux' ]; then command -v bpf2go 1>/dev/null 2>&1 || go install github.com/cilium/ebpf/cmd/bpf2go && bpf2go -cc clang -tags linux lsmOpen bpf/lsm_open.bpf.c -- -I./bpf && bpf2go -cc clang -tags linux lsmExec bpf/lsm_exec.bpf.c -- -I./bpf && bpf2go -cc clang -tags linux lsmConnect bpf/lsm_connect.bpf.c -- -I./bpf; else echo 'Skipping bpf2go in non-Linux build environment'; fi"

package lsm

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

type enforcementBackend interface {
	UpdatePolicies(*PolicySet) error
	Run() error
}

type backendKind string

const (
	backendBPF      backendKind = "bpf"
	backendFanotify backendKind = "fanotify"
)

// LSMManager manages multiple LSM programs and handles policy reloading
type LSMManager struct {
	cgroupPath string
	logger     *SharedLogger

	// Active LSM programs
	openLsm    *OpenLsm
	execLsm    *ExecLsm
	connectLsm *ConnectLsm

	reloadMutex sync.RWMutex
	started     bool
	backend     enforcementBackend
	backendKind backendKind
	policies    *PolicySet
}

func NewLSMManager(cgroupPath string, logger *SharedLogger) *LSMManager {
	return &LSMManager{
		cgroupPath: cgroupPath,
		logger:     logger,
	}
}

func (m *LSMManager) LoadAndStart() error {
	m.reloadMutex.Lock()
	defer m.reloadMutex.Unlock()

	if !m.started {
		backend, kind, err := m.initializeBackendLocked()
		if err != nil {
			return err
		}
		m.backend = backend
		m.backendKind = kind
		m.started = true
		if m.policies != nil {
			if err := m.backend.UpdatePolicies(clonePolicySet(m.policies)); err != nil {
				return err
			}
		}
	}

	if m.backendKind == backendFanotify {
		return m.backend.Run()
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("LSM Manager started. Press Ctrl-C to stop.\n")

	// Wait for shutdown signal
	select {
	case <-sigChan:
		fmt.Printf("Received shutdown signal\n")
	}

	return nil
}

func (m *LSMManager) initializeBackendLocked() (enforcementBackend, backendKind, error) {
	if runtime.GOOS != "linux" {
		return nil, "", fmt.Errorf("LSM manager is only supported on linux")
	}

	if hostSupportsBPFLSM() {
		fmt.Printf("Using BPF LSM enforcement backend\n")
		return newBPFBackend(m), backendBPF, nil
	}

	backend, err := newFanotifyBackend(m.cgroupPath, m.logger)
	if err != nil {
		return nil, "", err
	}
	fmt.Printf("Using fanotify enforcement backend\n")
	return backend, backendFanotify, nil
}

func hostSupportsBPFLSM() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(data)), "bpf")
}

func (m *LSMManager) updateOpenLSM(policies *PolicySet) error {
	if !policies.HasOpenPolicies() {
		// No open policies, ensure LSM is stopped
		if m.openLsm != nil {
			fmt.Printf("No open policies found, open LSM will continue with empty rules\n")
			// Just reload with empty rules instead of stopping
			return m.openLsm.LoadPolicies([]OpenPolicyRule{})
		}
		return nil
	}

	if m.openLsm == nil {
		// Create new open LSM
		var err error
		m.openLsm, err = NewOpenLsm(m.cgroupPath, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create file open LSM: %w", err)
		}

		// Load policies and start in background
		if err := m.openLsm.LoadPolicies(ConvertToFileOpenRules(policies.Open)); err != nil {
			return fmt.Errorf("failed to load open policies: %w", err)
		}

		go func() {
			if err := m.openLsm.LoadAndAttach(loadLsmOpen); err != nil {
				fmt.Fprintf(os.Stderr, "File open LSM error: %v\n", err)
			}
		}()
	} else {
		// Update existing policies
		return m.openLsm.LoadPolicies(ConvertToFileOpenRules(policies.Open))
	}

	return nil
}

func (m *LSMManager) updateExecLSM(policies *PolicySet) error {
	if !policies.HasExecPolicies() {
		if m.execLsm != nil {
			fmt.Printf("No exec policies found, exec LSM will continue with empty rules\n")
			return m.execLsm.LoadPolicies([]ExecPolicyRule{})
		}
		return nil
	}

	if m.execLsm == nil {
		var err error
		m.execLsm, err = NewExecLsm(m.cgroupPath, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create exec LSM: %w", err)
		}

		if err := m.execLsm.LoadPolicies(ConvertToExecRules(policies.Exec)); err != nil {
			return fmt.Errorf("failed to load exec policies: %w", err)
		}

		go func() {
			if err := m.execLsm.LoadAndAttach(loadLsmExec); err != nil {
				fmt.Fprintf(os.Stderr, "Exec LSM error: %v\n", err)
			}
		}()
	} else {
		return m.execLsm.LoadPolicies(ConvertToExecRules(policies.Exec))
	}

	return nil
}

func (m *LSMManager) updateConnectLSM(policies *PolicySet) error {
	var defaultOverride *bool
	if policies.ConnectDefaultExplicit {
		val := policies.ConnectDefaultAllow
		defaultOverride = &val
	}

	if !policies.HasConnectPolicies() {
		if m.connectLsm != nil {
			fmt.Printf("No connect policies found, connect LSM will continue with empty rules\n")
			return m.connectLsm.LoadPolicies([]ConnectPolicyRule{}, defaultOverride)
		}
		return nil
	}

	if m.connectLsm == nil {
		var err error
		m.connectLsm, err = NewConnectLsm(m.cgroupPath, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create connect LSM: %w", err)
		}

		if err := m.connectLsm.LoadPolicies(ConvertToConnectRules(policies.Connect), defaultOverride); err != nil {
			return fmt.Errorf("failed to load connect policies: %w", err)
		}

		go func() {
			if err := m.connectLsm.LoadAndAttach(loadLsmConnect); err != nil {
				fmt.Fprintf(os.Stderr, "Connect LSM error: %v\n", err)
			}
		}()
	} else {
		return m.connectLsm.LoadPolicies(ConvertToConnectRules(policies.Connect), defaultOverride)
	}

	return nil
}

// UpdateRuntimeRules updates all LSM modules with new runtime rules
func (m *LSMManager) UpdateRuntimeRules(policies *PolicySet) error {
	m.reloadMutex.Lock()
	defer m.reloadMutex.Unlock()

	m.policies = clonePolicySet(policies)
	if !m.started {
		return nil
	}
	return m.backend.UpdatePolicies(clonePolicySet(policies))
}

func clonePolicySet(src *PolicySet) *PolicySet {
	if src == nil {
		return &PolicySet{}
	}
	return &PolicySet{
		Open:                   append([]PolicyRule(nil), src.Open...),
		Exec:                   append([]PolicyRule(nil), src.Exec...),
		Connect:                append([]PolicyRule(nil), src.Connect...),
		MCP:                    append([]MCPPolicyRule(nil), src.MCP...),
		ConnectDefaultAllow:    src.ConnectDefaultAllow,
		ConnectDefaultExplicit: src.ConnectDefaultExplicit,
	}
}

type bpfBackend struct {
	manager *LSMManager
}

func newBPFBackend(manager *LSMManager) *bpfBackend {
	return &bpfBackend{manager: manager}
}

func (b *bpfBackend) UpdatePolicies(policies *PolicySet) error {
	if err := b.manager.updateOpenLSM(policies); err != nil {
		return err
	}
	if err := b.manager.updateExecLSM(policies); err != nil {
		return err
	}
	if err := b.manager.updateConnectLSM(policies); err != nil {
		return err
	}
	return nil
}

func (b *bpfBackend) Run() error { return nil }
