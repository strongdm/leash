package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
)

// Config is the parsed policy content split for different subsystems.
type Config struct {
	LSMPolicies  *lsm.PolicySet
	HTTPRewrites []proxy.HeaderRewriteRule
	Cedar        string
	Path         string
	lastModTime  time.Time
}

// Parse reads a Cedar policy file and returns combined Config including LSM and http.rewrite rules.
func Parse(path string) (*Config, error) {
	compilation, err := cedar.CompileFile(path)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat Cedar policy file: %w", err)
	}

	return &Config{
		LSMPolicies:  compilation.Policies,
		HTTPRewrites: compilation.HTTPRules,
		Cedar:        compilation.Cedar,
		Path:         path,
		lastModTime:  stat.ModTime(),
	}, nil
}

// WatchCedar polls the Cedar file and invokes onUpdate when a new valid
// configuration is available. When compilation fails, onError receives the
// structured Cedar error while the previous configuration remains active.
func WatchCedar(path string, interval time.Duration, onUpdate func(*Config), onError func(*cedar.ErrorDetail)) (func(), error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat Cedar policy file: %w", err)
	}

	stop := make(chan struct{})
	ticker := time.NewTicker(interval)

	go func(initialModTime time.Time) {
		defer ticker.Stop()
		// Track the last successful mod time separately so partial writes keep retrying until a valid config is parsed.
		lastSuccessModTime := initialModTime
		var lastErrorModTime time.Time

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				info, statErr := os.Stat(path)
				if statErr != nil {
					if onError != nil {
						onError(&cedar.ErrorDetail{
							Summary:    "failed to stat Cedar policy file",
							Message:    fmt.Sprintf("failed to stat Cedar policy file %q: %v", path, statErr),
							File:       path,
							Suggestion: "Ensure the Cedar file remains accessible to the leash daemon.",
							Code:       "CEDAR_IO",
							Raw:        statErr,
						})
					}
					continue
				}
				if !info.ModTime().After(lastSuccessModTime) {
					continue
				}

				cfg, parseErr := Parse(path)
				if parseErr != nil {
					var detail *cedar.ErrorDetail
					if errors.As(parseErr, &detail) {
						if onError != nil && !info.ModTime().Equal(lastErrorModTime) {
							onError(detail)
						}
					} else if onError != nil && !info.ModTime().Equal(lastErrorModTime) {
						onError(&cedar.ErrorDetail{
							Summary:    "failed to parse Cedar policy",
							Message:    fmt.Sprintf("failed to parse Cedar policy %q: %v", path, parseErr),
							File:       path,
							Suggestion: "Review the Cedar file and correct the reported error.",
							Code:       "CEDAR_PARSE",
							Raw:        parseErr,
						})
					}
					lastErrorModTime = info.ModTime()
					continue
				}

				cfg.lastModTime = info.ModTime()
				lastSuccessModTime = info.ModTime()
				lastErrorModTime = time.Time{}
				if onUpdate != nil {
					onUpdate(cfg)
				}
			}
		}
	}(stat.ModTime())

	cancel := func() { close(stop) }
	return cancel, nil
}

// ParseHTTPRuleString parses an HTTP rewrite rule string into a HeaderRewriteRule
func ParseHTTPRuleString(ruleStr string) (*proxy.HeaderRewriteRule, error) {
	// Parse: "allow http.rewrite <host> header:<header>:<value>"
	parts := strings.Fields(ruleStr)
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid HTTP rewrite rule format")
	}

	if parts[0] != "allow" || parts[1] != "http.rewrite" {
		return nil, fmt.Errorf("invalid HTTP rewrite rule format")
	}

	host := parts[2]
	headerTok := parts[3]

	if !strings.HasPrefix(headerTok, "header:") {
		return nil, fmt.Errorf("invalid header format")
	}

	headerTok = strings.TrimPrefix(headerTok, "header:")
	hv := strings.SplitN(headerTok, ":", 2)
	if len(hv) != 2 {
		return nil, fmt.Errorf("invalid header format")
	}

	headerName := strings.TrimSpace(hv[0])
	headerValue := strings.TrimSpace(hv[1])

	// Handle multi-word values
	if len(parts) > 4 {
		headerValue += " " + strings.Join(parts[4:], " ")
	}

	return &proxy.HeaderRewriteRule{
		Host:   host,
		Header: headerName,
		Value:  headerValue,
	}, nil
}

// Manager manages both file-based and runtime policy rules
type Manager struct {
	fileRules        *lsm.PolicySet
	fileHTTPRules    []proxy.HeaderRewriteRule
	runtimeRules     *lsm.PolicySet
	runtimeHTTPRules []proxy.HeaderRewriteRule
	runtimeMutex     sync.RWMutex
	runtimeOnly      bool // when true, active rules are runtime-only (ignore file layer)

	// Subsystem references for live updates
	lsmManager   *lsm.LSMManager
	proxyUpdater func(*lsm.PolicySet, []proxy.HeaderRewriteRule) // Callback to update proxy
}

// NewManager creates a new policy manager
func NewManager(lsmManager *lsm.LSMManager, proxyUpdater func(*lsm.PolicySet, []proxy.HeaderRewriteRule)) *Manager {
	return &Manager{
		fileRules:        &lsm.PolicySet{},
		fileHTTPRules:    []proxy.HeaderRewriteRule{},
		runtimeRules:     &lsm.PolicySet{},
		runtimeHTTPRules: []proxy.HeaderRewriteRule{},
		lsmManager:       lsmManager,
		proxyUpdater:     proxyUpdater,
	}
}

// PolicySetCompat is a type alias to expose *lsm.PolicySet to external packages with minimal coupling.
type PolicySetCompat = lsm.PolicySet

// AddRule adds a rule at runtime
func (m *Manager) AddRule(ruleStr string) error {
	m.runtimeMutex.Lock()
	defer m.runtimeMutex.Unlock()

	// Check if it's an HTTP rewrite rule
	if strings.Contains(ruleStr, "http.rewrite") {
		httpRule, err := ParseHTTPRuleString(ruleStr)
		if err != nil {
			return fmt.Errorf("invalid HTTP rule: %w", err)
		}
		m.runtimeHTTPRules = append(m.runtimeHTTPRules, *httpRule)
	} else {
		// LSM rule
		rule, err := lsm.ParseRuleString(ruleStr)
		if err != nil {
			return fmt.Errorf("invalid LSM rule: %w", err)
		}

		// Add to appropriate rule set
		switch rule.Operation {
		case lsm.OpOpen, lsm.OpOpenRO, lsm.OpOpenRW:
			m.runtimeRules.Open = append(m.runtimeRules.Open, *rule)
		case lsm.OpExec:
			m.runtimeRules.Exec = append(m.runtimeRules.Exec, *rule)
		case lsm.OpConnect:
			m.runtimeRules.Connect = append(m.runtimeRules.Connect, *rule)
		}
	}

	return m.applyChanges()
}

// RemoveRule removes a rule at runtime
func (m *Manager) RemoveRule(ruleStr string) error {
	m.runtimeMutex.Lock()
	defer m.runtimeMutex.Unlock()

	// Check if it's an HTTP rewrite rule
	if strings.Contains(ruleStr, "http.rewrite") {
		m.runtimeHTTPRules = m.removeHTTPRuleFromSlice(m.runtimeHTTPRules, ruleStr)
	} else {
		// Remove from LSM runtime rules by string comparison
		m.runtimeRules.Open = m.removeLSMRuleFromSlice(m.runtimeRules.Open, ruleStr)
		m.runtimeRules.Exec = m.removeLSMRuleFromSlice(m.runtimeRules.Exec, ruleStr)
		m.runtimeRules.Connect = m.removeLSMRuleFromSlice(m.runtimeRules.Connect, ruleStr)
	}

	return m.applyChanges()
}

// GetActiveRules returns the merged file and runtime rules
func (m *Manager) GetActiveRules() (*lsm.PolicySet, []proxy.HeaderRewriteRule) {
	m.runtimeMutex.RLock()
	defer m.runtimeMutex.RUnlock()

	if m.runtimeOnly {
		// In runtime-only mode, ignore file layer completely
		rr := &lsm.PolicySet{
			Open:                   append([]lsm.PolicyRule(nil), m.runtimeRules.Open...),
			Exec:                   append([]lsm.PolicyRule(nil), m.runtimeRules.Exec...),
			Connect:                append([]lsm.PolicyRule(nil), m.runtimeRules.Connect...),
			MCP:                    append([]lsm.MCPPolicyRule(nil), m.runtimeRules.MCP...),
			ConnectDefaultAllow:    m.runtimeRules.ConnectDefaultAllow,
			ConnectDefaultExplicit: m.runtimeRules.ConnectDefaultExplicit,
		}
		rh := append([]proxy.HeaderRewriteRule(nil), m.runtimeHTTPRules...)
		return rr, rh
	}

	mergedLSM := &lsm.PolicySet{
		Open:                   append([]lsm.PolicyRule{}, m.runtimeRules.Open...),
		Exec:                   append([]lsm.PolicyRule{}, m.runtimeRules.Exec...),
		Connect:                append([]lsm.PolicyRule{}, m.runtimeRules.Connect...),
		MCP:                    append([]lsm.MCPPolicyRule{}, m.runtimeRules.MCP...),
		ConnectDefaultAllow:    m.fileRules.ConnectDefaultAllow,
		ConnectDefaultExplicit: m.fileRules.ConnectDefaultExplicit,
	}
	mergedLSM.Open = append(mergedLSM.Open, m.fileRules.Open...)
	mergedLSM.Exec = append(mergedLSM.Exec, m.fileRules.Exec...)
	mergedLSM.Connect = append(mergedLSM.Connect, m.fileRules.Connect...)
	mergedLSM.MCP = append(mergedLSM.MCP, m.fileRules.MCP...)

	mergedLSM.Open = dedupeLSMRules(mergedLSM.Open)
	mergedLSM.Exec = dedupeLSMRules(mergedLSM.Exec)
	mergedLSM.Connect = dedupeConnectRules(mergedLSM.Connect)
	mergedLSM.MCP = dedupeMCPRules(mergedLSM.MCP)
	if m.runtimeRules.ConnectDefaultExplicit {
		mergedLSM.ConnectDefaultAllow = m.runtimeRules.ConnectDefaultAllow
		mergedLSM.ConnectDefaultExplicit = true
	} else if !mergedLSM.ConnectDefaultExplicit && m.runtimeRules.ConnectDefaultAllow {
		mergedLSM.ConnectDefaultAllow = true
	}

	mergedHTTP := append(m.fileHTTPRules, m.runtimeHTTPRules...)

	return mergedLSM, mergedHTTP
}

// UpdateFileRules updates the file-based rules
func (m *Manager) UpdateFileRules(newFileRules *lsm.PolicySet, newHTTPRules []proxy.HeaderRewriteRule) error {
	m.runtimeMutex.Lock()
	m.fileRules = newFileRules
	m.fileHTTPRules = newHTTPRules
	m.runtimeMutex.Unlock()

	return m.applyChanges()
}

// Helper functions

func (m *Manager) removeLSMRuleFromSlice(rules []lsm.PolicyRule, ruleStr string) []lsm.PolicyRule {
	var result []lsm.PolicyRule
	for _, rule := range rules {
		if rule.String() != ruleStr {
			result = append(result, rule)
		}
	}
	return result
}

func (m *Manager) removeHTTPRuleFromSlice(rules []proxy.HeaderRewriteRule, ruleStr string) []proxy.HeaderRewriteRule {
	var result []proxy.HeaderRewriteRule
	for _, rule := range rules {
		if rule.String() != ruleStr {
			result = append(result, rule)
		}
	}
	return result
}

func dedupeLSMRules(rules []lsm.PolicyRule) []lsm.PolicyRule {
	seen := make(map[string]struct{}, len(rules))
	result := make([]lsm.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		key := rule.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, rule)
	}
	return result
}

func dedupeConnectRules(rules []lsm.PolicyRule) []lsm.PolicyRule {
	seen := make(map[string]struct{}, len(rules))
	denies := make([]lsm.PolicyRule, 0, len(rules))
	allows := make([]lsm.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		key := rule.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if rule.Action == lsm.PolicyDeny {
			denies = append(denies, rule)
		} else {
			allows = append(allows, rule)
		}
	}
	return append(denies, allows...)
}

func dedupeMCPRules(rules []lsm.MCPPolicyRule) []lsm.MCPPolicyRule {
	seen := make(map[string]struct{}, len(rules))
	result := make([]lsm.MCPPolicyRule, 0, len(rules))
	for _, rule := range rules {
		key := fmt.Sprintf("%d|%s|%s", rule.Action, rule.Server, rule.Tool)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, rule)
	}
	return result
}

func (m *Manager) applyChanges() error {
	activeRules, activeHTTPRules := m.GetActiveRules()

	// Attempt LSM update; record error but do not short-circuit proxy updates so
	// that the userspace proxy reflects current policy even on non-Linux hosts
	// or early bootstrap when LSM may be unavailable.
	var lsmErr error
	if m.lsmManager != nil {
		if err := m.lsmManager.UpdateRuntimeRules(activeRules); err != nil {
			lsmErr = fmt.Errorf("failed to update LSM: %w", err)
		}
	}

	// Always update proxy to keep networking consistent with active rules
	if m.proxyUpdater != nil {
		m.proxyUpdater(activeRules, activeHTTPRules)
	}

	return lsmErr
}

// SetRuntimeRules replaces the current runtime rule layers atomically.
func (m *Manager) SetRuntimeRules(newLSM *lsm.PolicySet, newHTTP []proxy.HeaderRewriteRule) error {
	m.runtimeMutex.Lock()
	// Defensive copies
	rr := &lsm.PolicySet{
		Open:                   append([]lsm.PolicyRule(nil), newLSM.Open...),
		Exec:                   append([]lsm.PolicyRule(nil), newLSM.Exec...),
		Connect:                append([]lsm.PolicyRule(nil), newLSM.Connect...),
		MCP:                    append([]lsm.MCPPolicyRule(nil), newLSM.MCP...),
		ConnectDefaultAllow:    newLSM.ConnectDefaultAllow,
		ConnectDefaultExplicit: newLSM.ConnectDefaultExplicit,
	}
	rh := append([]proxy.HeaderRewriteRule(nil), newHTTP...)
	m.runtimeRules = rr
	m.runtimeHTTPRules = rh
	m.runtimeMutex.Unlock()
	return m.applyChanges()
}

// SetRuntimeOnly toggles whether the Manager should ignore the file layer when
// computing active rules. When enabled, only runtime rules are applied to the
// LSM/proxy; file rules continue to be tracked and exposed via Snapshot() for UI.
func (m *Manager) SetRuntimeOnly(enabled bool) error {
	m.runtimeMutex.Lock()
	m.runtimeOnly = enabled
	m.runtimeMutex.Unlock()
	return m.applyChanges()
}

// Snapshot returns copies of file and runtime rule layers for safe inspection.
func (m *Manager) Snapshot() (fileLSM *lsm.PolicySet, fileHTTP []proxy.HeaderRewriteRule, runtimeLSM *lsm.PolicySet, runtimeHTTP []proxy.HeaderRewriteRule) {
	m.runtimeMutex.RLock()
	defer m.runtimeMutex.RUnlock()
	fl := &lsm.PolicySet{
		Open:                   append([]lsm.PolicyRule(nil), m.fileRules.Open...),
		Exec:                   append([]lsm.PolicyRule(nil), m.fileRules.Exec...),
		Connect:                append([]lsm.PolicyRule(nil), m.fileRules.Connect...),
		MCP:                    append([]lsm.MCPPolicyRule(nil), m.fileRules.MCP...),
		ConnectDefaultAllow:    m.fileRules.ConnectDefaultAllow,
		ConnectDefaultExplicit: m.fileRules.ConnectDefaultExplicit,
	}
	rl := &lsm.PolicySet{
		Open:                   append([]lsm.PolicyRule(nil), m.runtimeRules.Open...),
		Exec:                   append([]lsm.PolicyRule(nil), m.runtimeRules.Exec...),
		Connect:                append([]lsm.PolicyRule(nil), m.runtimeRules.Connect...),
		MCP:                    append([]lsm.MCPPolicyRule(nil), m.runtimeRules.MCP...),
		ConnectDefaultAllow:    m.runtimeRules.ConnectDefaultAllow,
		ConnectDefaultExplicit: m.runtimeRules.ConnectDefaultExplicit,
	}
	fh := append([]proxy.HeaderRewriteRule(nil), m.fileHTTPRules...)
	rh := append([]proxy.HeaderRewriteRule(nil), m.runtimeHTTPRules...)
	return fl, fh, rl, rh
}
