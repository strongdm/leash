package messages

import (
	"encoding/json"
	"time"
)

// Type names for message envelopes.
const (
	TypePendingRequest       = "pending.request"
	TypeVerdict              = "verdict"
	TypeRuleUpdate           = "rule.update"
	TypeEvent                = "event"
	TypeClientHello          = "client.hello"
	TypeMacPIDSync           = "mac.pid.sync"
	TypeMacRuleSync          = "mac.rule.sync"
	TypeMacEvent             = "mac.event"
	TypeMacAck               = "mac.ack"
	TypeShimHello            = "shim.hello"
	TypeShimHeartbeat        = "shim.heartbeat"
	TypeMacPolicyEvent       = "mac.policy.event"
	TypeMacPolicyDecision    = "mac.policy.decision"
	TypeMacRuleQuery         = "mac.rule.query"
	TypeMacRuleAdd           = "mac.rule.add"
	TypeMacRuleRemove        = "mac.rule.remove"
	TypeMacRuleClear         = "mac.rule.clear"
	TypeMacNetworkRuleQuery  = "mac.network_rule.query"
	TypeMacNetworkRuleUpdate = "mac.network_rule.update"
	TypeMacMITMConfig        = "mac.mitm.config"
	TypeMacMITMSession       = "mac.mitm.session"
	TypeMacMITMTelemetry     = "mac.mitm.telemetry"
	TypeMacMITMCertificate   = "mac.mitm.certificate"
)

// DecisionType represents an allow/deny decision for a flow.
type DecisionType string

const (
	DecisionAllow DecisionType = "Allow"
	DecisionDeny  DecisionType = "Deny"
)

// RuleScope controls the lifetime/application of a rule.
type RuleScope string

const (
	ScopeOnce       RuleScope = "Once"
	ScopeSession    RuleScope = "Session"
	ScopePersistent RuleScope = "Persistent"
)

// Envelope is a versioned, self-describing message wrapper.
// Payload must be decoded into a concrete payload struct based on Type.
type Envelope struct {
	Type      string          `json:"type"`
	Version   int             `json:"version"`
	SessionID string          `json:"session_id"`
	ShimID    string          `json:"shim_id"`
	RequestID string          `json:"request_id,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

// FlowMatch captures the identifying tuple for a network flow.
type FlowMatch struct {
	ImageDigest string `json:"image_digest,omitempty"`
	ExePath     string `json:"exe_path,omitempty"`
	CmdHash     string `json:"cmd_hash,omitempty"`
	DestHost    string `json:"dest_host,omitempty"`
	DestIP      string `json:"dest_ip,omitempty"`
	DestPort    int    `json:"dest_port,omitempty"`
	Proto       string `json:"proto,omitempty"`
	SNI         string `json:"sni,omitempty"`
}

// ProcInfo describes the process initiating a flow.
type ProcInfo struct {
	PID  int `json:"pid"`
	PPID int `json:"ppid"`
	UID  int `json:"uid"`
	GID  int `json:"gid"`
}

// Match defines fields used to match flows for a rule; all fields are optional.
type Match struct {
	ImageDigest string `json:"image_digest,omitempty"`
	ExePath     string `json:"exe_path,omitempty"`
	CmdHash     string `json:"cmd_hash,omitempty"`
	DestHost    string `json:"dest_host,omitempty"`
	DestIP      string `json:"dest_ip,omitempty"`
	DestPort    int    `json:"dest_port,omitempty"`
	Proto       string `json:"proto,omitempty"`
	SNI         string `json:"sni,omitempty"`
}

// Rule represents a user-authored or system-generated rule.
type Rule struct {
	ID     string       `json:"id,omitempty"`
	Action DecisionType `json:"action"`
	Scope  RuleScope    `json:"scope,omitempty"`
	Match  Match        `json:"match"`
}

// PendingRequestPayload (shim -> ctl) asks for a decision for a held flow.
type PendingRequestPayload struct {
	HoldID string    `json:"hold_id"`
	Flow   FlowMatch `json:"flow"`
	Proc   ProcInfo  `json:"proc"`
	TS     time.Time `json:"ts"`
}

// VerdictPayload (ctl -> shim) returns the decision for a pending flow.
// If Scope is Persistent and Rule is provided, the shim should apply it to its runtime policy.
type VerdictPayload struct {
	HoldID   string       `json:"hold_id"`
	Decision DecisionType `json:"decision"`
	Scope    RuleScope    `json:"scope,omitempty"`
	Rule     *Rule        `json:"rule,omitempty"`
}

// RuleUpdatePayload (ctl -> shim) pushes policy updates with a version number.
type RuleUpdatePayload struct {
	PolicyVersion int    `json:"policy_version"`
	Rules         []Rule `json:"rules"`
}

// EventPayload (shim -> ctl) records notable activity for audit/telemetry.
type EventPayload struct {
	ID     string          `json:"id,omitempty"`
	Event  string          `json:"event"`
	TS     time.Time       `json:"ts"`
	RuleID string          `json:"rule_id,omitempty"`
	Flow   *FlowMatch      `json:"flow,omitempty"`
	Extra  json.RawMessage `json:"extra,omitempty"`
}

// ClientHelloPayload identifies a websocket client and advertised capabilities.
type ClientHelloPayload struct {
	Platform     string   `json:"platform"`
	Capabilities []string `json:"capabilities,omitempty"`
	Version      string   `json:"version,omitempty"`
}

// MacTrackedPID describes a leash-tracked process on macOS.
type MacTrackedPID struct {
	PID         int    `json:"pid"`
	LeashPID    int    `json:"leash_pid"`
	Executable  string `json:"executable"`
	TTYPath     string `json:"tty_path,omitempty"`
	Cwd         string `json:"cwd,omitempty"`
	Description string `json:"description,omitempty"`
}

// MacPIDSyncPayload carries tracked PID updates from macOS clients.
type MacPIDSyncPayload struct {
	Entries   []MacTrackedPID `json:"entries"`
	SessionID string          `json:"session_id,omitempty"`
}

// MacFileRule represents a macOS-specific file policy rule.
type MacFileRule struct {
	ID           string `json:"id"`
	Action       string `json:"action"`
	Executable   string `json:"executable"`
	Directory    string `json:"directory,omitempty"`
	File         string `json:"file,omitempty"`
	Kind         string `json:"kind,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Description  string `json:"description,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// MacExecRule represents an execution policy rule.
type MacExecRule struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Executable  string `json:"executable"`
	ArgsHash    string `json:"args_hash,omitempty"`
	Description string `json:"description,omitempty"`
}

// MacNetworkRule captures domain/IP policy rules.
type MacNetworkRule struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	TargetType  string `json:"target_type"`
	TargetValue string `json:"target_value"`
	Action      string `json:"action"`
	Cwd         string `json:"cwd,omitempty"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

// MacRuleSyncPayload bundles rule updates from macOS.
type MacRuleSyncPayload struct {
	FileRules    []MacFileRule    `json:"file_rules,omitempty"`
	ExecRules    []MacExecRule    `json:"exec_rules,omitempty"`
	NetworkRules []MacNetworkRule `json:"network_rules,omitempty"`
	Version      string           `json:"version,omitempty"`
}

// MacMITMConfigPayload distributes MITM proxy configuration to macOS shims.
type MacMITMConfigPayload struct {
	Enabled        bool      `json:"enabled"`
	ListenAddress  string    `json:"listen_address,omitempty"`
	CertificatePEM string    `json:"certificate_pem,omitempty"`
	Fingerprint    string    `json:"fingerprint,omitempty"`
	NotBefore      time.Time `json:"not_before,omitempty"`
	NotAfter       time.Time `json:"not_after,omitempty"`
	Version        int       `json:"version"`
}

// MacMITMSessionPayload announces lifecycle changes for MITM-proxied sessions.
type MacMITMSessionPayload struct {
	Action      string `json:"action"` // start|stop|refresh
	SessionID   string `json:"session_id"`
	LeashPID    int    `json:"leash_pid,omitempty"`
	Executable  string `json:"executable,omitempty"`
	Description string `json:"description,omitempty"`
}

// MacMITMTelemetryPayload reports intercepted HTTP activity.
type MacMITMTelemetryPayload struct {
	SessionID  string    `json:"session_id"`
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status_code"`
	Decision   string    `json:"decision"`
	RuleID     string    `json:"rule_id,omitempty"`
	Error      string    `json:"error,omitempty"`
	BytesIn    int64     `json:"bytes_in,omitempty"`
	BytesOut   int64     `json:"bytes_out,omitempty"`
	LatencyMS  int64     `json:"latency_ms,omitempty"`
}

// MacMITMCertificatePayload lets macOS clients request certificate installs/removals.
type MacMITMCertificatePayload struct {
	Action        string `json:"action"` // install|remove|regenerate|status
	PromptUser    bool   `json:"prompt_user,omitempty"`
	InstallSystem bool   `json:"install_system,omitempty"`
}

// MacEventPayload mirrors event telemetry from macOS components.
type MacEventPayload struct {
	Time       time.Time       `json:"time"`
	Event      string          `json:"event"`
	Details    json.RawMessage `json:"details,omitempty"`
	Severity   string          `json:"severity,omitempty"`
	Source     string          `json:"source,omitempty"`
	InstanceID string          `json:"instance_id,omitempty"`
	RuleID     string          `json:"rule_id,omitempty"`
}

// AckPayload acknowledges receipt of a client command.
type AckPayload struct {
	Cmd       string `json:"cmd"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	PendingID string `json:"pending_id,omitempty"`
}

// MacPolicyEventPayload represents a policy event from macOS requiring a decision.
type MacPolicyEventPayload struct {
	ID                      string   `json:"id"`
	Timestamp               string   `json:"timestamp"`
	Kind                    string   `json:"kind"`
	ProcessPath             string   `json:"process_path"`
	ProcessArguments        []string `json:"process_arguments"`
	CurrentWorkingDirectory string   `json:"current_working_directory,omitempty"`
	FilePath                string   `json:"file_path,omitempty"`
	FileOperation           string   `json:"file_operation,omitempty"`
	ParentProcessPath       string   `json:"parent_process_path,omitempty"`
	TTYPath                 string   `json:"tty_path,omitempty"`
	LeashProcessPath        string   `json:"leash_process_path,omitempty"`
	LeashPID                int      `json:"leash_pid,omitempty"`
	LeashArguments          []string `json:"leash_arguments,omitempty"`
	LeashTTYPath            string   `json:"leash_tty_path,omitempty"`
	PID                     int      `json:"pid"`
	ParentPID               int      `json:"parent_pid"`
}

// MacPolicyDecisionScope represents the scope of a policy decision.
type MacPolicyDecisionScope struct {
	Type string `json:"type"`           // "once", "always", "directory"
	Path string `json:"path,omitempty"` // For directory scope
}

// MacPolicyDecisionPayload represents a user's decision on a policy event.
type MacPolicyDecisionPayload struct {
	EventID string                 `json:"event_id"`
	Action  string                 `json:"action"` // "allow" or "deny"
	Scope   MacPolicyDecisionScope `json:"scope"`
}

// MacPolicyRule represents a macOS policy rule.
type MacPolicyRule struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`   // "processExec" or "fileAccess"
	Action         string `json:"action"` // "allow" or "deny"
	ExecutablePath string `json:"executable_path"`
	Directory      string `json:"directory,omitempty"`
	FilePath       string `json:"file_path,omitempty"`
	CoversCreates  bool   `json:"covers_creates,omitempty"`
}

// MacRuleQueryResponse returns current policy rules.
type MacRuleQueryResponse struct {
	Rules []MacPolicyRule `json:"rules"`
}

// MacRuleAddPayload adds new policy rules.
type MacRuleAddPayload struct {
	Rules []MacPolicyRule `json:"rules"`
}

// MacRuleRemovePayload removes rules by ID.
type MacRuleRemovePayload struct {
	IDs []string `json:"ids"`
}

// MacNetworkRuleQueryResponse returns current network rules.
type MacNetworkRuleQueryResponse struct {
	Rules []MacNetworkRule `json:"rules"`
}

// MacNetworkRuleUpdatePayload updates network rules.
type MacNetworkRuleUpdatePayload struct {
	Rules []MacNetworkRule `json:"rules"`
}

// HelloPayload (shim -> ctl) announces initial shim metadata.
type HelloPayload struct {
	ProxyPort string `json:"proxy_port,omitempty"`
}

// HeartbeatPayload (shim -> ctl) maintains liveness and light metrics.
type HeartbeatPayload struct {
	TS time.Time `json:"ts"`
}

// WrapPayload marshals a payload into an envelope.
func WrapPayload(sessionID, shimID, typ string, version int, payload any) (*Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Type:      typ,
		Version:   version,
		SessionID: sessionID,
		ShimID:    shimID,
		Payload:   raw,
	}, nil
}

// WrapPayloadWithRequestID marshals a payload with request ID for request-response pattern.
func WrapPayloadWithRequestID(sessionID, shimID, typ, requestID string, version int, payload any) (*Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Type:      typ,
		Version:   version,
		SessionID: sessionID,
		ShimID:    shimID,
		RequestID: requestID,
		Payload:   raw,
	}, nil
}

// UnmarshalPayload decodes the envelope payload into the provided destination.
func UnmarshalPayload[T any](env *Envelope, dst *T) error {
	return json.Unmarshal(env.Payload, dst)
}
