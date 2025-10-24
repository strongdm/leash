package transpiler

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// LintSeverity indicates the severity of a lint finding.
type LintSeverity string

const (
	LintError   LintSeverity = "error"
	LintWarning LintSeverity = "warning"
)

// LintIssue describes one validation problem or warning discovered in Cedar.
type LintIssue struct {
	PolicyID   string       `json:"policyId"`
	Severity   LintSeverity `json:"severity"`
	Code       string       `json:"code"`
	Message    string       `json:"message"`
	Suggestion string       `json:"suggestion,omitempty"`
}

// LintReport aggregates issues for a set of Cedar policies.
type LintReport struct {
	Issues []LintIssue `json:"issues"`
}

// LintFromString parses Cedar and returns a report of issues indicating constructs
// that cannot be enforced by the current Leash IR.
func LintFromString(cedar string) (*LintReport, error) {
	parser := NewCedarParser()
	ps, err := parser.ParseFromString(cedar)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Cedar: %w", err)
	}
	issues := lintPolicySet(ps)
	return &LintReport{Issues: issues}, nil
}

func lintPolicySet(ps *CedarPolicySet) []LintIssue {
	var issues []LintIssue

	for _, p := range ps.Policies {
		// 1) Principal scoping is not enforced in IR (warning to avoid hard blocks)
		if !p.Principal.IsAny || len(p.Principal.InSet) > 0 || p.Principal.Type != "" || p.Principal.ID != "" {
			issues = append(issues, LintIssue{
				PolicyID:   p.ID,
				Severity:   LintWarning,
				Code:       "unsupported_principal",
				Message:    "Principal constraints are not enforced in v1; rules apply to the Leash instance/cgroup.",
				Suggestion: "Use bare 'principal' and run separate Leash instances to scope, or wait for per-principal enforcement.",
			})
		}

		// 2) Actions: only FileOpen/FileOpenReadOnly/FileOpenReadWrite/ProcessExec/NetworkConnect/HttpRewrite enforceable today
		var rawActions []string
		rawActions = append(rawActions, p.Action.Actions...)
		rawActions = append(rawActions, p.Action.InSet...)
		if len(rawActions) == 0 && p.Action.IsAny {
			issues = append(issues, LintIssue{
				PolicyID:   p.ID,
				Severity:   LintError,
				Code:       "missing_action",
				Message:    "Policy omits an explicit Action; specify a concrete Action.",
				Suggestion: "Use Action::\"FileOpen\"|\"FileOpenReadOnly\"|\"FileOpenReadWrite\"|\"ProcessExec\"|\"NetworkConnect\"|\"HttpRewrite\".",
			})
		}
		for _, a := range rawActions {
			if strings.HasPrefix(a, "Action::") {
				id := strings.Trim(strings.TrimPrefix(a, "Action::"), `"`)
				switch {
				case strings.EqualFold(id, "FileOpen"), strings.EqualFold(id, "FileOpenReadOnly"), strings.EqualFold(id, "FileOpenReadWrite"), strings.EqualFold(id, "ProcessExec"), strings.EqualFold(id, "NetworkConnect"), strings.EqualFold(id, "HttpRewrite"), strings.EqualFold(id, "McpCall"):
					// ok
				default:
					issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "unsupported_action_id", Message: fmt.Sprintf("Action %q is not supported.", id), Suggestion: "Use FileOpen, FileOpenReadOnly, FileOpenReadWrite, ProcessExec, NetworkConnect, HttpRewrite, or McpCall."})
				}
				continue
			}
			// Anything else in the action head is non-canonical and rejected
			issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "unsupported_action_syntax", Message: fmt.Sprintf("Non-canonical action head %q; only Action::\"…\" is supported.", a), Suggestion: "Use Action::\"FileOpen\"|\"FileOpenReadOnly\"|\"FileOpenReadWrite\"|\"ProcessExec\"|\"NetworkConnect\"|\"HttpRewrite\"|\"McpCall\"."})
		}

		// 3) Resources and basic type matching
		ops := extractOperationsForLint(p.Action)
		res := extractResourcesForLint(p)
		hasMCPCall := containsActionID(p.Action, "McpCall")
		// MCP tool/server: advise current enforcement limits
		if hasMCPCall {
			if p.Effect == Permit {
				issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintWarning, Code: "mcp_allow_noop", Message: "Allow on McpCall is informational in v1; only deny is enforceable."})
			}
			if len(res) == 0 {
				issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintWarning, Code: "mcp_no_resources", Message: "McpCall policy has no resources; specify MCP::Server or MCP::Tool."})
			}
		}
		if strings.Contains(p.Resource.Type, "DnsZone") {
			issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintWarning, Code: "dnszone_apex_excluded", Message: "Net::DnsZone maps to '*.zone' in IR; apex host is not included.", Suggestion: "Add Host::\"zone\" explicitly if the apex should be included."})
		}
		for _, ent := range p.Resource.InSet {
			if strings.Contains(ent, "::DnsZone::") || strings.HasSuffix(ent, "::DnsZone") {
				issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintWarning, Code: "dnszone_apex_excluded", Message: "Net::DnsZone maps to '*.zone' in IR; apex host is not included.", Suggestion: "Add Host::\"zone\" explicitly if the apex should be included."})
				break
			}
		}

		if len(res) == 0 {
			issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "no_resources", Message: "Policy has no enforceable resources (only specific File/Dir/Host are supported).", Suggestion: "Use resource in [ File::\"/path\" | Dir::\"/dir\" | Host::\"name[:port]\" ] or context.hostname equals/like."})
		}

		for _, r := range res {
			switch r.Type {
			case "File", "Dir", "Host":
			case "MCPServer", "MCPTool":
				if !hasMCPCall {
					issues = append(issues, LintIssue{
						PolicyID: p.ID, Severity: LintError, Code: "mcp_resource_without_mcp_call",
						Message:    fmt.Sprintf("MCP resources require Action::\"McpCall\"; found %q without it.", r.Type),
						Suggestion: "Add Action::\"McpCall\" to the policy or remove MCP::Server/MCP::Tool resources.",
					})
				}
			case "":
			case "IpRange":
				issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "cidr_unsupported", Message: "IpRange/CIDR targets are not supported in v1."})
			default:
				issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "unsupported_resource_type", Message: fmt.Sprintf("Resource type %q is not supported.", r.Type), Suggestion: "Use File, Dir, or Host (map Net::Hostname→Host, Net::DnsZone→Host as '*.zone', Fs::Directory→Dir)."})
			}
		}

		// Operation/resource compatibility and value validation
		for _, op := range ops {
			for _, r := range res {
				switch op {
				case "open", "read", "write", "exec":
					if r.Type == "Host" {
						issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "resource_mismatch", Message: "Host cannot be used with file/exec operations.", Suggestion: "Use File or Dir for file/exec operations."})
					}
					if (r.Type == "File" || r.Type == "Dir") && len(r.Value) >= 256 {
						issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "path_too_long", Message: fmt.Sprintf("Path length %d exceeds 255 bytes.", len(r.Value)), Suggestion: "Shorten the path or target a higher-level directory."})
					}
					if r.Type == "Dir" && !strings.HasSuffix(r.Value, "/") {
						issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintWarning, Code: "dir_missing_trailing_slash", Message: "Directory resources should end with '/'.", Suggestion: "Append '/' to indicate recursive coverage."})
					}
				case "connect":
					if r.Type == "File" || r.Type == "Dir" {
						issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "resource_mismatch", Message: "File/Dir cannot be used with connect operation.", Suggestion: "Use Host::\"name\" or Host::\"ip[:port]\"."})
					}
					if r.Type == "Host" {
						host, port := splitHostPortLoose(r.Value)
						if len(host) >= 128 {
							issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "hostname_too_long", Message: fmt.Sprintf("Hostname length %d exceeds 127 bytes.", len(host)), Suggestion: "Shorten the hostname."})
						}
						if strings.Contains(host, "*") && !strings.HasPrefix(host, "*.") && host != "*" {
							issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "unsupported_wildcard", Message: fmt.Sprintf("Unsupported wildcard pattern %q; only prefix '*.domain' is supported.", host), Suggestion: "Use '*.example.com' style or enumerate explicit hosts."})
						}
						if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
							issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "ipv6_unsupported", Message: fmt.Sprintf("IPv6 literal %q is not supported in connect rules.", host), Suggestion: "Use IPv4 or hostname."})
						}
						if port != "" {
							if _, err := strconv.ParseUint(port, 10, 16); err != nil {
								issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "invalid_port", Message: fmt.Sprintf("Invalid port %q (must be 1-65535).", port)})
							}
						}
						// Warn authors that hostname-based rules require the proxy for enforcement
						if net.ParseIP(host) == nil && host != "*" {
							issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintWarning, Code: "proxy_recommended", Message: "Hostname-based connect rules require the Leash proxy for enforcement; kernel enforces IP only.", Suggestion: "Use IP targets or ensure the proxy is enabled for these rules."})
						}
					}
				}
			}
		}

		// 4) Conditions: only resource in [ ... ] and context.hostname equals/like are handled
		for _, c := range p.Conditions {
			switch c.Type {
			case ConditionResourceIn:
				for _, entry := range c.ResourceSet {
					if !strings.Contains(entry, "::") {
						issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "invalid_resource_literal", Message: fmt.Sprintf("Unrecognized resource literal %q in set.", entry)})
					}
					if strings.Contains(entry, "DnsZone::") || strings.Contains(entry, "::DnsZone::") || strings.HasSuffix(entry, "::DnsZone") {
						issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintWarning, Code: "dnszone_apex_excluded", Message: "Net::DnsZone maps to '*.zone' in IR; apex host is not included.", Suggestion: "Add Host::\"zone\" explicitly if the apex should be included."})
					}
				}
			case ConditionContextEquals, ConditionContextLike:
				if key := strings.ToLower(strings.TrimSpace(c.ContextKey)); key != "hostname" {
					if key == "header" || key == "value" {
						continue
					}
					issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "unsupported_context_key", Message: fmt.Sprintf("Context key %q is not supported (data-plane supports 'hostname'; 'header'/'value' only for http.rewrite).", c.ContextKey)})
				} else if c.Type == ConditionContextLike {
					// Additional hostname like() checks handled above in Host resources via extractResourcesForLint
				}
				if c.Kind == "unless" {
					issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "unsupported_unless", Message: "'unless' conditions are not supported by the IR.", Suggestion: "Rewrite the policy using explicit forbid/permit rules."})
				}
			default:
				issues = append(issues, LintIssue{PolicyID: p.ID, Severity: LintError, Code: "unsupported_condition", Message: fmt.Sprintf("Condition %q cannot be enforced; it will be ignored.", strings.TrimSpace(c.Expression)), Suggestion: "Restrict policy using resource lists or context.hostname equals/like."})
			}
		}
	}
	return dedupeIssues(issues)
}

// containsActionID returns true if the Action constraint includes Action::"<id>"
func containsActionID(ac ActionConstraint, id string) bool {
	target := strings.ToLower(strings.TrimSpace(id))
	if target == "" {
		return false
	}
	actions := append([]string{}, ac.Actions...)
	actions = append(actions, ac.InSet...)
	for _, a := range actions {
		if strings.HasPrefix(a, "Action::") {
			got := strings.Trim(strings.TrimPrefix(a, "Action::"), `"`)
			if strings.EqualFold(got, target) {
				return true
			}
		}
	}
	return false
}

// extractOperationsForLint mirrors transpiler.extractOperations but does not rely on the transpile path.
func extractOperationsForLint(ac ActionConstraint) []string {
	ops := make([]string, 0)
	for _, a := range ac.Actions {
		if strings.HasPrefix(a, "Action::") {
			id := strings.Trim(strings.TrimPrefix(a, "Action::"), `"`)
			switch strings.ToLower(id) {
			case strings.ToLower("FileOpen"):
				ops = append(ops, "open")
			case strings.ToLower("FileOpenReadOnly"):
				ops = append(ops, "read")
			case strings.ToLower("FileOpenReadWrite"):
				ops = append(ops, "write")
			case strings.ToLower("ProcessExec"):
				ops = append(ops, "exec")
			case strings.ToLower("NetworkConnect"):
				ops = append(ops, "connect")
			}
		}
	}
	for _, a := range ac.InSet {
		if strings.HasPrefix(a, "Action::") {
			id := strings.Trim(strings.TrimPrefix(a, "Action::"), `"`)
			switch strings.ToLower(id) {
			case strings.ToLower("FileOpen"):
				ops = append(ops, "open")
			case strings.ToLower("FileOpenReadOnly"):
				ops = append(ops, "read")
			case strings.ToLower("FileOpenReadWrite"):
				ops = append(ops, "write")
			case strings.ToLower("ProcessExec"):
				ops = append(ops, "exec")
			case strings.ToLower("NetworkConnect"):
				ops = append(ops, "connect")
			}
		}
	}
	return ops
}

// extractResourcesForLint mirrors transpiler.extractResources.
func extractResourcesForLint(p CedarPolicy) []Resource {
	t := NewCedarToLeashTranspiler()
	return t.extractResources(p)
}

func splitHostPortLoose(value string) (host string, port string) {
	if strings.Count(value, ":") == 0 {
		return value, ""
	}
	parts := strings.SplitN(value, ":", 2)
	return parts[0], parts[1]
}

func dedupeIssues(in []LintIssue) []LintIssue {
	if len(in) == 0 {
		return in
	}
	type key struct{ id, code, msg string }
	seen := make(map[key]bool)
	out := make([]LintIssue, 0, len(in))
	for _, it := range in {
		k := key{it.PolicyID, it.Code, it.Message}
		if !seen[k] {
			seen[k] = true
			out = append(out, it)
		}
	}
	return out
}

func splitNS(v string) (string, string) {
	parts := strings.SplitN(v, "::", 2)
	if len(parts) != 2 {
		return v, ""
	}
	ns := parts[0]
	name := strings.Trim(parts[1], `"`)
	return ns, name
}
