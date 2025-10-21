package transpiler

import (
	"fmt"
	"strings"

	"github.com/strongdm/leash/internal/lsm"
)

// PolicySetToCedar renders an LSM policy set into a Cedar policy string.
func PolicySetToCedar(policies *lsm.PolicySet) string {
	if policies == nil {
		policies = &lsm.PolicySet{}
	}

	openRules, execRules, connectRules := cloneAndSortPolicyRules(policies)

	var builder strings.Builder
	wrote := false

	emit := func(rule lsm.PolicyRule) {
		block := policyRuleToCedar(rule)
		if block == "" {
			return
		}
		if wrote {
			builder.WriteString("\n")
		}
		builder.WriteString(block)
		wrote = true
	}

	for _, rule := range openRules {
		emit(rule)
	}

	for _, rule := range execRules {
		emit(rule)
	}

	if policies.ConnectDefaultExplicit {
		block := defaultConnectToCedar(policies.ConnectDefaultAllow)
		if block != "" {
			if wrote {
				builder.WriteString("\n")
			}
			builder.WriteString(block)
			wrote = true
		}
	}

	for _, rule := range connectRules {
		emit(rule)
	}

	if !wrote {
		return ""
	}
	return builder.String()
}

func policyRuleToCedar(rule lsm.PolicyRule) string {
	actionName, ok := cedarActionName(rule.Operation)
	if !ok {
		return ""
	}

	effect := "permit"
	if rule.Action == lsm.PolicyDeny {
		effect = "forbid"
	}

	resourceClause := resourceClauseForRule(rule)
	if resourceClause == "" {
		return ""
	}

	var builder strings.Builder
	builder.WriteString(effect)
	builder.WriteString("(\n")
	builder.WriteString("    principal,\n")
	builder.WriteString(fmt.Sprintf("    action == Action::\"%s\",\n", actionName))
	builder.WriteString("    ")
	builder.WriteString(resourceClause)
	builder.WriteString("\n);")
	builder.WriteString("\n")

	return builder.String()
}

func cedarActionName(op int32) (string, bool) {
	switch op {
	case lsm.OpOpen:
		return "FileOpen", true
	case lsm.OpOpenRO:
		return "FileOpenReadOnly", true
	case lsm.OpOpenRW:
		return "FileOpenReadWrite", true
	case lsm.OpExec:
		return "ProcessExec", true
	case lsm.OpConnect:
		return "NetworkConnect", true
	default:
		return "", false
	}
}

func resourceClauseForRule(rule lsm.PolicyRule) string {
	switch rule.Operation {
	case lsm.OpOpen, lsm.OpOpenRO, lsm.OpOpenRW, lsm.OpExec:
		path := string(rule.Path[:rule.PathLen])
		if path == "" {
			return ""
		}
		resourceType := "File"
		if rule.IsDirectory == 1 || strings.HasSuffix(path, "/") {
			if !strings.HasSuffix(path, "/") {
				path += "/"
			}
			resourceType = "Dir"
		}
		return fmt.Sprintf("resource == %s::\"%s\"", resourceType, escapeCedarString(path))
	case lsm.OpConnect:
		host := string(rule.Hostname[:rule.HostnameLen])
		if host != "" {
			if rule.DestPort > 0 {
				host = fmt.Sprintf("%s:%d", host, rule.DestPort)
			}
			return fmt.Sprintf("resource == Host::\"%s\"", escapeCedarString(host))
		}
		if rule.DestIP != 0 {
			host = fmt.Sprintf("%d.%d.%d.%d", (rule.DestIP>>24)&0xFF, (rule.DestIP>>16)&0xFF, (rule.DestIP>>8)&0xFF, rule.DestIP&0xFF)
			if rule.DestPort > 0 {
				host = fmt.Sprintf("%s:%d", host, rule.DestPort)
			}
			return fmt.Sprintf("resource == Host::\"%s\"", escapeCedarString(host))
		}
		// Fallback to wildcard when no explicit host/ip is present.
		return "resource == Host::\"*\""
	default:
		return ""
	}
}

func defaultConnectToCedar(allow bool) string {
	effect := "forbid"
	if allow {
		effect = "permit"
	}
	return fmt.Sprintf("%s(\n    principal,\n    action == Action::\"NetworkConnect\",\n    resource == Host::\"*\"\n);\n", effect)
}

func escapeCedarString(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}
