package transpiler

import (
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/ast"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
)

type CedarToLeashTranspiler struct {
	parser *CedarParser
}

func NewCedarToLeashTranspiler() *CedarToLeashTranspiler {
	return &CedarToLeashTranspiler{
		parser: NewCedarParser(),
	}
}

func (t *CedarToLeashTranspiler) TranspileFromReader(reader io.Reader) (*lsm.PolicySet, []proxy.HeaderRewriteRule, error) {
	policySet, err := t.parser.ParseFromReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse Cedar policies: %w", err)
	}

	return t.TranspilePolicySet(policySet)
}

func (t *CedarToLeashTranspiler) TranspileFromString(content string) (*lsm.PolicySet, []proxy.HeaderRewriteRule, error) {
	return t.TranspileFromNamedString("policies", content)
}

// TranspileFromNamedString parses Cedar content using the provided source name
// in error messages before converting it to Leash IR.
func (t *CedarToLeashTranspiler) TranspileFromNamedString(name, content string) (*lsm.PolicySet, []proxy.HeaderRewriteRule, error) {
	policySet, err := t.parser.ParseFromNamedString(name, content)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse Cedar policies: %w", err)
	}

	return t.TranspilePolicySet(policySet)
}

func (t *CedarToLeashTranspiler) TranspilePolicySet(policySet *CedarPolicySet) (*lsm.PolicySet, []proxy.HeaderRewriteRule, error) {
	leashPolicies := &lsm.PolicySet{
		Open:    []lsm.PolicyRule{},
		Exec:    []lsm.PolicyRule{},
		Connect: []lsm.PolicyRule{},
		MCP:     []lsm.MCPPolicyRule{},
	}
	httpRewrites := []proxy.HeaderRewriteRule{}

	for _, policy := range policySet.Policies {
		// Special-case: MCP server forbids compile to connect denies in v1
		if hasMCPCallAction(policy) && policy.Effect == Forbid {
			hosts := t.extractMCPServerHosts(policy)
			tools := t.extractMCPToolNames(policy)
			for _, h := range hosts {
				r, err := t.buildRule(int32(lsm.PolicyDeny), "connect", Resource{Type: "Host", Value: h})
				if err == nil {
					leashPolicies.Connect = append(leashPolicies.Connect, r)
				}
			}
			if len(hosts) == 0 {
				hosts = []string{""}
			}
			if len(tools) == 0 {
				tools = []string{""}
			}
			for _, server := range hosts {
				for _, tool := range tools {
					leashPolicies.MCP = append(leashPolicies.MCP, lsm.MCPPolicyRule{
						Action: int32(lsm.PolicyDeny),
						Server: server,
						Tool:   tool,
					})
				}
			}
			// Skip normal conversion for MCP policies to avoid spurious errors
			continue
		}
		// Extract any HTTP rewrite rules present in Cedar
		if rew := t.extractHTTPRewrites(policy); len(rew) > 0 {
			httpRewrites = append(httpRewrites, rew...)
		}

		rules, err := t.convertPolicy(policy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping policy %s: %v\n", policy.ID, err)
			continue
		}

		for _, rule := range rules {
			switch rule.Operation {
			case lsm.OpOpen, lsm.OpOpenRO, lsm.OpOpenRW:
				leashPolicies.Open = append(leashPolicies.Open, rule)
			case lsm.OpExec:
				leashPolicies.Exec = append(leashPolicies.Exec, rule)
			case lsm.OpConnect:
				leashPolicies.Connect = append(leashPolicies.Connect, rule)
			}
		}
	}

	applyConnectDefaults(leashPolicies)
	return leashPolicies, httpRewrites, nil
}

func applyConnectDefaults(policies *lsm.PolicySet) {
	if policies == nil {
		return
	}
	allowAny := false
	denyAny := false
	for _, rule := range policies.Connect {
		if rule.DestIP != 0 || rule.DestPort != 0 {
			continue
		}
		host := string(rule.Hostname[:rule.HostnameLen])
		if host != "*" {
			continue
		}
		if rule.Action == lsm.PolicyAllow {
			allowAny = true
		} else if rule.Action == lsm.PolicyDeny {
			denyAny = true
		}
	}
	if denyAny {
		policies.ConnectDefaultAllow = false
		policies.ConnectDefaultExplicit = true
	} else if allowAny && !policies.ConnectDefaultExplicit {
		policies.ConnectDefaultAllow = true
		// keep ConnectDefaultExplicit false to indicate implicit default
	}
}

func (t *CedarToLeashTranspiler) convertPolicy(policy CedarPolicy) ([]lsm.PolicyRule, error) {
	action := int32(lsm.PolicyDeny)
	if policy.Effect == Permit {
		action = int32(lsm.PolicyAllow)
	}

	operations := t.extractOperations(policy.Action)
	if len(operations) == 0 {
		return nil, fmt.Errorf("no operations found in policy")
	}

	resources := t.extractResources(policy)
	if len(resources) == 0 {
		return nil, fmt.Errorf("no resources found in policy")
	}

	var rules []lsm.PolicyRule
	for _, op := range operations {
		for _, resource := range resources {
			rule, err := t.buildRule(action, op, resource)
			if err != nil {
				continue
			}
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

// hasMCPCallAction returns true if the policy includes Action::"McpCall" in its Action set.
func hasMCPCallAction(policy CedarPolicy) bool {
	actions := append([]string{}, policy.Action.Actions...)
	actions = append(actions, policy.Action.InSet...)
	for _, a := range actions {
		if strings.HasPrefix(a, "Action::") {
			id := strings.Trim(strings.TrimPrefix(a, "Action::"), `"`)
			if strings.EqualFold(id, "McpCall") {
				return true
			}
		}
	}
	return false
}

// extractMCPServerHosts collects MCP::Server ids referenced either in head or in ResourceIn conditions
// and returns them as hostnames suitable for Net::Hostname mapping.
func (t *CedarToLeashTranspiler) extractMCPServerHosts(policy CedarPolicy) []string {
	hosts := []string{}
	// From parsed resources (head or resource-in conditions)
	res := t.extractResources(policy)
	for _, r := range res {
		if r.Type == "MCPServer" && r.Value != "" {
			hosts = append(hosts, r.Value)
		}
	}
	// Fallback: scan AST text for MCP::Server::"host"
	if policy.NativePolicy != nil && policy.NativePolicy.AST() != nil {
		expr := fmt.Sprintf("%+v", policy.NativePolicy.AST())
		re := regexp.MustCompile(`MCP::Server::\"([^\"]+)\"`)
		matches := re.FindAllStringSubmatch(expr, -1)
		for _, m := range matches {
			if len(m) > 1 {
				hosts = append(hosts, m[1])
			}
		}
	}
	// Normalize and dedupe
	dedup := make(map[string]struct{})
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		lh := strings.ToLower(strings.TrimSpace(h))
		if lh == "" {
			continue
		}
		if _, ok := dedup[lh]; !ok {
			dedup[lh] = struct{}{}
			out = append(out, lh)
		}
	}
	sort.Strings(out)
	return out
}

func (t *CedarToLeashTranspiler) extractMCPToolNames(policy CedarPolicy) []string {
	resources := t.extractResources(policy)
	dedup := make(map[string]struct{})
	for _, r := range resources {
		if r.Type == "MCPTool" && r.Value != "" {
			name := strings.ToLower(strings.TrimSpace(r.Value))
			if name == "" {
				continue
			}
			if _, ok := dedup[name]; !ok {
				dedup[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(dedup))
	for name := range dedup {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (t *CedarToLeashTranspiler) extractOperations(actionConstraint ActionConstraint) []string {
	operations := []string{}
	for _, action := range actionConstraint.Actions {
		operations = append(operations, canonicalizeActionToOperation(action)...)
	}
	for _, action := range actionConstraint.InSet {
		operations = append(operations, canonicalizeActionToOperation(action)...)
	}
	return operations
}

// canonicalizeActionToOperation maps various action identifier forms to canonical operations
func canonicalizeActionToOperation(action string) []string {
	out := []string{}
	switch {
	case strings.HasPrefix(action, "Action::"):
		id := strings.Trim(strings.TrimPrefix(action, "Action::"), `"`)
		idLower := strings.ToLower(id)
		// Canonical PascalCase actions
		switch idLower {
		case strings.ToLower("FileOpen"):
			out = append(out, "open")
		case strings.ToLower("FileOpenReadOnly"):
			out = append(out, "read")
		case strings.ToLower("FileOpenReadWrite"):
			out = append(out, "write")
		case strings.ToLower("ProcessExec"):
			out = append(out, "exec")
		case strings.ToLower("NetworkConnect"):
			out = append(out, "connect")
		case strings.ToLower("HttpRewrite"): /* handled separately by extractHTTPRewrites */
		case strings.ToLower("McpCall"): /* handled separately as MCP */
		default:
			// Unsupported action id
		}
	default:
		if strings.HasPrefix(action, "Fs::") {
			name := strings.Trim(strings.TrimPrefix(action, "Fs::"), `"`)
			switch name {
			case "ReadFile":
				out = append(out, "read")
			case "WriteFile":
				out = append(out, "write")
			case "ListDir":
				out = append(out, "read")
			case "CreateFileUnder":
				out = append(out, "write")
			}
		} else if strings.HasPrefix(action, "Proc::") {
			name := strings.Trim(strings.TrimPrefix(action, "Proc::"), `"`)
			if strings.EqualFold(name, "Exec") {
				out = append(out, "exec")
			}
		} else if strings.HasPrefix(action, "Net::") {
			name := strings.Trim(strings.TrimPrefix(action, "Net::"), `"`)
			if strings.EqualFold(name, "Connect") {
				out = append(out, "connect")
			}
		} else if strings.HasPrefix(action, "Http::") {
			// Http.Request not supported; Http.ApplyRewrite handled in extractHTTPRewrites
		}
	}
	return out
}

func (t *CedarToLeashTranspiler) extractResources(policy CedarPolicy) []Resource {
	resources := []Resource{}
	// Head form
	if policy.Resource.Type != "" && policy.Resource.ID != "" {
		if res := t.parseResource(fmt.Sprintf("%s::%q", policy.Resource.Type, policy.Resource.ID)); res != nil {
			resources = append(resources, *res)
		} else {
			resources = append(resources, Resource{Type: policy.Resource.Type, Value: policy.Resource.ID})
		}
	}
	// Head Entities list
	if len(policy.Resource.InSet) > 0 {
		for _, res := range policy.Resource.InSet {
			if r := t.parseResource(res); r != nil {
				resources = append(resources, *r)
			}
		}
	}
	// Conditions
	for _, condition := range policy.Conditions {
		if condition.Type == ConditionResourceIn {
			for _, res := range condition.ResourceSet {
				if r := t.parseResource(res); r != nil {
					resources = append(resources, *r)
				}
			}
		} else if condition.Type == ConditionContextEquals || condition.Type == ConditionContextLike {
			if condition.ContextKey == "hostname" {
				hostname := ""
				if condition.Type == ConditionContextEquals {
					hostname = fmt.Sprintf("%v", condition.ContextValue)
				} else if condition.Type == ConditionContextLike {
					hostname = condition.Pattern
				}
				if hostname != "" {
					resources = append(resources, Resource{Type: "Host", Value: hostname})
				}
			}
		}
	}
	return resources
}

func (t *CedarToLeashTranspiler) parseResource(resourceStr string) *Resource {
	if strings.TrimSpace(resourceStr) == "" {
		return nil
	}
	// Normalize escaped quotes produced by cedar AST serialization
	clean := strings.ReplaceAll(resourceStr, `\"`, `"`)
	parts := strings.Split(clean, "::")
	if len(parts) < 2 {
		return nil
	}
	valuePart := strings.TrimSpace(parts[len(parts)-1])
	typeParts := make([]string, len(parts)-1)
	for i, part := range parts[:len(parts)-1] {
		typeParts[i] = strings.Trim(strings.TrimSpace(part), `"`)
	}
	rawType := strings.TrimSpace(strings.Join(typeParts, "::"))
	if rawType == "" {
		return nil
	}
	resourceValue := strings.Trim(strings.TrimSpace(valuePart), `"`)

	resourceType := rawType
	switch {
	case rawType == "File" || strings.HasSuffix(rawType, "::File") || strings.HasSuffix(rawType, ".File"):
		resourceType = "File"
	case rawType == "Dir" || strings.HasSuffix(rawType, "::Directory") || strings.HasSuffix(rawType, ".Directory"):
		resourceType = "Dir"
	case rawType == "Host" || strings.HasSuffix(rawType, "::Hostname") || strings.HasSuffix(rawType, ".Hostname"):
		resourceType = "Host"
	case strings.HasSuffix(rawType, "::DnsZone") || strings.HasSuffix(rawType, ".DnsZone"):
		resourceType = "Host"
		if !strings.HasPrefix(resourceValue, "*.") {
			resourceValue = "*." + resourceValue
		}
	case strings.HasSuffix(rawType, "::Endpoint") || strings.HasSuffix(rawType, ".Endpoint"):
		resourceType = "Host"
	case strings.HasSuffix(rawType, "::Server") || strings.HasSuffix(rawType, ".Server"):
		// MCP::Server maps to MCPServer pseudo-type; later compiled to Host
		resourceType = "MCPServer"
	case strings.HasSuffix(rawType, "::Tool") || strings.HasSuffix(rawType, ".Tool"):
		resourceType = "MCPTool"
	case strings.HasSuffix(rawType, "::IpRange") || strings.HasSuffix(rawType, ".IpRange"):
		resourceType = "IpRange" // unsupported in v1, linter will flag
	}
	return &Resource{Type: resourceType, Value: resourceValue}
}

func (t *CedarToLeashTranspiler) buildRule(action int32, operation string, resource Resource) (lsm.PolicyRule, error) {
	var rule lsm.PolicyRule
	rule.Action = action

	switch operation {
	case "open":
		rule.Operation = lsm.OpOpen
		return t.buildFileRule(rule, resource)
	case "read":
		rule.Operation = lsm.OpOpenRO
		return t.buildFileRule(rule, resource)
	case "write":
		rule.Operation = lsm.OpOpenRW
		return t.buildFileRule(rule, resource)
	case "exec":
		rule.Operation = lsm.OpExec
		return t.buildFileRule(rule, resource)
	case "connect":
		rule.Operation = lsm.OpConnect
		return t.buildConnectRule(rule, resource)
	default:
		return rule, fmt.Errorf("unsupported operation: %s", operation)
	}
}

func (t *CedarToLeashTranspiler) buildFileRule(rule lsm.PolicyRule, resource Resource) (lsm.PolicyRule, error) {
	var path string
	isDirectory := int32(0)

	switch resource.Type {
	case "File":
		path = resource.Value
	case "Dir":
		path = resource.Value
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
		isDirectory = 1
	default:
		return rule, fmt.Errorf("invalid resource type for file operation: %s", resource.Type)
	}

	if len(path) >= 256 {
		return rule, fmt.Errorf("path too long: %s", path)
	}

	copy(rule.Path[:], path)
	rule.PathLen = int32(len(path))
	rule.IsDirectory = isDirectory

	return rule, nil
}

func (t *CedarToLeashTranspiler) buildConnectRule(rule lsm.PolicyRule, resource Resource) (lsm.PolicyRule, error) {
	switch resource.Type {
	case "Host":
		hostname := resource.Value
		var port uint16 = 0

		if strings.Contains(hostname, ":") {
			parts := strings.SplitN(hostname, ":", 2)
			hostname = parts[0]
			if p, err := strconv.ParseUint(parts[1], 10, 16); err == nil {
				port = uint16(p)
			}
		}

		if len(hostname) >= 128 {
			return rule, fmt.Errorf("hostname too long: %s", hostname)
		}

		if net.ParseIP(hostname) != nil {
			ip := net.ParseIP(hostname)
			ipv4 := ip.To4()
			if ipv4 == nil {
				return rule, fmt.Errorf("IPv6 not supported: %s", hostname)
			}
			rule.DestIP = uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
			rule.DestPort = port
		} else {
			if strings.HasPrefix(hostname, "*.") {
				rule.IsWildcard = 1
			}
			copy(rule.Hostname[:], hostname)
			rule.HostnameLen = int32(len(hostname))
			rule.DestPort = port
		}

		return rule, nil

	default:
		return rule, fmt.Errorf("invalid resource type for connect operation: %s", resource.Type)
	}
}

// extractHTTPRewrites builds HTTP rewrite rules from Cedar when action is http.rewrite or Http::ApplyRewrite
func (t *CedarToLeashTranspiler) extractHTTPRewrites(policy CedarPolicy) []proxy.HeaderRewriteRule {
	// Only on permit
	if policy.Effect != Permit {
		return nil
	}
	// Detect http rewrite action
	isRewrite := false
	actions := append([]string{}, policy.Action.Actions...)
	actions = append(actions, policy.Action.InSet...)
	for _, a := range actions {
		if strings.HasPrefix(a, "Action::") {
			id := strings.Trim(strings.TrimPrefix(a, "Action::"), `"`)
			if strings.EqualFold(id, "HttpRewrite") {
				isRewrite = true
			}
		}
		if strings.HasPrefix(a, "Http::") {
			name := strings.Trim(strings.TrimPrefix(a, "Http::"), `"`)
			if strings.EqualFold(name, "ApplyRewrite") {
				isRewrite = true
			}
		}
	}
	if !isRewrite {
		return nil
	}

	// First, try to collect header/value from parsed simple equals conditions
	var headerName, headerValue string
	for _, c := range policy.Conditions {
		if c.Type == ConditionContextEquals {
			key := strings.ToLower(strings.TrimSpace(c.ContextKey))
			if key == "header" && headerName == "" {
				if s, ok := c.ContextValue.(string); ok {
					headerName = s
				} else {
					headerName = fmt.Sprintf("%v", c.ContextValue)
				}
			}
			if key == "value" && headerValue == "" {
				if s, ok := c.ContextValue.(string); ok {
					headerValue = s
				} else {
					headerValue = fmt.Sprintf("%v", c.ContextValue)
				}
			}
		}
	}
	// Fallback: scan AST string representation for header/value tokens
	if (headerName == "" || headerValue == "") && policy.NativePolicy != nil && policy.NativePolicy.AST() != nil {
		expr := fmt.Sprintf("%+v", policy.NativePolicy.AST())
		if headerName == "" {
			if idx := strings.Index(expr, "Value:header"); idx >= 0 {
				s := expr[idx:]
				if j := strings.Index(s, "Right:{Value:"); j >= 0 {
					k := j + len("Right:{Value:")
					name := make([]rune, 0)
					for _, r := range []rune(s[k:]) {
						if r == '}' || r == ' ' || r == '\n' || r == '\t' {
							break
						}
						name = append(name, r)
					}
					headerName = strings.TrimSpace(string(name))
				}
			}
		}
		if headerValue == "" {
			if idx := strings.Index(expr, "Value:value"); idx >= 0 {
				s := expr[idx:]
				if j := strings.Index(s, "Right:{Value:"); j >= 0 {
					k := j + len("Right:{Value:")
					val := make([]rune, 0)
					for _, r := range []rune(s[k:]) {
						if r == '}' || r == ' ' || r == '\n' || r == '\t' {
							break
						}
						val = append(val, r)
					}
					headerValue = strings.TrimSpace(string(val))
				}
			}
		}
	}
	if headerName == "" || headerValue == "" {
		return nil
	}

	// Map resources to hosts
	var hosts []string
	res := t.extractResources(policy)
	for _, r := range res {
		if r.Type == "Host" && r.Value != "" {
			hosts = append(hosts, r.Value)
		}
	}
	if len(hosts) == 0 && policy.Resource.Type != "" && policy.Resource.ID != "" {
		if rr := t.parseResource(fmt.Sprintf("%s::%q", policy.Resource.Type, policy.Resource.ID)); rr != nil && rr.Type == "Host" && rr.Value != "" {
			hosts = append(hosts, rr.Value)
		}
	}
	if len(hosts) == 0 {
		if h := extractHostnameFromASTHead(policy); h != "" {
			hosts = append(hosts, h)
		}
		if len(hosts) == 0 {
			return nil
		}
	}

	var rules []proxy.HeaderRewriteRule
	for _, h := range hosts {
		rules = append(rules, proxy.HeaderRewriteRule{Host: h, Header: headerName, Value: headerValue})
	}
	return rules
}

// extractHostnameFromASTHead tries to pull a hostname from the policy head resource via cedar AST
func extractHostnameFromASTHead(policy CedarPolicy) string {
	if policy.NativePolicy == nil || policy.NativePolicy.AST() == nil {
		return ""
	}
	if policy.Resource.Type != "" && policy.Resource.ID != "" {
		if strings.Contains(strings.ToLower(policy.Resource.Type), "host") {
			return policy.Resource.ID
		}
	}
	return ""
}

type Resource struct {
	Type  string
	Value string
}

type CedarParser struct {
	policySet *cedarlib.PolicySet
}

func NewCedarParser() *CedarParser {
	return &CedarParser{}
}

func (p *CedarParser) ParseFromReader(reader io.Reader) (*CedarPolicySet, error) {
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy content: %w", err)
	}

	return p.ParseFromString(string(content))
}

func (p *CedarParser) ParseFromString(content string) (*CedarPolicySet, error) {
	return p.ParseFromNamedString("policies", content)
}

func (p *CedarParser) ParseFromNamedString(name, content string) (*CedarPolicySet, error) {
	nativePolicySet, err := cedarlib.NewPolicySetFromBytes(name, []byte(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Cedar policies: %w", err)
	}

	p.policySet = nativePolicySet

	policySet := &CedarPolicySet{
		Policies:        make([]CedarPolicy, 0),
		NativePolicySet: nativePolicySet,
	}

	policies, err := p.extractPoliciesFromNativeSet(nativePolicySet)
	if err != nil {
		return nil, fmt.Errorf("failed to extract policy details: %w", err)
	}

	policySet.Policies = policies
	return policySet, nil
}

func (p *CedarParser) extractPoliciesFromNativeSet(nativePolicySet *cedarlib.PolicySet) ([]CedarPolicy, error) {
	policies := make([]CedarPolicy, 0)

	for policyID, nativePolicy := range nativePolicySet.Map() {
		policy, err := p.extractPolicyFromAST(string(policyID), nativePolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to extract policy %s: %w", policyID, err)
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func (p *CedarParser) extractPolicyFromAST(id string, nativePolicy *cedarlib.Policy) (CedarPolicy, error) {
	var effect Effect
	if nativePolicy.Effect() == types.Permit {
		effect = Permit
	} else {
		effect = Forbid
	}

	policy := CedarPolicy{
		ID:           id,
		Effect:       effect,
		Principal:    EntityConstraint{IsAny: true},
		Action:       ActionConstraint{IsAny: true},
		Resource:     EntityConstraint{IsAny: true},
		Conditions:   []Condition{},
		Annotations:  make(map[string]string),
		NativePolicy: nativePolicy,
	}

	for key, value := range nativePolicy.Annotations() {
		policy.Annotations[string(key)] = string(value)
	}

	policyAST := nativePolicy.AST()
	if policyAST == nil {
		return policy, nil
	}

	if principalConstraint := p.extractPrincipalFromAST(policyAST); principalConstraint != nil {
		policy.Principal = *principalConstraint
	}

	if actionConstraint := p.extractActionFromAST(policyAST); actionConstraint != nil {
		policy.Action = *actionConstraint
	}

	if resourceConstraint := p.extractResourceFromAST(policyAST); resourceConstraint != nil {
		policy.Resource = *resourceConstraint
	}

	policy.Conditions = p.extractConditionsFromAST(policyAST)

	return policy, nil
}

func (p *CedarParser) extractPrincipalFromAST(policyAST *ast.Policy) *EntityConstraint {
	principalValue := reflect.ValueOf(policyAST.Principal)

	if entityField := principalValue.FieldByName("Entity"); entityField.IsValid() {
		entityUID := entityField.Interface().(types.EntityUID)
		return &EntityConstraint{
			Type: string(entityUID.Type),
			ID:   string(entityUID.ID),
		}
	}

	if typeField := principalValue.FieldByName("Type"); typeField.IsValid() {
		entityType := typeField.Interface().(types.EntityType)
		return &EntityConstraint{
			Type:   string(entityType),
			IsLike: true,
		}
	}

	return &EntityConstraint{IsAny: true}
}

func (p *CedarParser) extractActionFromAST(policyAST *ast.Policy) *ActionConstraint {
	actionValue := reflect.ValueOf(policyAST.Action)

	if entitiesField := actionValue.FieldByName("Entities"); entitiesField.IsValid() && entitiesField.Kind() == reflect.Slice {
		actions := make([]string, entitiesField.Len())
		for i := 0; i < entitiesField.Len(); i++ {
			entityUID := entitiesField.Index(i).Interface().(types.EntityUID)
			actions[i] = fmt.Sprintf("%s::%q", entityUID.Type, entityUID.ID)
		}
		return &ActionConstraint{
			Actions: actions,
			IsAny:   len(actions) == 0,
		}
	}

	if entityField := actionValue.FieldByName("Entity"); entityField.IsValid() {
		entityUID := entityField.Interface().(types.EntityUID)
		return &ActionConstraint{
			Actions: []string{fmt.Sprintf("%s::%q", entityUID.Type, entityUID.ID)},
			IsAny:   false,
		}
	}

	return &ActionConstraint{IsAny: true}
}

func (p *CedarParser) extractResourceFromAST(policyAST *ast.Policy) *EntityConstraint {
	resourceValue := reflect.ValueOf(policyAST.Resource)

	if entityField := resourceValue.FieldByName("Entity"); entityField.IsValid() {
		entityUID := entityField.Interface().(types.EntityUID)
		return &EntityConstraint{
			Type: string(entityUID.Type),
			ID:   string(entityUID.ID),
		}
	}

	if typeField := resourceValue.FieldByName("Type"); typeField.IsValid() {
		entityType := typeField.Interface().(types.EntityType)
		return &EntityConstraint{
			Type:   string(entityType),
			IsLike: true,
		}
	}

	if entitiesField := resourceValue.FieldByName("Entities"); entitiesField.IsValid() && entitiesField.Kind() == reflect.Slice {
		if entitiesField.Len() > 0 {
			list := make([]string, 0, entitiesField.Len())
			for i := 0; i < entitiesField.Len(); i++ {
				entityUID := entitiesField.Index(i).Interface().(types.EntityUID)
				list = append(list, fmt.Sprintf("%s::%q", entityUID.Type, entityUID.ID))
			}
			return &EntityConstraint{InSet: list}
		}
	}

	return &EntityConstraint{IsAny: true}
}

func (p *CedarParser) extractConditionsFromAST(policyAST *ast.Policy) []Condition {
	conditions := make([]Condition, 0)
	conditionsValue := reflect.ValueOf(policyAST.Conditions)
	if conditionsValue.IsValid() && conditionsValue.Kind() == reflect.Slice {
		for i := 0; i < conditionsValue.Len(); i++ {
			conditionType := conditionsValue.Index(i)
			conditionField := conditionType.FieldByName("Condition")
			bodyField := conditionType.FieldByName("Body")
			if conditionField.IsValid() && bodyField.IsValid() {
				isWhen := conditionField.Bool()
				kind := "when"
				if !isWhen {
					kind = "unless"
				}
				bodyInterface := bodyField.Interface()
				// Flatten AND expressions to leaves for easier matching
				leaves := p.flattenANDBodies(bodyInterface)
				if len(leaves) == 0 {
					leaves = []reflect.Value{reflect.ValueOf(bodyInterface)}
				}
				for _, leaf := range leaves {
					ci := leaf.Interface()
					// Prefer explicit equals extractions for http.rewrite context keys
					hv := p.extractContextEqualsConditions(ci, []string{"header", "value"}, kind)
					if len(hv) > 0 {
						conditions = append(conditions, hv...)
						continue
					}
					condition := p.parseConditionExpression(ci, kind)
					conditions = append(conditions, condition)
				}
			}
		}
	}
	return conditions
}

// flattenANDBodies returns a flat slice of immediate subexpressions joined by logical AND
func (p *CedarParser) flattenANDBodies(body interface{}) []reflect.Value {
	v := reflect.ValueOf(body)
	v = derefValue(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	if opField := v.FieldByName("Op"); opField.IsValid() {
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", opField.Interface())), "and") {
			left := derefValue(v.FieldByName("Left"))
			right := derefValue(v.FieldByName("Right"))
			var out []reflect.Value
			if l := p.flattenANDBodies(left.Interface()); len(l) > 0 {
				out = append(out, l...)
			} else if left.IsValid() {
				out = append(out, left)
			}
			if r := p.flattenANDBodies(right.Interface()); len(r) > 0 {
				out = append(out, r...)
			} else if right.IsValid() {
				out = append(out, right)
			}
			return out
		}
	}
	return nil
}

// extractContextEqualsConditions pulls simple equals on context.<keys> into structured conditions
func (p *CedarParser) extractContextEqualsConditions(body interface{}, keys []string, kind string) []Condition {
	v := reflect.ValueOf(body)
	v = derefValue(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	left := derefValue(v.FieldByName("Left"))
	right := derefValue(v.FieldByName("Right"))
	if !left.IsValid() || !right.IsValid() {
		return nil
	}
	key := p.extractContextKey(left.Interface())
	keyLower := strings.ToLower(strings.TrimSpace(key))
	wanted := false
	for _, k := range keys {
		if keyLower == k {
			wanted = true
			break
		}
	}
	if !wanted {
		return nil
	}
	val := p.extractStringValue(right.Interface())
	if val == "" {
		return nil
	}
	return []Condition{{Type: ConditionContextEquals, Kind: kind, ContextKey: keyLower, ContextValue: val}}
}

func (p *CedarParser) parseConditionExpression(bodyInterface interface{}, kind string) Condition {
	condition := Condition{
		Type:      ConditionUnknown,
		Kind:      kind,
		Variables: make(map[string]interface{}),
	}

	bodyValue := reflect.ValueOf(bodyInterface)
	if !bodyValue.IsValid() {
		condition.Variables["invalid_body"] = true
		return condition
	}

	if bodyValue.Kind() == reflect.Interface {
		bodyValue = bodyValue.Elem()
		if !bodyValue.IsValid() {
			condition.Variables["invalid_after_elem"] = true
			return condition
		}
	}

	bodyTypeName := bodyValue.Type().String()

	switch {
	case strings.Contains(bodyTypeName, "In"):
		condition = p.parseInExpression(bodyValue, kind)
	case strings.Contains(bodyTypeName, "NodeTypeLike"):
		condition = p.parseLikeExpression(bodyValue, kind)
	case strings.Contains(bodyTypeName, "NodeTypeEquals"):
		condition = p.parseEqualsExpression(bodyValue, kind)
	case strings.Contains(bodyTypeName, "Like"):
		condition = p.parseBinaryExpression(bodyValue, kind)
	case strings.Contains(bodyTypeName, "Binary"):
		condition = p.parseBinaryExpression(bodyValue, kind)
	case strings.Contains(bodyTypeName, "GetAttr"):
		condition = p.parseAttributeAccess(bodyValue, kind)
	default:
		condition.Expression = fmt.Sprintf("%+v", bodyInterface)
	}

	return condition
}

func (p *CedarParser) parseInExpression(bodyValue reflect.Value, kind string) Condition {
	condition := Condition{
		Type:      ConditionResourceIn,
		Kind:      kind,
		Variables: make(map[string]interface{}),
	}

	condition.Variables["ast_type"] = bodyValue.Type().String()

	resourceSet := make([]string, 0)

	if binaryNodeField := bodyValue.FieldByName("BinaryNode"); binaryNodeField.IsValid() {
		if binaryNodeField.Kind() == reflect.Interface {
			binaryNodeField = binaryNodeField.Elem()
		}
		if binaryNodeField.IsValid() && binaryNodeField.Kind() == reflect.Struct {
			if rightField := binaryNodeField.FieldByName("Right"); rightField.IsValid() {
				if rightField.Kind() == reflect.Interface {
					rightField = rightField.Elem()
				}
				if rightField.IsValid() {
					if rightField.Kind() == reflect.Slice {
						resourceSet = p.extractEntitySet(rightField)
					} else if rightField.Kind() == reflect.Struct {
						if entitiesField := rightField.FieldByName("Entities"); entitiesField.IsValid() && entitiesField.Kind() == reflect.Slice {
							resourceSet = p.extractEntitySet(entitiesField)
						} else if setField := rightField.FieldByName("Set"); setField.IsValid() && setField.Kind() == reflect.Slice {
							resourceSet = p.extractEntitySet(setField)
						} else if elementsField := rightField.FieldByName("Elements"); elementsField.IsValid() && elementsField.Kind() == reflect.Slice {
							resourceSet = p.extractEntitySet(elementsField)
						}
					}
				}
			}
		}
	}

	if len(resourceSet) == 0 {
		if entitiesField := bodyValue.FieldByName("Entities"); entitiesField.IsValid() && entitiesField.Kind() == reflect.Slice {
			resourceSet = p.extractEntitySet(entitiesField)
		}
	}

	condition.ResourceSet = resourceSet
	condition.Variables["resource_count"] = len(resourceSet)

	return condition
}

func (p *CedarParser) parseEqualsExpression(bodyValue reflect.Value, kind string) Condition {
	condition := Condition{
		Type:      ConditionContextEquals,
		Kind:      kind,
		Variables: make(map[string]interface{}),
	}

	condition.Operator = "=="

	if leftField := bodyValue.FieldByName("Left"); leftField.IsValid() {
		if leftField.Kind() == reflect.Interface {
			leftField = leftField.Elem()
		}

		leftStr := fmt.Sprintf("%+v", leftField.Interface())
		contextKey := p.extractContextKeyFromString(leftStr)
		if contextKey != "" {
			condition.ContextKey = contextKey
		}
	}

	if rightField := bodyValue.FieldByName("Right"); rightField.IsValid() {
		if rightField.Kind() == reflect.Interface {
			rightField = rightField.Elem()
		}

		value := p.extractStringValue(rightField.Interface())
		if value != "" {
			condition.ContextValue = value
		}
	}

	return condition
}

func (p *CedarParser) parseLikeExpression(bodyValue reflect.Value, kind string) Condition {
	condition := Condition{
		Type:      ConditionContextLike,
		Kind:      kind,
		Variables: make(map[string]interface{}),
	}

	condition.Operator = "like"

	if argField := bodyValue.FieldByName("Arg"); argField.IsValid() {
		if argField.Kind() == reflect.Interface {
			argField = argField.Elem()
		}

		argStr := fmt.Sprintf("%+v", argField.Interface())
		contextKey := p.extractContextKeyFromString(argStr)
		if contextKey != "" {
			condition.ContextKey = contextKey
		}
	}

	if valueField := bodyValue.FieldByName("Value"); valueField.IsValid() {
		pattern := p.extractPatternFromValue(valueField.Interface())
		if pattern != "" {
			condition.Pattern = pattern
		}
	}

	return condition
}

func (p *CedarParser) extractContextKeyFromString(str string) string {
	re := regexp.MustCompile(`Arg:\{Name:context\}.*?Value:(\w+)`)
	matches := re.FindStringSubmatch(str)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func (p *CedarParser) extractPatternFromValue(value interface{}) string {
	str := fmt.Sprintf("%+v", value)

	re := regexp.MustCompile(`Wildcard:true.*?Literal:([^\}]+)`)
	matches := re.FindAllStringSubmatch(str, -1)

	if len(matches) > 0 {
		var parts []string
		for _, match := range matches {
			parts = append(parts, "*")
			if len(match) > 1 {
				parts = append(parts, strings.TrimSpace(match[1]))
			}
		}
		return strings.Join(parts, "")
	}

	re2 := regexp.MustCompile(`Literal:([^\}]+)`)
	matches2 := re2.FindAllStringSubmatch(str, -1)
	if len(matches2) > 0 {
		var parts []string
		for _, match := range matches2 {
			if len(match) > 1 {
				parts = append(parts, strings.TrimSpace(match[1]))
			}
		}
		return strings.Join(parts, "")
	}

	return ""
}

func (p *CedarParser) parseBinaryExpression(bodyValue reflect.Value, kind string) Condition {
	condition := Condition{
		Type:      ConditionBinaryOp,
		Kind:      kind,
		Variables: make(map[string]interface{}),
	}

	if opField := bodyValue.FieldByName("Op"); opField.IsValid() {
		opStr := strings.ToLower(fmt.Sprintf("%v", opField.Interface()))
		condition.Operator = opStr
	}

	if leftField := bodyValue.FieldByName("Left"); leftField.IsValid() {
		leftValue := leftField.Interface()
		leftStr := fmt.Sprintf("%+v", leftValue)
		contextKey := p.extractContextKeyFromString(leftStr)

		if contextKey != "" {
			condition.ContextKey = contextKey
			switch {
			case condition.Operator == "==" || strings.Contains(condition.Operator, "eq"):
				condition.Type = ConditionContextEquals
			case strings.Contains(condition.Operator, "like"):
				condition.Type = ConditionContextLike
			}
		}
	}

	if rightField := bodyValue.FieldByName("Right"); rightField.IsValid() {
		rightValue := rightField.Interface()

		strValue := p.extractStringValue(rightValue)
		if strValue != "" {
			if condition.Type == ConditionContextEquals {
				condition.ContextValue = strValue
			} else if condition.Type == ConditionContextLike {
				condition.Pattern = strValue
			}
		}
	}

	return condition
}

func (p *CedarParser) parseAttributeAccess(bodyValue reflect.Value, kind string) Condition {
	condition := Condition{
		Type:      ConditionMemberAccess,
		Kind:      kind,
		Variables: make(map[string]interface{}),
	}

	if contextKey := p.extractContextKey(bodyValue.Interface()); contextKey != "" {
		condition.ContextKey = contextKey
	}

	condition.Expression = fmt.Sprintf("%+v", bodyValue.Interface())
	return condition
}

func (p *CedarParser) extractContextKey(value interface{}) string {
	valueReflect := reflect.ValueOf(value)
	if !valueReflect.IsValid() {
		return ""
	}

	if valueReflect.Kind() == reflect.Interface {
		valueReflect = valueReflect.Elem()
		if !valueReflect.IsValid() {
			return ""
		}
	}

	if attrField := valueReflect.FieldByName("Attr"); attrField.IsValid() {
		attrStr := fmt.Sprintf("%v", attrField.Interface())
		return attrStr
	}

	if valueReflect.Kind() == reflect.Struct {
		targetField := valueReflect.FieldByName("Target")
		if targetField.IsValid() {
			if targetField.Kind() == reflect.Interface {
				targetField = targetField.Elem()
			}
			if targetField.Kind() == reflect.Struct {
				if attrField := targetField.FieldByName("Attr"); attrField.IsValid() {
					return fmt.Sprintf("%v", attrField.Interface())
				}
			}
		}

		objectField := valueReflect.FieldByName("Object")
		if objectField.IsValid() {
			if objectField.Kind() == reflect.Interface {
				objectField = objectField.Elem()
			}
			if objectField.Kind() == reflect.Struct {
				if varField := objectField.FieldByName("Name"); varField.IsValid() {
					varName := fmt.Sprintf("%v", varField.Interface())
					if varName == "context" {
						if attrField := valueReflect.FieldByName("Attr"); attrField.IsValid() {
							return fmt.Sprintf("%v", attrField.Interface())
						}
					}
				}
			}
		}
	}

	return ""
}

func (p *CedarParser) extractStringValue(value interface{}) string {
	str := fmt.Sprintf("%+v", value)

	re := regexp.MustCompile(`Value:([^}\s]+)`)
	matches := re.FindStringSubmatch(str)
	if len(matches) > 1 {
		return strings.Trim(matches[1], `"`)
	}

	if directStr, ok := value.(string); ok {
		return directStr
	}

	return ""
}

func (p *CedarParser) extractEntitySet(entitiesField reflect.Value) []string {
	resourceSet := make([]string, 0)

	for i := 0; i < entitiesField.Len(); i++ {
		entityValue := entitiesField.Index(i)

		if entityValue.Kind() == reflect.Interface {
			entityValue = entityValue.Elem()
		}

		if entityUID, ok := entityValue.Interface().(types.EntityUID); ok {
			resourceSet = append(resourceSet, fmt.Sprintf("%s::%q", entityUID.Type, entityUID.ID))
			continue
		}

		if entityValue.Kind() == reflect.Struct {
			if uidField := entityValue.FieldByName("EntityUID"); uidField.IsValid() {
				if entityUID, ok := uidField.Interface().(types.EntityUID); ok {
					resourceSet = append(resourceSet, fmt.Sprintf("%s::%q", entityUID.Type, entityUID.ID))
					continue
				}
			}

			if entityField := entityValue.FieldByName("Entity"); entityField.IsValid() {
				if entityUID, ok := entityField.Interface().(types.EntityUID); ok {
					resourceSet = append(resourceSet, fmt.Sprintf("%s::%q", entityUID.Type, entityUID.ID))
					continue
				}
			}

			typeField := entityValue.FieldByName("Type")
			idField := entityValue.FieldByName("ID")
			if typeField.IsValid() && idField.IsValid() {
				entityType := fmt.Sprintf("%v", typeField.Interface())
				entityID := fmt.Sprintf("%v", idField.Interface())
				resourceSet = append(resourceSet, fmt.Sprintf("%s::%q", entityType, entityID))
				continue
			}
		}

		entityStr := fmt.Sprintf("%v", entityValue.Interface())
		if parsed := p.parseEntityString(entityStr); parsed != "" {
			resourceSet = append(resourceSet, parsed)
			continue
		}

		resourceSet = append(resourceSet, fmt.Sprintf("unknown::%v", entityValue.Interface()))
	}

	return resourceSet
}

func (p *CedarParser) parseEntityString(entityStr string) string {
	entityStr = strings.Trim(entityStr, "{}")

	if strings.Contains(entityStr, "::") {
		parts := strings.SplitN(entityStr, "::", 2)
		if len(parts) == 2 {
			entityType := strings.TrimSpace(parts[0])
			entityID := strings.TrimSpace(parts[1])
			entityID = strings.Trim(entityID, `"`)
			return fmt.Sprintf("%s::%q", entityType, entityID)
		}
	}

	return ""
}

type CedarPolicySet struct {
	Policies        []CedarPolicy
	NativePolicySet *cedarlib.PolicySet
}

type CedarPolicy struct {
	ID           string
	Effect       Effect
	Principal    EntityConstraint
	Action       ActionConstraint
	Resource     EntityConstraint
	Conditions   []Condition
	Annotations  map[string]string
	NativePolicy *cedarlib.Policy
}

type Effect int

const (
	Permit Effect = iota
	Forbid
)

type EntityConstraint struct {
	Type   string
	ID     string
	IsAny  bool
	InSet  []string
	IsLike bool
}

type ActionConstraint struct {
	Actions []string
	IsAny   bool
	InSet   []string
}

type ConditionType int

const (
	ConditionUnknown ConditionType = iota
	ConditionResourceIn
	ConditionContextEquals
	ConditionContextLike
	ConditionBinaryOp
	ConditionUnaryOp
	ConditionMemberAccess
)

type Condition struct {
	Type         ConditionType
	Kind         string
	Expression   string
	Variables    map[string]interface{}
	ResourceSet  []string
	ContextKey   string
	ContextValue interface{}
	Pattern      string
	Operator     string
	Operands     []interface{}
}

// derefValue unwraps interface and pointer indirections to yield the underlying value
func derefValue(v reflect.Value) reflect.Value {
	for v.IsValid() {
		if v.Kind() == reflect.Interface || v.Kind() == reflect.Ptr {
			v = v.Elem()
			continue
		}
		break
	}
	return v
}
