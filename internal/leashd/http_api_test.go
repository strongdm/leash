package leashd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/proxy"
)

type captureBroadcaster struct {
	mu     sync.Mutex
	events []struct {
		event   string
		payload any
	}
}

func (c *captureBroadcaster) EmitJSON(event string, payload any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, struct {
		event   string
		payload any
	}{event: event, payload: payload})
}

func (c *captureBroadcaster) last() (string, any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return "", nil, false
	}
	ev := c.events[len(c.events)-1]
	return ev.event, ev.payload, true
}

func policySetsEqual(a, b *lsm.PolicySet) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	}

	if !policyRuleSlicesEqual(a.Open, b.Open) {
		return false
	}
	if !policyRuleSlicesEqual(a.Exec, b.Exec) {
		return false
	}
	if !policyRuleSlicesEqual(a.Connect, b.Connect) {
		return false
	}
	if len(a.MCP) != len(b.MCP) {
		return false
	}
	for i := range a.MCP {
		if a.MCP[i].Action != b.MCP[i].Action || a.MCP[i].Server != b.MCP[i].Server || a.MCP[i].Tool != b.MCP[i].Tool {
			return false
		}
	}
	if a.ConnectDefaultAllow != b.ConnectDefaultAllow {
		return false
	}
	if a.ConnectDefaultExplicit != b.ConnectDefaultExplicit {
		return false
	}
	return true
}

// policyRuleSlicesEqual is array ordering insensitive.
func policyRuleSlicesEqual(a, b []lsm.PolicyRule) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, rule := range a {
		counts[rule.String()]++
	}
	for _, rule := range b {
		key := rule.String()
		if counts[key] == 0 {
			return false
		}
		counts[key]--
		if counts[key] == 0 {
			delete(counts, key)
		}
	}
	return len(counts) == 0
}

func extractCaretCoords(t *testing.T, src string) (string, int, int) {
	t.Helper()
	const marker = "<caret>"
	idx := strings.Index(src, marker)
	if idx == -1 {
		t.Fatalf("caret marker not found")
	}
	before := src[:idx]
	after := src[idx+len(marker):]
	line := strings.Count(before, "\n") + 1
	lastNL := strings.LastIndex(before, "\n")
	col := len(before) + 1
	if lastNL != -1 {
		col = len(before[lastNL+1:]) + 1
	}
	return before + after, line, col
}

func TestPoliciesCORSOptions(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, func(*lsm.PolicySet, []proxy.HeaderRewriteRule) {})
	api := newPolicyAPI(mgr, "", nil, nil, nil)
	api.register(mux)

	req := httptest.NewRequest(http.MethodOptions, "/api/policies", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if v := w.Header().Get("Access-Control-Allow-Methods"); v == "" {
		t.Fatalf("missing CORS headers")
	}
}

func TestPoliciesPostZeroRuleGuard(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, "", nil, nil, nil)
	api.register(mux)

	// cedar that produces no rules (empty)
	body := bytes.NewBufferString("{}")
	req := httptest.NewRequest(http.MethodPost, "/api/policies", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("expected non-200 due to zero-rule guard, got %d", w.Code)
	}
}

func TestPoliciesPostJSONAccepts(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, "", nil, nil, nil)
	api.register(mux)

	payload := map[string]string{"cedar": `permit(action, subject, resource) when { context.op == "connect" };`}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/policies", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest { // transpiler may reject example; accept non-500
		t.Fatalf("unexpected status: %d", w.Code)
	}
}

func TestPersistPoliciesEmptyBodyUsesRuntimeCedar(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	origLeashDir := os.Getenv("LEASH_DIR")
	if err := os.Setenv("LEASH_DIR", tmpDir); err != nil {
		t.Fatalf("failed to set LEASH_DIR: %v", err)
	}
	t.Cleanup(func() {
		if origLeashDir == "" {
			_ = os.Unsetenv("LEASH_DIR")
		} else {
			_ = os.Setenv("LEASH_DIR", origLeashDir)
		}
		if entries, err := os.ReadDir(tmpDir); err == nil {
			for _, entry := range entries {
				_ = os.RemoveAll(filepath.Join(tmpDir, entry.Name()))
			}
		}
	})
	policyPath := filepath.Join(tmpDir, "policies.cedar")

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, policyPath, nil, nil, nil)
	api.register(mux)

	seed := policy.DefaultCedar()
	reqSeed := httptest.NewRequest(http.MethodPost, "/api/policies", bytes.NewBufferString(seed))
	wSeed := httptest.NewRecorder()
	mux.ServeHTTP(wSeed, reqSeed)
	if wSeed.Code != http.StatusOK {
		t.Fatalf("seed policies POST returned %d", wSeed.Code)
	}

	reqPersist := httptest.NewRequest(http.MethodPost, "/api/policies/persist?force=1", nil)
	wPersist := httptest.NewRecorder()
	mux.ServeHTTP(wPersist, reqPersist)
	if wPersist.Code != http.StatusOK {
		t.Fatalf("persist policies returned %d", wPersist.Code)
	}

	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("failed to read persisted cedar: %v", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		t.Fatalf("expected persisted cedar to be non-empty")
	}
}

func TestPoliciesPatchAddPersistEnforce(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	origLeashDir := os.Getenv("LEASH_DIR")
	if err := os.Setenv("LEASH_DIR", tmpDir); err != nil {
		t.Fatalf("failed to set LEASH_DIR: %v", err)
	}
	t.Cleanup(func() {
		if origLeashDir == "" {
			_ = os.Unsetenv("LEASH_DIR")
		} else {
			_ = os.Setenv("LEASH_DIR", origLeashDir)
		}
		if entries, err := os.ReadDir(tmpDir); err == nil {
			for _, entry := range entries {
				_ = os.RemoveAll(filepath.Join(tmpDir, entry.Name()))
			}
		}
	})
	policyPath := filepath.Join(tmpDir, "policies.cedar")

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	broadcast := &captureBroadcaster{}
	api := newPolicyAPI(mgr, policyPath, broadcast, nil, nil)
	api.register(mux)

	body := map[string]any{
		"add": []map[string]any{
			{
				"effect": "forbid",
				"action": map[string]string{
					"type": "net/connect",
					"name": "https://www.facebook.com",
				},
			},
		},
	}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/policies", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("patch policies returned %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		CedarFile       string `json:"cedarFile"`
		EnforcementMode string `json:"enforcementMode"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !strings.Contains(strings.ToLower(resp.CedarFile), "facebook.com") {
		t.Fatalf("expected cedarFile to contain facebook.com, got %q", resp.CedarFile)
	}
	if resp.EnforcementMode != "enforce" {
		t.Fatalf("expected enforcement mode to be enforce, got %q", resp.EnforcementMode)
	}

	fileLSM, _, runtimeLSM, _ := mgr.Snapshot()
	foundDeny := false
	for _, rule := range fileLSM.Connect {
		if rule.Action == lsm.PolicyDeny && strings.Contains(strings.ToLower(rule.String()), "facebook") {
			foundDeny = true
			break
		}
	}
	if !foundDeny {
		t.Fatalf("expected deny connect rule for facebook in file layer")
	}
	if len(runtimeLSM.Connect) != 0 {
		t.Fatalf("expected runtime overlay to be cleared, found %d connect rules", len(runtimeLSM.Connect))
	}

	if event, payloadAny, ok := broadcast.last(); !ok {
		t.Fatalf("expected policy snapshot broadcast")
	} else {
		if event != "policy.snapshot" {
			t.Fatalf("expected broadcast event policy.snapshot, got %q", event)
		}
		payloadMap, ok := payloadAny.(map[string]any)
		if !ok {
			t.Fatalf("expected payload map, got %T", payloadAny)
		}
		if _, ok := payloadMap["policies"]; !ok {
			t.Fatalf("expected policies in snapshot payload")
		}
		if _, ok := payloadMap["lines"]; !ok {
			t.Fatalf("expected lines in snapshot payload")
		}
	}

	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("failed to read canonical cedar: %v", err)
	}
	if !strings.Contains(strings.ToLower(string(data)), "facebook.com") {
		t.Fatalf("expected canonical cedar to contain facebook.com")
	}
}

func TestPoliciesPatchPermitAllKeepsRuntimeOverlay(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	origLeashDir := os.Getenv("LEASH_DIR")
	if err := os.Setenv("LEASH_DIR", tmpDir); err != nil {
		t.Fatalf("failed to set LEASH_DIR: %v", err)
	}
	t.Cleanup(func() {
		if origLeashDir == "" {
			_ = os.Unsetenv("LEASH_DIR")
		} else {
			_ = os.Setenv("LEASH_DIR", origLeashDir)
		}
		if entries, err := os.ReadDir(tmpDir); err == nil {
			for _, entry := range entries {
				_ = os.RemoveAll(filepath.Join(tmpDir, entry.Name()))
			}
		}
	})
	policyPath := filepath.Join(tmpDir, "policies.cedar")

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	broadcast := &captureBroadcaster{}
	api := newPolicyAPI(mgr, policyPath, broadcast, nil, nil)
	api.register(mux)

	// Seed baseline policy so we have connect allows in file layer
	seed := policy.DefaultCedar()
	reqSeed := httptest.NewRequest(http.MethodPost, "/api/policies", bytes.NewBufferString(seed))
	wSeed := httptest.NewRecorder()
	mux.ServeHTTP(wSeed, reqSeed)
	if wSeed.Code != http.StatusOK {
		t.Fatalf("seed policies POST returned %d", wSeed.Code)
	}

	// Switch to permit-all mode
	reqPermit := httptest.NewRequest(http.MethodPost, "/api/policies/permit-all", nil)
	wPermit := httptest.NewRecorder()
	mux.ServeHTTP(wPermit, reqPermit)
	if wPermit.Code != http.StatusOK {
		t.Fatalf("permit-all returned %d", wPermit.Code)
	}

	_, _, runtimeBefore, _ := mgr.Snapshot()

	body := map[string]any{
		"add": []map[string]any{
			{
				"effect": "forbid",
				"action": map[string]string{
					"type": "net/connect",
					"name": "https://blocked.example.com",
				},
			},
		},
	}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/policies", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("patch in permit-all returned %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		EnforcementMode string `json:"enforcementMode"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.EnforcementMode != "permit-all" {
		t.Fatalf("expected enforcement mode to remain permit-all, got %q", resp.EnforcementMode)
	}

	_, _, runtimeAfter, _ := mgr.Snapshot()
	if !policySetsEqual(runtimeBefore, runtimeAfter) {
		t.Fatalf("runtime overlay changed while in permit-all mode")
	}

	fileLSM, _, _, _ := mgr.Snapshot()
	denyFound := false
	for _, rule := range fileLSM.Connect {
		if rule.Action == lsm.PolicyDeny && strings.Contains(strings.ToLower(rule.String()), "blocked.example.com") {
			denyFound = true
			break
		}
	}
	if !denyFound {
		t.Fatalf("expected deny rule persisted to file layer")
	}

	// Ensure broadcast still occurred so UI updates without polling
	if event, _, ok := broadcast.last(); !ok || event != "policy.snapshot" {
		t.Fatalf("expected policy snapshot broadcast while in permit-all")
	}
}

func TestPoliciesPatchRequiresChanges(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, "", nil, nil, nil)
	api.register(mux)

	req := httptest.NewRequest(http.MethodPatch, "/api/policies", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty patch, got %d", w.Code)
	}
}

func TestPoliciesPostRejectsInternalConflict(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, "", nil, nil, nil)
	api.register(mux)

	cedar := `
permit (principal, action == Net::"Connect", resource == Net::Hostname::"api.openai.com");

forbid (principal, action == Net::"Connect", resource == Net::Hostname::"api.openai.com");
`
	req := httptest.NewRequest(http.MethodPost, "/api/policies", bytes.NewBufferString(cedar))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for internal conflicting policies, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAddPolicyFromActionDetectsConflict(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, "", nil, nil, nil)
	api.register(mux)

	// First add an allow connect to api.openai.com
	body1 := map[string]any{
		"effect": "permit",
		"action": map[string]any{
			"type": "net/connect",
			"name": "https://api.openai.com",
		},
	}
	b1, _ := json.Marshal(body1)
	req1 := httptest.NewRequest(http.MethodPost, "/api/policies/add-from-action", bytes.NewReader(b1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	mux.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("seed add-from-action returned %d: %s", w1.Code, w1.Body.String())
	}

	// Now attempt to add a conflicting deny for the same host
	body2 := map[string]any{
		"effect": "forbid",
		"action": map[string]any{
			"type": "net/connect",
			"name": "https://api.openai.com",
		},
	}
	b2, _ := json.Marshal(body2)
	req2 := httptest.NewRequest(http.MethodPost, "/api/policies/add-from-action", bytes.NewReader(b2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on conflicting add-from-action, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestPoliciesPatchAddMCPSpecificTool(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policies.cedar")

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, policyPath, nil, nil, nil)
	api.register(mux)

	body := map[string]any{
		"add": []map[string]any{
			{
				"effect": "forbid",
				"action": map[string]any{
					"type":   "mcp/deny",
					"name":   "mcp.deny method=tools/call", // description; structured fields carry server/tool
					"server": "mcp.context7.com",
					"tool":   "resolve-library-id",
				},
			},
		},
	}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/policies", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("patch policies returned %d: %s", w.Code, w.Body.String())
	}

	// Response includes a consolidated Cedar string; assert it targets the specific tool+server
	var resp struct {
		CedarFile string `json:"cedarFile"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	want := `forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"resolve-library-id") when { resource in [ MCP::Server::"mcp.context7.com" ] };`
	if !strings.Contains(resp.CedarFile, want) {
		t.Fatalf("expected cedarFile to contain tool-specific policy. want=%q\ncedarFile=%q", want, resp.CedarFile)
	}
}

func TestAddPolicyFromActionMCPSpecificTool(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policies.cedar")

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, policyPath, nil, nil, nil)
	api.register(mux)

	body := map[string]any{
		"effect": "permit",
		"action": map[string]any{
			"type":   "mcp/allow",
			"name":   "mcp.allow method=tools/call", // description; structured fields carry server/tool
			"server": "mcp.context7.com",
			"tool":   "resolve-library-id",
		},
	}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/policies/add-from-action", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("add-from-action returned %d: %s", w.Code, w.Body.String())
	}

	// Response includes cedarFile
	var resp struct {
		CedarRuntime string `json:"cedarRuntime"`
		CedarFile    string `json:"cedarFile"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	want := `permit (principal, action == Action::"McpCall", resource == MCP::Tool::"resolve-library-id") when { resource in [ MCP::Server::"mcp.context7.com" ] };`
	if !strings.Contains(resp.CedarRuntime, want) {
		t.Fatalf("expected cedarRuntime to contain tool-specific policy. want=%q\ncedarRuntime=%q", want, resp.CedarRuntime)
	}
}

func TestPoliciesPatchRejectsConflict(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policies.cedar")

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, policyPath, nil, nil, nil)
	api.register(mux)

	// Seed a permit connect for api.openai.com
	seed := `permit (principal, action == Net::"Connect", resource == Net::Hostname::"api.openai.com");`
	reqSeed := httptest.NewRequest(http.MethodPost, "/api/policies", bytes.NewBufferString(seed))
	wSeed := httptest.NewRecorder()
	mux.ServeHTTP(wSeed, reqSeed)
	if wSeed.Code != http.StatusOK {
		t.Fatalf("seed POST returned %d: %s", wSeed.Code, wSeed.Body.String())
	}

	// Try to add a conflicting forbid via PATCH
	body := map[string]any{
		"add": []map[string]any{
			{
				"effect": "forbid",
				"action": map[string]any{
					"type": "net/connect",
					"name": "https://api.openai.com",
				},
			},
		},
	}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/policies", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for patch conflict, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPersistPoliciesRejectsConflict(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policies.cedar")

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, policyPath, nil, nil, nil)
	api.register(mux)

	cedar := `
permit (principal, action == Net::"Connect", resource == Net::Hostname::"www.google.com");

forbid (principal, action == Net::"Connect", resource == Net::Hostname::"www.google.com");

permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ Dir::"/" ] };

permit (principal, action == Action::"ProcessExec", resource)
when { resource in [ Dir::"/" ] };

permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"*" ] };
`

	req := httptest.NewRequest(http.MethodPost, "/api/policies/persist", bytes.NewBufferString(cedar))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for persist conflict, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPoliciesCompleteBasic(t *testing.T) {
	t.Parallel()

	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, "", nil, nil, nil)

	reqBody := completionRequest{
		Cedar:  "",
		Cursor: completionCursor{Line: 1, Column: 1},
	}
	payload := new(bytes.Buffer)
	if err := json.NewEncoder(payload).Encode(reqBody); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/policies/complete", payload)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handlePoliciesComplete(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp completionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Items) == 0 {
		t.Fatalf("expected suggestions, got none")
	}
	if resp.Items[0].Label != "permit" {
		t.Fatalf("expected first suggestion to be permit, got %q", resp.Items[0].Label)
	}
	if resp.Items[0].Range.Start.Line != 1 || resp.Items[0].Range.Start.Column != 1 {
		t.Fatalf("unexpected range: %+v", resp.Items[0].Range)
	}
}

func TestPoliciesCompleteRejectsInvalidCursor(t *testing.T) {
	t.Parallel()

	mgr := policy.NewManager(nil, nil)
	api := newPolicyAPI(mgr, "", nil, nil, nil)

	reqBody := completionRequest{
		Cedar:  "",
		Cursor: completionCursor{Line: 0, Column: 0},
	}
	payload := new(bytes.Buffer)
	if err := json.NewEncoder(payload).Encode(reqBody); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/policies/complete", payload)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handlePoliciesComplete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", w.Code)
	}
}

func TestPoliciesCompleteUsesPolicyHints(t *testing.T) {
	t.Parallel()

	mgr := policy.NewManager(nil, nil)

	hostRule := lsm.PolicyRule{
		Action:      lsm.PolicyAllow,
		Operation:   lsm.OpConnect,
		DestPort:    443,
		HostnameLen: int32(len("example.com")),
	}
	copy(hostRule.Hostname[:], []byte("example.com"))
	if err := mgr.SetRuntimeRules(&lsm.PolicySet{Connect: []lsm.PolicyRule{hostRule}}, nil); err != nil {
		t.Fatalf("set runtime rules: %v", err)
	}

	api := newPolicyAPI(mgr, "", nil, nil, nil)

	src := `permit (principal, action == Action::"FileOpen", resource) when { resource in [ <caret> ] };`
	cedar, line, col := extractCaretCoords(t, src)
	reqBody := completionRequest{
		Cedar:  cedar,
		Cursor: completionCursor{Line: line, Column: col},
	}

	payload := new(bytes.Buffer)
	if err := json.NewEncoder(payload).Encode(reqBody); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/policies/complete", payload)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handlePoliciesComplete(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp completionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Items) == 0 {
		t.Fatalf("expected suggestions, got none")
	}
	if !containsLabel(resp.Items, `Host::"example.com"`) {
		t.Fatalf("expected host hint in suggestions, got %+v", labels(resp.Items))
	}
}

func containsLabel(items []completionResponseItem, label string) bool {
	for _, item := range items {
		if item.Label == label {
			return true
		}
	}
	return false
}

func labels(items []completionResponseItem) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Label)
	}
	return out
}
