//go:build darwin

package darwind

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/proxy"
	"github.com/strongdm/leash/internal/transpiler"
)

type policyBroadcaster interface {
	EmitJSON(event string, payload any)
}

// policyAPI implements GET/POST /api/policies and persists cedarRuntime.
// policyAPI serves policy CRUD and mode endpoints for the Control UI.
// It accepts Cedar from the client, compiles it into in-memory rule sets for the
// runtime/file layers, and persists Cedar for UX continuity and restarts.
type policyAPI struct {
	mgr          *policy.Manager
	cedarRuntime string
	cedarPrev    string
	mu           sync.RWMutex

	// policyPath is the canonical Cedar file persisted for the file layer.
	policyPath string

	// mode is a lightweight UI indicator for enforcement state. Values:
	//   - "enforce": runtime overlay cleared; file layer active
	//   - "permit-all": permissive runtime overlay loaded (does not alter file layer)
	mode        string
	broadcaster policyBroadcaster
}

func newPolicyAPI(mgr *policy.Manager, policyPath string, broadcaster policyBroadcaster) *policyAPI {
	api := &policyAPI{mgr: mgr, policyPath: policyPath, mode: "enforce", broadcaster: broadcaster}
	// Attempt to restore runtime Cedar on startup
	if b, err := loadCedarRuntime(); err == nil && len(b) > 0 {
		if comp, compErr := cedarutil.CompileString("cedar-runtime.cedar", string(b)); compErr == nil {
			if hasAnyRules(comp.Policies, comp.HTTPRules) {
				if err := api.mgr.SetRuntimeRules(comp.Policies, comp.HTTPRules); err != nil {
					if !softLSMError(err) {
						logPolicyEvent("policy.restore", map[string]any{"source": "runtime", "error": err.Error()})
					}
				} else {
					api.mu.Lock()
					api.cedarRuntime = string(b)
					api.mu.Unlock()
					logPolicyEvent("policy.restore", map[string]any{"source": "runtime"})
				}
			}
		} else if detail, ok := compErr.(*cedarutil.ErrorDetail); ok {
			logPolicyEvent("policy.restore", map[string]any{"source": "runtime", "error": detail.Message})
		}
	}
	// Determine whether a canonical Cedar file already exists with content. When present,
	// prefer that as the operator-authored source instead of seeding a permissive runtime overlay.
	canonicalHasCedar := false
	if path := strings.TrimSpace(policyPath); path != "" {
		if b, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(b)) > 0 {
			canonicalHasCedar = true
		}
	}

	// If nothing was restored and no canonical Cedar exists, seed runtime with the default baseline.
	if strings.TrimSpace(api.cedarRuntime) == "" && !canonicalHasCedar {
		if comp, err := cedarutil.CompileString("default.cedar", policy.DefaultCedar()); err == nil && hasAnyRules(comp.Policies, comp.HTTPRules) {
			if err := api.mgr.SetRuntimeRules(comp.Policies, comp.HTTPRules); err != nil {
				if !softLSMError(err) {
					logPolicyEvent("policy.restore", map[string]any{"error": err.Error(), "source": "baseline"})
				}
			} else {
				api.mu.Lock()
				api.cedarRuntime = policy.DefaultCedar()
				api.mu.Unlock()
				_ = saveCedarRuntime([]byte(api.cedarRuntime))
				logPolicyEvent("policy.restore", map[string]any{"source": "baseline"})
			}
		} else if detail, ok := err.(*cedarutil.ErrorDetail); ok {
			logPolicyEvent("policy.restore", map[string]any{"source": "baseline", "error": detail.Message})
		}
	}
	return api
}

func (api *policyAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("/api/policies", api.handlePolicies)
	mux.HandleFunc("/api/policies/persist", api.handlePersistPolicies)
	mux.HandleFunc("/api/policies/validate", api.handleValidatePolicies)
	mux.HandleFunc("/api/policies/permit-all", api.handlePermitAll)
	mux.HandleFunc("/api/policies/enforce-apply", api.handleEnforceApply)
	mux.HandleFunc("/api/policies/lines", api.handlePolicyLines)
	mux.HandleFunc("/api/policies/add", api.handleAddPolicy)
	mux.HandleFunc("/api/policies/add-from-action", api.handleAddPolicyFromAction)
	mux.HandleFunc("/api/policies/delete", api.handleDeletePolicy)
}

func (api *policyAPI) handlePolicies(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.Method {
	case http.MethodGet:
		api.handleGet(w, r)
	case http.MethodPost:
		api.handlePost(w, r)
	case http.MethodPatch:
		api.handlePatch(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *policyAPI) handleGet(w http.ResponseWriter, r *http.Request) {
	resp := api.buildPoliciesResponse()
	writeJSON(w, http.StatusOK, resp)
}

func (api *policyAPI) handlePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB
	cedar, err := extractCedar(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"message": err.Error()}})
		return
	}

	cedar = strings.TrimSpace(cedar)
	if cedar != "" {
		statements := extractCedarStatements(cedar)
		if len(statements) > 0 {
			statements = dedupeCedarStatements(statements)
			cedar = strings.TrimSpace(strings.Join(statements, "\n\n"))
		}
	}

	compilation, compErr := cedarutil.CompileString("runtime.cedar", cedar)
	if compErr != nil {
		if detail, ok := compErr.(*cedarutil.ErrorDetail); ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": cedarutil.BuildErrorResponse(detail)})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"message": compErr.Error()}})
		}
		return
	}
	if !hasAnyRules(compilation.Policies, compilation.HTTPRules) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"message": "no rules produced from Cedar"}})
		return
	}

	if err := api.mgr.SetRuntimeRules(compilation.Policies, compilation.HTTPRules); err != nil {
		if softLSMError(err) {
			logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]any{"message": err.Error()}})
			return
		}
	}

	// Persist cedarRuntime atomically; log but do not fail API on error
	if err := saveCedarRuntime([]byte(cedar)); err != nil {
		logPolicyEvent("policy.update", map[string]any{"error": err.Error(), "persist": "cedar-runtime"})
	}

	api.mu.Lock()
	api.cedarRuntime = cedar
	api.mu.Unlock()

	resp := api.buildPoliciesResponse()
	api.respondPolicies(w, resp)
}

type patchPoliciesRequest struct {
	Add       []patchPolicyAdd    `json:"add"`
	Remove    []patchPolicyRemove `json:"remove"`
	ApplyMode string              `json:"applyMode"`
}

type patchPolicyAdd struct {
	Cedar  string         `json:"cedar"`
	Effect string         `json:"effect"`
	Action *actionPayload `json:"action"`
}

type patchPolicyRemove struct {
	ID    string `json:"id"`
	Cedar string `json:"cedar"`
}

func (api *policyAPI) respondPolicies(w http.ResponseWriter, resp map[string]any) {
	writeJSON(w, http.StatusOK, resp)
	api.broadcastPolicySnapshot(resp)
}

func (api *policyAPI) broadcastPolicySnapshot(resp map[string]any) {
	if api.broadcaster == nil {
		return
	}

	payload := map[string]any{"policies": resp}
	if lines, err := renderPolicyLines(api.currentCedarSnapshot()); err == nil {
		payload["lines"] = lines
	} else {
		logPolicyEvent("policy.lines.snapshot.error", map[string]any{"error": err.Error()})
	}

	api.broadcaster.EmitJSON("policy.snapshot", payload)
}

func (api *policyAPI) handlePatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var payload patchPoliciesRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON payload"})
		return
	}

	addCount := len(payload.Add)
	removeCount := len(payload.Remove)
	if addCount == 0 && removeCount == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no changes provided"})
		return
	}

	applyMode := strings.ToLower(strings.TrimSpace(payload.ApplyMode))
	if applyMode != "" && applyMode != "enforce" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "applyMode must be \"enforce\" or omitted"})
		return
	}
	permitAllMode := strings.EqualFold(api.mode, "permit-all")
	if applyMode == "" && !permitAllMode && strings.EqualFold(api.mode, "enforce") {
		applyMode = "enforce"
	}

	existing := strings.TrimSpace(api.editableCedar())
	currentStatements := make([]string, 0)
	if existing != "" {
		currentStatements = append(currentStatements, extractCedarStatements(existing)...)
	}

	lines, err := renderPolicyLines(existing)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("failed to parse existing policies: %v", err)})
		return
	}

	idToStatement := make(map[string]string, len(lines))
	for _, line := range lines {
		idToStatement[strings.TrimSpace(line.ID)] = strings.TrimSpace(line.Cedar)
	}

	for _, rem := range payload.Remove {
		byID := strings.TrimSpace(rem.ID)
		target := strings.TrimSpace(rem.Cedar)
		if target == "" && byID != "" {
			if stmt, ok := idToStatement[byID]; ok {
				target = stmt
			} else {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": fmt.Sprintf("policy id %q not found", byID)})
				return
			}
		}
		if target == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "remove entries require id or cedar"})
			return
		}
		index := -1
		for i, stmt := range currentStatements {
			if strings.TrimSpace(stmt) == target {
				index = i
				break
			}
		}
		if index == -1 {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy to remove was not found"})
			return
		}
		currentStatements = append(currentStatements[:index], currentStatements[index+1:]...)
		for id, stmt := range idToStatement {
			if stmt == target {
				delete(idToStatement, id)
			}
		}
	}

	newStatements := make([]string, 0, addCount)
	for _, add := range payload.Add {
		cedar := strings.TrimSpace(add.Cedar)
		if cedar == "" && add.Action != nil {
			effect := strings.ToLower(strings.TrimSpace(add.Effect))
			if effect != "permit" && effect != "forbid" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "add entries with action require effect of permit or forbid"})
				return
			}
			c, err := buildCedarFromActionRequest(addPolicyFromActionRequest{
				Effect: effect,
				Action: *add.Action,
			})
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			cedar = c
		}
		if cedar == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "add entries require cedar or action"})
			return
		}
		cedar = strings.TrimSpace(cedar)
		if !strings.HasSuffix(cedar, ";") {
			cedar += ";"
		}
		newStatements = append(newStatements, cedar)
	}

	for i := len(newStatements) - 1; i >= 0; i-- {
		stmt := newStatements[i]
		duplicate := false
		for _, existingStmt := range currentStatements {
			if strings.TrimSpace(existingStmt) == strings.TrimSpace(stmt) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		currentStatements = append([]string{stmt}, currentStatements...)
	}

	if len(currentStatements) > 0 {
		currentStatements = dedupeCedarStatements(currentStatements)
	}

	if len(currentStatements) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "resulting policy set is empty"})
		return
	}

	updated := strings.TrimSpace(strings.Join(currentStatements, "\n\n"))

	if rep, err := transpiler.LintFromString(updated); err == nil && rep != nil {
		hasErr := false
		for _, it := range rep.Issues {
			if it.Severity == transpiler.LintError {
				hasErr = true
				break
			}
		}
		if hasErr {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "policy has lint errors; fix them before applying"})
			return
		}
	}

	compilePath := api.policyPath
	if strings.TrimSpace(compilePath) == "" {
		compilePath = "patch.cedar"
	}
	compilation, compErr := cedarutil.CompileString(compilePath, updated)
	if compErr != nil {
		if detail, ok := compErr.(*cedarutil.ErrorDetail); ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": cedarutil.BuildErrorResponse(detail)})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": compErr.Error()})
		}
		return
	}
	if !hasAnyRules(compilation.Policies, compilation.HTTPRules) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "transpile produced no rules; refusing to apply"})
		return
	}
	if err := ensureConnectSafety(compilation.Policies); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	if !permitAllMode {
		if err := api.mgr.SetRuntimeRules(compilation.Policies, compilation.HTTPRules); err != nil {
			if softLSMError(err) {
				logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
			} else {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
		}
	}

	if err := saveCedarRuntime([]byte(updated)); err != nil {
		logPolicyEvent("policy.patch", map[string]any{"error": err.Error(), "persist": "cedar-runtime"})
	}

	api.mu.Lock()
	if permitAllMode {
		api.cedarPrev = updated
	}
	api.cedarRuntime = updated
	api.mu.Unlock()

	prevFile, prevHTTP, _, _ := api.mgr.Snapshot()
	if err := api.mgr.UpdateFileRules(compilation.Policies, compilation.HTTPRules); err != nil {
		if softLSMError(err) {
			logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}

	persistPayload := updated
	if persistPayload != "" && !strings.HasSuffix(persistPayload, "\n") {
		persistPayload += "\n"
	}
	if err := api.saveCanonicalCedar([]byte(persistPayload)); err != nil {
		_ = api.mgr.UpdateFileRules(prevFile, prevHTTP)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("failed to persist Cedar: %v", err)})
		return
	}

	if applyMode == "enforce" {
		_ = api.mgr.SetRuntimeOnly(false)
		if err := api.mgr.SetRuntimeRules(&lsm.PolicySet{}, nil); err != nil {
			if softLSMError(err) {
				logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
			} else {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
		}
		api.mode = "enforce"
		api.mu.Lock()
		api.cedarPrev = ""
		api.cedarRuntime = updated
		api.mu.Unlock()
	}

	logPolicyEvent("policy.patch", map[string]any{
		"add":       addCount,
		"remove":    removeCount,
		"applyMode": applyMode,
	})

	resp := api.buildPoliciesResponse()
	api.respondPolicies(w, resp)
}

// handlePersistPolicies promotes Cedar to the file layer and writes the canonical
// Cedar source to disk. If no Cedar is provided, the current runtime Cedar is used.
// Lints with severity=error are rejected unless force=1 is provided.
func (api *policyAPI) handlePersistPolicies(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	cedar, err := extractCedar(r)
	if err != nil {
		if strings.EqualFold(err.Error(), "empty body") {
			cedar = ""
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	cedar = strings.TrimSpace(cedar)
	if cedar == "" {
		api.mu.RLock()
		cedar = api.cedarRuntime
		api.mu.RUnlock()
		if strings.TrimSpace(cedar) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no Cedar available to persist"})
			return
		}
	}

	if cedar != "" {
		statements := extractCedarStatements(cedar)
		if len(statements) > 0 {
			statements = dedupeCedarStatements(statements)
			cedar = strings.TrimSpace(strings.Join(statements, "\n\n"))
		}
	}

	// Lint and optionally block on errors unless force=1
	force := strings.EqualFold(r.URL.Query().Get("force"), "1") || strings.EqualFold(r.URL.Query().Get("force"), "true")
	if rep, err := transpiler.LintFromString(cedar); err == nil && rep != nil {
		hasErr := false
		for _, it := range rep.Issues {
			if it.Severity == transpiler.LintError {
				hasErr = true
				break
			}
		}
		if hasErr && !force {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "policy has lint errors; fix them or add ?force=1"})
			return
		}
	}

	compilation, compErr := cedarutil.CompileString(api.policyPath, cedar)
	if compErr != nil {
		if detail, ok := compErr.(*cedarutil.ErrorDetail); ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": cedarutil.BuildErrorResponse(detail)})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": compErr.Error()})
		}
		return
	}
	if !hasAnyRules(compilation.Policies, compilation.HTTPRules) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "transpile produced no rules; refusing to persist"})
		return
	}

	if !force {
		if err := ensureConnectSafety(compilation.Policies); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}

	prevFile, prevHTTP, _, _ := api.mgr.Snapshot()
	if err := api.mgr.UpdateFileRules(compilation.Policies, compilation.HTTPRules); err != nil {
		if softLSMError(err) {
			logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}

	// If currently enforcing, clear runtime overlays so file layer is authoritative.
	if api.mode == "enforce" {
		_ = api.mgr.SetRuntimeRules(&lsm.PolicySet{}, nil)
	}

	if err := api.saveCanonicalCedar([]byte(cedar)); err != nil {
		// Roll back file layer to last-good state.
		_ = api.mgr.UpdateFileRules(prevFile, prevHTTP)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("failed to persist Cedar: %v", err)})
		return
	}

	resp := api.buildPoliciesResponse()
	api.respondPolicies(w, resp)
}

// handleValidatePolicies lints Cedar and returns a summary with issue list.
func (api *policyAPI) handleValidatePolicies(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	cedar, err := extractCedar(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	cedar = strings.TrimSpace(cedar)
	// Empty body -> treat as no-op lint (report zeros)
	var issues []map[string]any
	var allowOpen, allowExec, allowConnect, denyOpen, denyExec, denyConnect int
	var allowAllConnect bool

	if cedar != "" {
		if rep, err := transpiler.LintFromString(cedar); err == nil && rep != nil {
			for _, it := range rep.Issues {
				sev := "warning"
				if it.Severity == transpiler.LintError {
					sev = "error"
				}
				issues = append(issues, map[string]any{
					"policyId":   it.PolicyID,
					"severity":   sev,
					"code":       it.Code,
					"message":    it.Message,
					"suggestion": it.Suggestion,
				})
			}
		}

		tr := transpiler.NewCedarToLeashTranspiler()
		ps, _, err := tr.TranspileFromString(cedar)
		if err == nil && ps != nil {
			for _, r := range ps.Open {
				if r.Action == lsm.PolicyAllow {
					allowOpen++
				} else {
					denyOpen++
				}
			}
			for _, r := range ps.Exec {
				if r.Action == lsm.PolicyAllow {
					allowExec++
				} else {
					denyExec++
				}
			}
			for _, r := range ps.Connect {
				if r.Action == lsm.PolicyAllow {
					allowConnect++
				} else {
					denyConnect++
				}
				if r.Action == lsm.PolicyAllow && r.IsWildcard == 1 {
					allowAllConnect = true
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"allowOpen":       allowOpen,
		"allowExec":       allowExec,
		"allowConnect":    allowConnect,
		"denyOpen":        denyOpen,
		"denyExec":        denyExec,
		"denyConnect":     denyConnect,
		"allowAllConnect": allowAllConnect,
		"issues":          issues,
	})
}

// handlePermitAll enables a permissive runtime-only overlay and sets UI mode.
func (api *policyAPI) handlePermitAll(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Compile allow-all Cedar. Stash current runtime Cedar so we can restore it
	// when switching back to enforce mode.
	cedarAllowAll := policy.DefaultCedar()
	compilation, compErr := cedarutil.CompileString("permit-all.cedar", cedarAllowAll)
	if compErr != nil || compilation == nil || compilation.Policies == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to compile default policy"})
		return
	}

	// Permit-All is a runtime-only overlay generated from Cedar: ignore the
	// file layer while this mode is active.
	_ = api.mgr.SetRuntimeOnly(true)
	if err := api.mgr.SetRuntimeRules(compilation.Policies, compilation.HTTPRules); err != nil {
		if softLSMError(err) {
			logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}
	api.mu.Lock()
	if api.mode != "permit-all" {
		// Preserve the caller's current Cedar draft so the editor retains it
		// while permit-all is active. We'll restore this when switching back
		// to enforce mode.
		api.cedarPrev = api.cedarRuntime
	}
	api.mu.Unlock()
	api.mode = "permit-all"
	resp := api.buildPoliciesResponse()
	api.respondPolicies(w, resp)
}

// handleEnforceApply clears runtime overlays so only file layer is active.
func (api *policyAPI) handleEnforceApply(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Update Cedar state for the editor: restore the prior runtime draft if we
	// had one; otherwise surface the persisted file Cedar so users keep their
	// policy text in view.
	fileCedar := ""
	if cf, err := api.loadCanonicalCedar(); err == nil {
		fileCedar = string(cf)
	}
	if strings.TrimSpace(fileCedar) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no persisted Cedar available to enforce"})
		return
	}

	compilation, compErr := cedarutil.CompileString(api.policyPath, fileCedar)
	if compErr != nil {
		if detail, ok := compErr.(*cedarutil.ErrorDetail); ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": cedarutil.BuildErrorResponse(detail)})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": compErr.Error()})
		}
		return
	}
	if !hasAnyRules(compilation.Policies, compilation.HTTPRules) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "persisted Cedar produced no rules"})
		return
	}
	if err := ensureConnectSafety(compilation.Policies); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	// Enforce must apply only the real (file) policy: disable runtime-only
	// composition and clear any runtime overlays.
	_ = api.mgr.SetRuntimeOnly(false)
	if err := api.mgr.SetRuntimeRules(&lsm.PolicySet{}, nil); err != nil {
		if softLSMError(err) {
			logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}

	api.mu.Lock()
	if restored := strings.TrimSpace(api.cedarPrev); restored != "" {
		api.cedarRuntime = restored
	} else {
		api.cedarRuntime = fileCedar
	}
	api.cedarPrev = ""
	api.mu.Unlock()

	api.mode = "enforce"
	resp := api.buildPoliciesResponse()
	api.respondPolicies(w, resp)
}

func (api *policyAPI) buildPoliciesResponse() map[string]any {
	fileLSM, fileHTTP, runtimeLSM, runtimeHTTP := api.mgr.Snapshot()
	activeLSM, activeHTTP := api.mgr.GetActiveRules()
	api.mu.RLock()
	cr := api.cedarRuntime
	api.mu.RUnlock()
	// Best-effort read of persisted Cedar file for UI
	cf, _ := api.loadCanonicalCedar()
	return map[string]any{
		"active":          newPolicyLayerView(activeLSM, activeHTTP),
		"file":            newPolicyLayerView(fileLSM, fileHTTP),
		"runtime":         newPolicyLayerView(runtimeLSM, runtimeHTTP),
		"cedarRuntime":    cr,
		"cedarFile":       string(cf),
		"cedarBaseline":   policy.DefaultCedar(),
		"enforcementMode": api.mode,
	}
}

// softLSMError returns true when an LSM/bpf update error should not fail the request.
// This includes known cases in dev/startup where the LSM program or maps are not ready yet
// (e.g., running on non-Linux, missing privileges, or closed/invalid fds).
func softLSMError(err error) bool {
	if err == nil {
		return false
	}
	// Allow soft-fail on non-Linux hosts where LSM is unavailable.
	if runtime.GOOS != "linux" {
		return true
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "bad file descriptor") {
		return true
	}
	if strings.Contains(s, "operation not permitted") {
		return true
	}
	if strings.Contains(s, "bpf") && strings.Contains(s, "not supported") {
		return true
	}
	return false
}

// Frontend expects layers shaped as arrays of rule views under keys 'lsm' and 'http'.
type policyRuleView struct {
	Action     string `json:"action"`
	Operation  string `json:"operation"`
	Target     string `json:"target"`
	Path       string `json:"path,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	IP         string `json:"ip,omitempty"`
	Port       uint16 `json:"port,omitempty"`
	IsWildcard bool   `json:"isWildcard,omitempty"`
	Rule       string `json:"rule"`
}

type httpRuleView struct {
	Host   string `json:"host"`
	Header string `json:"header"`
	Value  string `json:"value"`
	Rule   string `json:"rule"`
}

type policyLayerView struct {
	LSM  []policyRuleView `json:"lsm"`
	HTTP []httpRuleView   `json:"http"`
}

func newPolicyLayerView(ps *lsm.PolicySet, httpRules []proxy.HeaderRewriteRule) policyLayerView {
	view := policyLayerView{LSM: make([]policyRuleView, 0), HTTP: make([]httpRuleView, 0)}
	if ps != nil {
		view.LSM = append(view.LSM, rulesToView(ps.Open)...)
		view.LSM = append(view.LSM, rulesToView(ps.Exec)...)
		view.LSM = append(view.LSM, rulesToView(ps.Connect)...)
	}
	for _, rule := range httpRules {
		view.HTTP = append(view.HTTP, httpRuleView{
			Host:   rule.Host,
			Header: rule.Header,
			Value:  rule.Value,
			Rule:   rule.String(),
		})
	}
	return view
}

func rulesToView(rules []lsm.PolicyRule) []policyRuleView {
	out := make([]policyRuleView, 0, len(rules))
	for _, r := range rules {
		out = append(out, policyRuleToView(r))
	}
	return out
}

func policyRuleToView(rule lsm.PolicyRule) policyRuleView {
	view := policyRuleView{
		Action:    actionString(rule.Action),
		Operation: operationString(rule.Operation),
		Rule:      rule.String(),
	}
	switch rule.Operation {
	case lsm.OpConnect:
		host := strings.TrimRight(string(rule.Hostname[:rule.HostnameLen]), "\x00")
		if host != "" {
			view.Hostname = host
			view.Target = host
		}
		if rule.DestIP != 0 {
			view.IP = formatIPv4(rule.DestIP)
			if view.Target == "" {
				view.Target = view.IP
			}
		}
		if rule.DestPort != 0 {
			view.Port = rule.DestPort
			if view.Target != "" {
				view.Target = fmt.Sprintf("%s:%d", view.Target, rule.DestPort)
			} else {
				view.Target = fmt.Sprintf(":%d", rule.DestPort)
			}
		}
		view.IsWildcard = rule.IsWildcard == 1
	default:
		path := string(bytes.TrimRight(rule.Path[:rule.PathLen], "\x00"))
		view.Path = path
		view.Target = path
		if rule.IsDirectory == 1 && !strings.HasSuffix(view.Target, "/") {
			view.Target += "/"
		}
	}
	return view
}

func actionString(action int32) string {
	if action == lsm.PolicyAllow {
		return "allow"
	}
	return "deny"
}

func operationString(op int32) string {
	switch op {
	case lsm.OpOpen:
		return "file.open"
	case lsm.OpOpenRO:
		return "file.open:ro"
	case lsm.OpOpenRW:
		return "file.open:rw"
	case lsm.OpExec:
		return "proc.exec"
	case lsm.OpConnect:
		return "net.connect"
	default:
		return "unknown"
	}
}

func formatIPv4(addr uint32) string {
	b0 := byte((addr >> 24) & 0xff)
	b1 := byte((addr >> 16) & 0xff)
	b2 := byte((addr >> 8) & 0xff)
	b3 := byte(addr & 0xff)
	return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
}

// extractCedar reads the body as raw Cedar or JSON { "cedar": string }.
func extractCedar(r *http.Request) (string, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return "", errors.New("empty body")
	}
	// Try JSON first when content-type is json or body looks like JSON
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") || (len(data) > 0 && data[0] == '{') {
		var payload struct {
			Cedar string `json:"cedar"`
		}
		if err := json.Unmarshal(data, &payload); err == nil && strings.TrimSpace(payload.Cedar) != "" {
			return payload.Cedar, nil
		}
		if err == nil && strings.TrimSpace(payload.Cedar) == "" {
			return "", errors.New("missing cedar field")
		}
		// Fall through to treat as raw if JSON parse failed
	}
	return string(data), nil
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getLeashDirFromEnv() string {
	if v := os.Getenv("LEASH_DIR"); strings.TrimSpace(v) != "" {
		return v
	}
	return "/leash"
}

func saveCedarRuntime(b []byte) error {
	dir := getLeashDirFromEnv()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "cedar-runtime-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, filepath.Join(dir, "cedar-runtime.cedar"))
}

func (api *policyAPI) saveCanonicalCedar(b []byte) error {
	path := strings.TrimSpace(api.policyPath)
	if path == "" {
		return fmt.Errorf("canonical Cedar path not configured")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "cedar-file-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func loadCedarRuntime() ([]byte, error) {
	dir := getLeashDirFromEnv()
	return os.ReadFile(filepath.Join(dir, "cedar-runtime.cedar"))
}

func (api *policyAPI) loadCanonicalCedar() ([]byte, error) {
	path := strings.TrimSpace(api.policyPath)
	if path == "" {
		return nil, fmt.Errorf("canonical Cedar path not configured")
	}
	return os.ReadFile(path)
}

func hasAnyRules(lsmRules *lsm.PolicySet, httpRules []proxy.HeaderRewriteRule) bool {
	return len(lsmRules.Open)+len(lsmRules.Exec)+len(lsmRules.Connect)+len(httpRules) > 0
}

// handlePolicyLines returns a list of parsed policy lines from the operative Cedar.
// Each line includes: effect (permit/forbid), humanized description, and raw Cedar text.
func (api *policyAPI) handlePolicyLines(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cedar := api.currentCedarSnapshot()
	lines, err := renderPolicyLines(cedar)
	if err != nil {
		logPolicyEvent("policy.lines.parse.error", map[string]any{"error": err.Error()})
	}

	out := map[string]any{"lines": lines}
	writeJSON(w, http.StatusOK, out)
}

// extractCedarStatements splits Cedar source into individual policy statements.
// Each statement is a complete permit(...) or forbid(...) expression ending with semicolon.
func extractCedarStatements(cedar string) []string {
	var statements []string
	var current strings.Builder
	inString := false
	depth := 0

	for _, ch := range cedar {
		current.WriteRune(ch)

		if ch == '"' && (current.Len() == 0 || current.String()[current.Len()-2] != '\\') {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
		} else if ch == ';' && depth == 0 {
			stmt := strings.TrimSpace(current.String())
			if stmt != "" {
				statements = append(statements, stmt)
			}
			current.Reset()
		}
	}

	// Handle any remaining content
	if remaining := strings.TrimSpace(current.String()); remaining != "" {
		statements = append(statements, remaining)
	}

	return statements
}

func dedupeCedarStatements(statements []string) []string {
	seen := make(map[string]struct{}, len(statements))
	deduped := make([]string, 0, len(statements))
	for _, stmt := range statements {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		deduped = append(deduped, trimmed)
	}
	return deduped
}

type policyLine struct {
	ID        string `json:"id"`
	Effect    string `json:"effect"`
	Humanized string `json:"humanized"`
	Cedar     string `json:"cedar"`
	Sequence  int    `json:"sequence"`
}

func (api *policyAPI) currentCedarSnapshot() string {
	api.mu.RLock()
	cedar := api.cedarRuntime
	mode := api.mode
	api.mu.RUnlock()
	if mode == "enforce" && strings.TrimSpace(cedar) == "" {
		if cf, err := api.loadCanonicalCedar(); err == nil {
			cedar = string(cf)
		}
	}
	return cedar
}

func (api *policyAPI) editableCedar() string {
	api.mu.RLock()
	cedar := api.cedarRuntime
	mode := api.mode
	api.mu.RUnlock()
	if strings.TrimSpace(cedar) == "" {
		if cf, err := loadCedarRuntime(); err == nil && len(cf) > 0 {
			cedar = string(cf)
		}
	}
	if mode == "enforce" && strings.TrimSpace(cedar) == "" {
		if cf, err := api.loadCanonicalCedar(); err == nil {
			cedar = string(cf)
		}
	}
	if strings.TrimSpace(cedar) == "" {
		cedar = policy.DefaultCedar()
	}
	return cedar
}

func renderPolicyLines(cedar string) ([]policyLine, error) {
	cedar = strings.TrimSpace(cedar)
	if cedar == "" {
		return []policyLine{}, nil
	}

	statements := extractCedarStatements(cedar)
	statements = dedupeCedarStatements(statements)
	if len(statements) == 0 {
		return []policyLine{}, nil
	}

	lines := make([]policyLine, 0, len(statements))

	for idx, stmt := range statements {
		policy, _ := parsePolicyStatement(stmt)

		id := stablePolicyID(stmt, idx)

		effect := detectPolicyEffect(stmt, policy)
		description := stmt
		if policy != nil {
			if desc := describePolicy(*policy); desc != "" {
				description = fmt.Sprintf("%s %s", effectLabel(effect), desc)
			} else {
				description = fmt.Sprintf("%s %s", effectLabel(effect), strings.TrimSpace(stmt))
			}
		} else {
			description = fmt.Sprintf("%s %s", effectLabel(effect), strings.TrimSpace(stmt))
		}

		lines = append(lines, policyLine{
			ID:        id,
			Effect:    effect,
			Humanized: description,
			Cedar:     stmt,
			Sequence:  idx,
		})
	}

	return lines, nil
}

func parsePolicyStatement(stmt string) (*transpiler.CedarPolicy, error) {
	parser := transpiler.NewCedarParser()
	set, err := parser.ParseFromString(stmt)
	if err != nil {
		return nil, err
	}
	if set == nil || len(set.Policies) == 0 {
		return nil, fmt.Errorf("no policy parsed")
	}
	policy := set.Policies[0]
	return &policy, nil
}

func stablePolicyID(stmt string, index int) string {
	hasher := fnv.New64a()
	trimmed := strings.TrimSpace(stmt)
	_, _ = hasher.Write([]byte(trimmed))
	sum := hasher.Sum64()
	return fmt.Sprintf("policy-%d-%x", index, sum)
}

func detectPolicyEffect(stmt string, policy *transpiler.CedarPolicy) string {
	if policy != nil {
		switch policy.Effect {
		case transpiler.Permit:
			return "permit"
		case transpiler.Forbid:
			return "forbid"
		}
	}
	trimmed := strings.TrimSpace(stmt)
	if strings.HasPrefix(trimmed, "permit") {
		return "permit"
	}
	return "forbid"
}

func effectLabel(effect string) string {
	if effect == "permit" {
		return "Allow"
	}
	if effect == "forbid" {
		return "Deny"
	}
	return strings.Title(effect)
}

func describePolicy(policy transpiler.CedarPolicy) string {
	action := describeAction(policy.Action)
	resource := describeResource(policy)
	principal := describePrincipal(policy.Principal)

	parts := make([]string, 0, 3)
	if action != "" {
		parts = append(parts, action)
	}
	if resource != "" {
		parts = append(parts, resource)
	}
	if len(parts) == 0 {
		parts = append(parts, "policy")
	}
	description := strings.Join(parts, " ")
	if principal != "" {
		description += " for " + principal
	}
	return strings.TrimSpace(description)
}

func describeAction(ac transpiler.ActionConstraint) string {
	if ac.IsAny {
		return "any action"
	}
	var parts []string
	for _, act := range ac.Actions {
		parts = append(parts, humanizeAction(act))
	}
	for _, set := range ac.InSet {
		parts = append(parts, humanizeAction(set))
	}
	return strings.Join(uniqueStrings(parts), ", ")
}

func describeResource(policy transpiler.CedarPolicy) string {
	resources := make([]string, 0)
	resources = append(resources, entityConstraintResources(policy.Resource)...)
	for _, cond := range policy.Conditions {
		if cond.Type == transpiler.ConditionResourceIn {
			for _, lit := range cond.ResourceSet {
				if typ, val, ok := splitResourceLiteral(lit); ok {
					resources = append(resources, humanizeResource(typ, val))
				}
			}
		}
	}
	resources = uniqueStrings(resources)
	if len(resources) == 0 {
		return "any resource"
	}
	return strings.Join(resources, ", ")
}

func describePrincipal(ec transpiler.EntityConstraint) string {
	if ec.IsAny {
		return ""
	}
	if strings.TrimSpace(ec.Type) == "" && strings.TrimSpace(ec.ID) == "" && len(ec.InSet) == 0 {
		return ""
	}

	var parts []string
	if strings.TrimSpace(ec.Type) != "" || strings.TrimSpace(ec.ID) != "" {
		parts = append(parts, humanizePrincipal(ec.Type, ec.ID))
	}
	for _, v := range ec.InSet {
		parts = append(parts, humanizePrincipal(ec.Type, v))
	}
	parts = uniqueStrings(parts)
	if len(parts) == 0 {
		return "specified principals"
	}
	return strings.Join(parts, ", ")
}

func entityConstraintResources(ec transpiler.EntityConstraint) []string {
	results := make([]string, 0)
	if ec.IsAny && strings.TrimSpace(ec.ID) == "" && len(ec.InSet) == 0 {
		return results
	}
	if strings.TrimSpace(ec.ID) != "" {
		results = append(results, humanizeResource(ec.Type, ec.ID))
	}
	for _, val := range ec.InSet {
		results = append(results, humanizeResource(ec.Type, val))
	}
	return results
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func analyzeConnectPolicies(ps *lsm.PolicySet) (allowCount int, wildcard bool) {
	if ps == nil {
		return 0, false
	}
	for _, rule := range ps.Connect {
		if rule.Action == lsm.PolicyAllow {
			allowCount++
			if rule.IsWildcard == 1 {
				wildcard = true
			}
		}
	}
	return
}

func ensureConnectSafety(ps *lsm.PolicySet) error {
	allowCount, _ := analyzeConnectPolicies(ps)
	if allowCount == 0 {
		return errors.New("refusing to remove all network connect allows")
	}
	return nil
}

func (api *policyAPI) addPolicyStatement(newCedar string) (map[string]any, int, error) {
	stmt := strings.TrimSpace(newCedar)
	if stmt == "" {
		return nil, http.StatusBadRequest, errors.New("empty policy statement")
	}
	if !strings.HasSuffix(stmt, ";") {
		stmt += ";"
	}

	newParser := transpiler.NewCedarParser()
	newSet, err := newParser.ParseFromString(stmt)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid Cedar: %w", err)
	}
	if len(newSet.Policies) == 0 {
		return nil, http.StatusBadRequest, errors.New("no policy found in statement")
	}
	newPolicy := newSet.Policies[0]

	existing := strings.TrimSpace(api.editableCedar())
	if existing != "" {
		existingParser := transpiler.NewCedarParser()
		if existingSet, err := existingParser.ParseFromString(existing); err == nil {
			for _, existingPolicy := range existingSet.Policies {
				if policiesAreEquivalent(newPolicy, existingPolicy) {
					logPolicyEvent("policy.add.duplicate", map[string]any{"id": newPolicy.ID})
					resp := api.buildPoliciesResponse()
					return resp, http.StatusOK, nil
				}
			}
		}
	}

	updated := stmt
	if existing != "" {
		updated = stmt + "\n\n" + existing
	}

	tr := transpiler.NewCedarToLeashTranspiler()
	lsmRules, httpRules, err := tr.TranspileFromString(updated)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := ensureConnectSafety(lsmRules); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := api.mgr.SetRuntimeRules(lsmRules, httpRules); err != nil {
		if softLSMError(err) {
			logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
		} else {
			return nil, http.StatusInternalServerError, err
		}
	}

	if err := saveCedarRuntime([]byte(updated)); err != nil {
		logPolicyEvent("policy.add", map[string]any{"error": err.Error(), "persist": "cedar-runtime"})
	}

	api.mu.Lock()
	api.cedarRuntime = updated
	api.mu.Unlock()

	logPolicyEvent("policy.add", map[string]any{"id": newPolicy.ID})

	resp := api.buildPoliciesResponse()
	return resp, http.StatusOK, nil
}

type actionPayload struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type addPolicyFromActionRequest struct {
	Effect string        `json:"effect"`
	Action actionPayload `json:"action"`
}

type deletePolicyRequest struct {
	ID    string `json:"id"`
	Cedar string `json:"cedar"`
}

func buildCedarFromActionRequest(req addPolicyFromActionRequest) (string, error) {
	effect := strings.ToLower(strings.TrimSpace(req.Effect))
	if effect != "permit" && effect != "forbid" {
		return "", errors.New("effect must be permit or forbid")
	}
	actType := strings.TrimSpace(req.Action.Type)
	name := strings.TrimSpace(req.Action.Name)
	if actType == "" {
		return "", errors.New("action.type is required")
	}

	switch actType {
	case "file/open":
		entity, kind := buildFileEntityFromName(name)
		action := `Fs::"ReadFile"`
		if kind == "dir" {
			action = `Fs::"ListDir"`
		}
		return buildHeadEqualityPolicy(effect, action, entity), nil
	case "file/write":
		entity, kind := buildFileEntityFromName(name)
		action := `Fs::"WriteFile"`
		if kind == "dir" {
			action = `Fs::"CreateFileUnder"`
		}
		return buildHeadEqualityPolicy(effect, action, entity), nil
	case "proc/exec":
		path := firstToken(name)
		if path == "" {
			return "", errors.New("unable to derive command path from action name")
		}
		resource := fmt.Sprintf(`Fs::File::"%s"`, escapeCedarString(path))
		return buildHeadEqualityPolicy(effect, `Proc::"Exec"`, resource), nil
	case "net/connect":
		host := parseHostFromName(name)
		if host == "" {
			host = "example.com"
		}
		resource := fmt.Sprintf(`Net::Hostname::"%s"`, escapeCedarString(host))
		return buildHeadEqualityPolicy(effect, `Net::"Connect"`, resource), nil
	case "fs/list":
		entity, _ := buildFileEntityFromName(name)
		return buildHeadEqualityPolicy(effect, `Fs::"ListDir"`, entity), nil
	case "dns/resolve":
		host := parseHostFromName(name)
		if host == "" {
			host = "example.com"
		}
		resource := fmt.Sprintf(`Net::Hostname::"%s"`, escapeCedarString(host))
		return buildHeadEqualityPolicy(effect, `Net::"Connect"`, resource), nil
		// MCP events: Option A — Action::"McpCall" with MCP::Tool and MCP::Server
	case "mcp/deny", "mcp/allow", "mcp/list", "mcp/call", "mcp/resources", "mcp/prompts", "mcp/init", "mcp/notify":
		server := parseServerHostFromName(name)
		tool := parseToolFromName(name)
		if server == "" {
			server = "example.com"
		}
		if tool != "" {
			return fmt.Sprintf(`%s (principal, action == Action::"McpCall", resource == MCP::Tool::"%s") when { resource in [ MCP::Server::"%s" ] };`, effect, escapeCedarString(tool), escapeCedarString(server)), nil
		}
		return fmt.Sprintf(`%s (principal, action == Action::"McpCall", resource) when { resource in [ MCP::Server::"%s" ] };`, effect, escapeCedarString(server)), nil
	default:
		return "", fmt.Errorf("unsupported action type %q", actType)
	}
}

func buildHeadEqualityPolicy(effect, action, resource string) string {
	return fmt.Sprintf(`%s (principal, action == %s, resource == %s);`, effect, action, resource)
}

func buildFileEntityFromName(name string) (string, string) {
	path := firstToken(name)
	if path == "" {
		path = "/"
	}
	kind := "file"
	if strings.HasSuffix(path, "/") {
		kind = "dir"
	}
	entityType := `Fs::File`
	if kind == "dir" {
		entityType = `Fs::Directory`
	}
	return fmt.Sprintf(`%s::"%s"`, entityType, escapeCedarString(path)), kind
}

func firstToken(text string) string {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func escapeCedarString(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return escaped
}

func parseHostFromName(name string) string {
	candidate := strings.TrimSpace(name)
	if candidate == "" {
		return ""
	}

	lower := strings.ToLower(candidate)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if u, err := url.Parse(candidate); err == nil && u != nil {
			if u.Host != "" {
				return u.Host
			}
		}
	}

	for _, tok := range strings.Fields(candidate) {
		cleaned := strings.Trim(tok, "[]")
		if isHostLike(cleaned) {
			return cleaned
		}
	}

	return strings.Trim(candidate, "[]")
}

// parseToolFromName extracts the MCP tool name from free-form text like
// "... tool=<name>"; returns empty string if not present.
func parseToolFromName(name string) string {
	candidate := strings.TrimSpace(name)
	if candidate == "" {
		return ""
	}
	for _, tok := range strings.Fields(candidate) {
		if !strings.Contains(tok, "=") {
			continue
		}
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		v = strings.Trim(v, "[]")
		if k == "tool" {
			return v
		}
	}
	return ""
}

// parseServerHostFromName attempts to extract an MCP server host from a free-form
// action name. It understands tokens like "server=https://api.example.com" or
// "server=api.example.com" and returns the host portion. If no explicit server
// token is found, returns an empty string.
func parseServerHostFromName(name string) string {
	candidate := strings.TrimSpace(name)
	if candidate == "" {
		return ""
	}
	fields := strings.Fields(candidate)
	for _, f := range fields {
		if !strings.Contains(f, "=") {
			continue
		}
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		v = strings.Trim(v, "[]")
		if k != "server" {
			continue
		}
		// Try URL first
		if strings.HasPrefix(strings.ToLower(v), "http://") || strings.HasPrefix(strings.ToLower(v), "https://") || strings.HasPrefix(strings.ToLower(v), "ws://") || strings.HasPrefix(strings.ToLower(v), "wss://") {
			if u, err := url.Parse(v); err == nil && u != nil && u.Host != "" {
				h := u.Host
				if idx := strings.LastIndex(h, ":"); idx > -1 {
					if _, err := strconv.Atoi(h[idx+1:]); err == nil {
						return h[:idx]
					}
				}
				return h
			}
		}
		// Otherwise, accept host-like tokens (including host:port and IPs)
		if isHostLike(v) {
			// If a port is present, strip it for the Cedar Host entity which captures hostnames; port matching is not modeled.
			if idx := strings.LastIndex(v, ":"); idx > -1 {
				if _, err := strconv.Atoi(v[idx+1:]); err == nil {
					return v[:idx]
				}
			}
			return v
		}
	}
	return ""
}

func isHostLike(s string) bool {
	if s == "" {
		return false
	}
	host := s
	if idx := strings.LastIndex(s, ":"); idx > -1 && idx < len(s)-1 {
		port := s[idx+1:]
		if _, err := strconv.Atoi(port); err == nil {
			host = s[:idx]
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if strings.Count(host, ".") == 0 {
		return false
	}
	for _, r := range host {
		if !(r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func (api *policyAPI) deletePolicy(req deletePolicyRequest) (map[string]any, int, error) {
	id := strings.TrimSpace(req.ID)
	targetCedar := strings.TrimSpace(req.Cedar)
	if id == "" && targetCedar == "" {
		return nil, http.StatusBadRequest, errors.New("id or cedar must be provided")
	}

	existing := strings.TrimSpace(api.editableCedar())
	if existing == "" {
		return nil, http.StatusBadRequest, errors.New("no policies available to delete")
	}

	statements := extractCedarStatements(existing)
	if len(statements) == 0 {
		return nil, http.StatusBadRequest, errors.New("no policy statements available")
	}

	lines, err := renderPolicyLines(existing)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to parse policies: %w", err)
	}

	index := -1
	var deletedLine policyLine
	for idx, line := range lines {
		if id != "" && line.ID == id {
			index = idx
			deletedLine = line
			break
		}
		if targetCedar != "" && strings.TrimSpace(line.Cedar) == targetCedar {
			index = idx
			deletedLine = line
			break
		}
	}
	if index == -1 {
		return nil, http.StatusNotFound, errors.New("policy not found")
	}

	if len(statements) <= 1 {
		return nil, http.StatusBadRequest, errors.New("cannot remove the final policy statement")
	}

	statements = append(statements[:index], statements[index+1:]...)
	updated := strings.TrimSpace(strings.Join(statements, "\n\n"))

	tr := transpiler.NewCedarToLeashTranspiler()
	lsmRules, httpRules, err := tr.TranspileFromString(updated)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := ensureConnectSafety(lsmRules); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := api.mgr.SetRuntimeRules(lsmRules, httpRules); err != nil {
		if softLSMError(err) {
			logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
		} else {
			return nil, http.StatusInternalServerError, err
		}
	}

	if err := saveCedarRuntime([]byte(updated)); err != nil {
		logPolicyEvent("policy.delete", map[string]any{"error": err.Error(), "persist": "cedar-runtime"})
	}

	api.mu.Lock()
	api.cedarRuntime = updated
	api.mu.Unlock()

	prevFile, prevHTTP, _, _ := api.mgr.Snapshot()
	if err := api.mgr.UpdateFileRules(lsmRules, httpRules); err != nil {
		if softLSMError(err) {
			logPolicyEvent("lsm.update.skip", map[string]any{"reason": err.Error()})
		} else {
			return nil, http.StatusInternalServerError, err
		}
	}

	payload := strings.TrimSpace(updated)
	if payload != "" && !strings.HasSuffix(payload, "\n") {
		payload += "\n"
	}
	if err := api.saveCanonicalCedar([]byte(payload)); err != nil {
		_ = api.mgr.UpdateFileRules(prevFile, prevHTTP)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to persist Cedar: %w", err)
	}

	logPolicyEvent("policy.delete", map[string]any{
		"id":          deletedLine.ID,
		"effect":      deletedLine.Effect,
		"description": deletedLine.Humanized,
	})

	resp := api.buildPoliciesResponse()
	return resp, http.StatusOK, nil
}

// humanizeAction converts Cedar action to human-readable text.

func humanizeAction(action string) string {
	// Expect Action::"PascalCase" only; no legacy/schemas.
	trimmed := strings.Trim(action, "\"")
	lower := strings.ToLower(trimmed)
	if i := strings.Index(lower, "action::"); i >= 0 {
		trimmed = trimmed[i+len("action::"):]
		trimmed = strings.Trim(trimmed, "\"")
		lower = strings.ToLower(trimmed)
	}
	switch lower {
	case "fileopen":
		return "open files"
	case "fileopenreadonly", "read", "readfile":
		return "read files"
	case "fileopenreadwrite", "write", "writefile":
		return "write files"
	case "processexec", "exec", "execute":
		return "run processes"
	case "networkconnect", "connect":
		return "network connect"
	case "httprewrite", "http.rewrite":
		return "HTTP rewrite"
	case "mcpcall":
		return "call MCP tool"
	default:
		return strings.ReplaceAll(trimmed, "_", " ")
	}
}

// humanizeResource converts Cedar resource to human-readable text.
func humanizeResource(resourceType, resourceID string) string {
	typeParts := parseSegments(resourceType)
	id := strings.Trim(resourceID, "\"")
	if id == "*" || strings.EqualFold(id, "any") || id == "" {
		return friendlyResourceForType(typeParts, true)
	}
	return friendlyResourceForTypeWithValue(typeParts, id)
}

func humanizePrincipal(resourceType, resourceID string) string {
	typeParts := parseSegments(resourceType)
	id := strings.Trim(resourceID, "\"")
	if id == "" {
		return "specified principals"
	}
	return friendlyResourceForTypeWithValue(typeParts, id)
}

func parseSegments(value string) []string {
	if value == "" {
		return nil
	}
	segments := strings.Split(value, "::")
	out := make([]string, 0, len(segments))
	for _, s := range segments {
		s = strings.TrimSpace(s)
		s = strings.Trim(s, "\"")
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func friendlyResourceForType(typeParts []string, wildcard bool) string {
	if len(typeParts) == 0 {
		if wildcard {
			return "any resource"
		}
		return "resource"
	}
	switch strings.ToLower(typeParts[0]) {
	case "fs", "filesystem", "file", "dir":
		if len(typeParts) > 1 && strings.EqualFold(typeParts[1], "directory") || strings.EqualFold(typeParts[0], "dir") {
			if wildcard {
				return "any directory"
			}
			return "directory"
		}
		if wildcard {
			return "any file"
		}
		return "file"
	case "net", "network", "host", "hostname":
		if wildcard {
			return "any host"
		}
		return "host"
	case "mcp":
		if len(typeParts) > 1 {
			switch strings.ToLower(typeParts[1]) {
			case "tool":
				if wildcard {
					return "any MCP tool"
				}
				return "MCP tool"
			case "server":
				if wildcard {
					return "any MCP server"
				}
				return "MCP server"
			}
		}
		if wildcard {
			return "any MCP resource"
		}
		return "MCP resource"
	case "proc", "process":
		if wildcard {
			return "any process"
		}
		return "process"
	default:
		if wildcard {
			return "any resource"
		}
		return strings.ToLower(typeParts[len(typeParts)-1])
	}
}

func friendlyResourceForTypeWithValue(typeParts []string, value string) string {
	if len(typeParts) == 0 {
		return value
	}
	switch strings.ToLower(typeParts[0]) {
	case "fs", "filesystem", "file", "dir":
		isDirectory := len(typeParts) > 1 && strings.EqualFold(typeParts[1], "directory") || strings.EqualFold(typeParts[0], "dir")
		if isDirectory {
			if value == "" {
				return "any directory"
			}
			if !strings.HasSuffix(value, "/") {
				value += "/"
			}
			return "directory " + value
		}
		if value == "" {
			return "any file"
		}
		return value
	case "net", "network", "host", "hostname":
		if value == "*" {
			return "any host"
		}
		return value
	case "mcp":
		if len(typeParts) > 1 {
			switch strings.ToLower(typeParts[1]) {
			case "tool":
				if value == "" {
					return "any MCP tool"
				}
				return fmt.Sprintf("MCP tool %s", value)
			case "server":
				if value == "" || value == "*" {
					return "any MCP server"
				}
				return fmt.Sprintf("MCP server %s", value)
			}
		}
		if value == "" {
			return "MCP resource"
		}
		return fmt.Sprintf("MCP %s", value)
	case "proc", "process":
		return value
	default:
		return value
	}
}

func splitResourceLiteral(literal string) (string, string, bool) {
	lit := strings.TrimSpace(literal)
	if lit == "" {
		return "", "", false
	}
	parts := strings.Split(lit, "::")
	if len(parts) == 0 {
		return "", "", false
	}
	var typeParts []string
	if len(parts) > 1 {
		typeParts = parts[:len(parts)-1]
	}
	value := strings.Trim(parts[len(parts)-1], "\"")
	typeStr := strings.Join(typeParts, "::")
	return typeStr, value, true
}

// handleAddPolicy adds a new Cedar policy statement with idempotent behavior.
// If an AST-equivalent policy already exists, it's a no-op. Otherwise, prepends the new policy.
func (api *policyAPI) handleAddPolicy(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	newCedar, err := extractCedar(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	resp, status, applyErr := api.addPolicyStatement(newCedar)
	if applyErr != nil {
		writeJSON(w, status, map[string]any{"error": applyErr.Error()})
		return
	}

	api.respondPolicies(w, resp)
}

// handleAddPolicyFromAction builds a Cedar snippet from an action descriptor on the server.
func (api *policyAPI) handleAddPolicyFromAction(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var req addPolicyFromActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON payload"})
		return
	}

	cedar, err := buildCedarFromActionRequest(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	resp, status, applyErr := api.addPolicyStatement(cedar)
	if applyErr != nil {
		writeJSON(w, status, map[string]any{"error": applyErr.Error()})
		return
	}

	api.respondPolicies(w, resp)
}

// handleDeletePolicy removes a Cedar policy statement by ID or literal match.
func (api *policyAPI) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var req deletePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON payload"})
		return
	}

	resp, status, delErr := api.deletePolicy(req)
	if delErr != nil {
		writeJSON(w, status, map[string]any{"error": delErr.Error()})
		return
	}

	api.respondPolicies(w, resp)
}

// policiesAreEquivalent checks if two policies are semantically equivalent by comparing ASTs.
func policiesAreEquivalent(p1, p2 transpiler.CedarPolicy) bool {
	// Compare effects
	if p1.Effect != p2.Effect {
		return false
	}

	// Compare principal constraints
	if !entityConstraintsEqual(p1.Principal, p2.Principal) {
		return false
	}

	// Compare action constraints
	if !actionConstraintsEqual(p1.Action, p2.Action) {
		return false
	}

	// Compare resource constraints
	if !entityConstraintsEqual(p1.Resource, p2.Resource) {
		return false
	}

	// For conditions, we'll use the native AST comparison if available
	if p1.NativePolicy != nil && p2.NativePolicy != nil {
		// Compare using AST string representation as a proxy
		ast1 := fmt.Sprintf("%+v", p1.NativePolicy.AST())
		ast2 := fmt.Sprintf("%+v", p2.NativePolicy.AST())
		if ast1 != ast2 {
			return false
		}
	}

	return true
}

func entityConstraintsEqual(e1, e2 transpiler.EntityConstraint) bool {
	if e1.IsAny != e2.IsAny || e1.Type != e2.Type || e1.ID != e2.ID {
		return false
	}
	if len(e1.InSet) != len(e2.InSet) {
		return false
	}
	// For simplicity, require exact match of InSet
	for i := range e1.InSet {
		if e1.InSet[i] != e2.InSet[i] {
			return false
		}
	}
	return true
}

func actionConstraintsEqual(a1, a2 transpiler.ActionConstraint) bool {
	if a1.IsAny != a2.IsAny {
		return false
	}
	if len(a1.Actions) != len(a2.Actions) {
		return false
	}
	// Compare action lists (order matters for our purposes)
	for i := range a1.Actions {
		if a1.Actions[i] != a2.Actions[i] {
			return false
		}
	}
	if len(a1.InSet) != len(a2.InSet) {
		return false
	}
	for i := range a1.InSet {
		if a1.InSet[i] != a2.InSet[i] {
			return false
		}
	}
	return true
}
