package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/entrypoint"
)

type completionRequest struct {
	Cedar    string             `json:"cedar"`
	Cursor   completionCursor   `json:"cursor"`
	MaxItems int                `json:"maxItems,omitempty"`
	IDHints  *completionIDHints `json:"idHints,omitempty"`
}

type completionCursor struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type completionIDHints struct {
	Servers []string `json:"servers,omitempty"`
	Tools   []string `json:"tools,omitempty"`
}

type completionResponse struct {
	Items []completionItem `json:"items"`
}

type completionItem struct {
	Label string `json:"label"`
	Kind  string `json:"kind"`
}

func TestPoliciesCompleteE2E(t *testing.T) {
	skipUnlessE2E(t)

	t.Parallel()

	bin := ensureLeashBinary(t)

	shareDir := t.TempDir()
	mustWrite(t, filepath.Join(shareDir, entrypoint.ReadyFileName), []byte("1\n"))

	cgroupDir := filepath.Join(t.TempDir(), "cgroup")
	mustCreateDir(t, cgroupDir)
	mustWrite(t, filepath.Join(cgroupDir, "cgroup.controllers"), []byte("memory\n"))

	policyPath := filepath.Join(t.TempDir(), "policy.cedar")
	policyBody := `permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"example.com" ] };`
	mustWrite(t, policyPath, []byte(policyBody))

	uiPort := freePort(t)
	proxyPort := freePort(t)

	cfg := daemonConfig{
		shareDir:   shareDir,
		cgroupDir:  cgroupDir,
		policyPath: policyPath,
		listenAddr: ":" + uiPort,
		proxyPort:  proxyPort,
		timeout:    15 * time.Second,
	}

	cmd, stdout, stderr := startDaemon(t, bin, cfg)
	defer terminateProcess(t, cmd, stdout, stderr)

	policyURL := fmt.Sprintf("http://127.0.0.1:%s/health/policy", uiPort)
	waitForPolicyStatus(t, policyURL, http.StatusServiceUnavailable, 10*time.Second)

	writeBootstrapMarker(t, shareDir, map[string]any{
		"pid":       os.Getpid(),
		"hostname":  "e2e-complete",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})

	waitForPolicyStatus(t, policyURL, http.StatusOK, cfg.timeout+5*time.Second)

	baseURL := fmt.Sprintf("http://127.0.0.1:%s/api/policies/complete", uiPort)

	t.Run("start-of-document", func(t *testing.T) {
		resp := completeRequestE2E(t, baseURL, completionRequest{
			Cedar:  "",
			Cursor: completionCursor{Line: 1, Column: 1},
		})
		if len(resp.Items) == 0 {
			t.Fatalf("expected suggestions, got none")
		}
		if resp.Items[0].Label != "permit" {
			t.Fatalf("expected permit suggestion first, got %q", resp.Items[0].Label)
		}
	})

	t.Run("action-comparator", func(t *testing.T) {
		resp := completeRequestE2E(t, baseURL, completionRequest{
			Cedar:  `permit (principal, action == , resource);`,
			Cursor: completionCursor{Line: 1, Column: 33},
		})
		if !containsLabel(resp.Items, `Action::"FileOpen"`) {
			t.Fatalf("expected action suggestions, got %+v", resp.Items)
		}
	})

	t.Run("resource-hints", func(t *testing.T) {
		resp := completeRequestE2E(t, baseURL, completionRequest{
			Cedar: `permit (principal, action == Action::"NetworkConnect", resource)
    when { resource in [  ] };`,
			Cursor: completionCursor{Line: 2, Column: 25},
		})
		if len(resp.Items) == 0 {
			t.Fatalf("expected resource suggestions")
		}
		if resp.Items[0].Label != `Host::"example.com"` {
			t.Fatalf("expected host hint first, got %q", resp.Items[0].Label)
		}
	})

	t.Run("handles malformed input", func(t *testing.T) {
		resp := completeRequestE2E(t, baseURL, completionRequest{
			Cedar:  `permit (principal, action == Action::"FileOpen", resource`,
			Cursor: completionCursor{Line: 1, Column: 59},
		})
		if len(resp.Items) == 0 {
			t.Fatalf("expected suggestions even for malformed input")
		}
	})

	t.Run("comment context", func(t *testing.T) {
		resp := completeRequestE2E(t, baseURL, completionRequest{
			Cedar:  "// comment",
			Cursor: completionCursor{Line: 1, Column: 11},
		})
		if len(resp.Items) != 0 {
			t.Fatalf("expected no suggestions inside comments, got %+v", resp.Items)
		}
	})

	t.Run("rapid requests", func(t *testing.T) {
		const workers = 5
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(iter int) {
				defer wg.Done()
				resp := completeRequestE2E(t, baseURL, completionRequest{
					Cedar:  fmt.Sprintf("permit (principal, action == , resource); // %d", iter),
					Cursor: completionCursor{Line: 1, Column: 33},
				})
				if len(resp.Items) == 0 {
					errs <- fmt.Errorf("worker %d: no suggestions", iter)
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("large input", func(t *testing.T) {
		builder := strings.Builder{}
		builder.Grow(8192)
		for i := 0; i < 200; i++ {
			builder.WriteString("permit (principal, action == Action::\"NetworkConnect\", resource) when { resource in [ Host::\"example.com\" ] };\n")
		}
		cedar := builder.String()
		resp := completeRequestE2E(t, baseURL, completionRequest{
			Cedar:  cedar,
			Cursor: completionCursor{Line: 200, Column: 33},
		})
		if len(resp.Items) == 0 {
			t.Fatalf("expected suggestions for large input")
		}
	})

	t.Run("id hints surface", func(t *testing.T) {
		resp := completeRequestE2E(t, baseURL, completionRequest{
			Cedar: `forbid (principal, action == Action::"McpCall", resource)
	when { resource in [ MCP::Server::"" ] };`,
			Cursor:  completionCursor{Line: 2, Column: 32},
			IDHints: &completionIDHints{Servers: []string{"mcp.example.com"}, Tools: []string{"resolve-library-id"}},
		})
		if !containsLabel(resp.Items, `MCP::Server::"mcp.example.com"`) {
			t.Fatalf("expected MCP hint in suggestions, got %+v", resp.Items)
		}
	})
}

func completeRequestE2E(t *testing.T, url string, req completionRequest) completionResponse {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	httpClient := &http.Client{Timeout: 2 * time.Second}
	defer httpClient.CloseIdleConnections()

	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		t.Fatalf("unexpected status %d body=%s", resp.StatusCode, buf.String())
	}

	var decoded completionResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode completion response: %v", err)
	}
	return decoded
}

func containsLabel(items []completionItem, want string) bool {
	for _, item := range items {
		if item.Label == want {
			return true
		}
	}
	return false
}
