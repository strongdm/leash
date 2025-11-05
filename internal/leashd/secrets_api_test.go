package leashd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/strongdm/leash/internal/secrets"
)

type noopBroadcaster struct{}

func (noopBroadcaster) EmitJSON(string, any) {}

func TestSecretsAPIGet(t *testing.T) {
	t.Parallel()
	manager := secrets.NewManager()
	if _, err := manager.Upsert("alpha", "", "value-a"); err != nil {
		t.Fatalf("setup create failed: %v", err)
	}

	api := newSecretsAPI(manager, noopBroadcaster{})
	mux := http.NewServeMux()
	api.register(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	var payload map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if _, ok := payload["alpha"]; !ok {
		t.Fatalf("expected alpha secret in response: %#v", payload)
	}
}

func TestSecretsAPICreateAndRename(t *testing.T) {
	t.Parallel()
	manager := secrets.NewManager()
	api := newSecretsAPI(manager, noopBroadcaster{})
	mux := http.NewServeMux()
	api.register(mux)

	body := map[string]string{"value": "secret"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/secrets/dbPassword", bytes.NewReader(data))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected create status 200, got %d", rec.Code)
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}
	if created["id"] != "dbPassword" {
		t.Fatalf("expected id dbPassword, got %v", created["id"])
	}

	renameBody := map[string]string{"id": "dbPasswordNew", "value": "secret"}
	renameData, _ := json.Marshal(renameBody)
	renameReq := httptest.NewRequest(http.MethodPost, "/api/secrets/dbPassword", bytes.NewReader(renameData))
	renameRec := httptest.NewRecorder()
	mux.ServeHTTP(renameRec, renameReq)
	if renameRec.Code != http.StatusOK {
		t.Fatalf("expected rename status 200, got %d", renameRec.Code)
	}
	var renamed map[string]any
	if err := json.Unmarshal(renameRec.Body.Bytes(), &renamed); err != nil {
		t.Fatalf("failed to decode rename response: %v", err)
	}
	if renamed["id"] != "dbPasswordNew" {
		t.Fatalf("expected renamed id dbPasswordNew, got %v", renamed["id"])
	}
}

func TestSecretsAPIDelete(t *testing.T) {
	t.Parallel()
	manager := secrets.NewManager()
	if _, err := manager.Upsert("toDelete", "", "value"); err != nil {
		t.Fatalf("setup create failed: %v", err)
	}

	api := newSecretsAPI(manager, noopBroadcaster{})
	mux := http.NewServeMux()
	api.register(mux)

	req := httptest.NewRequest(http.MethodDelete, "/api/secrets/toDelete", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected delete status 204, got %d", rec.Code)
	}
	if _, err := manager.Upsert("toDelete", "", "value"); err != nil {
		t.Fatalf("recreate after delete failed: %v", err)
	}
}
