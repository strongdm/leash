package leashd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/strongdm/leash/internal/secrets"
)

const (
	maxSecretPayloadBytes = 1 << 20 // 1 MiB
)

type secretsBroadcaster interface {
	EmitJSON(event string, payload any)
}

type secretsAPI struct {
	mgr         *secrets.Manager
	broadcaster secretsBroadcaster
}

func newSecretsAPI(mgr *secrets.Manager, broadcaster secretsBroadcaster) *secretsAPI {
	return &secretsAPI{
		mgr:         mgr,
		broadcaster: broadcaster,
	}
}

func (api *secretsAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("/api/secrets", api.handleSecrets)
	mux.HandleFunc("/api/secrets/", api.handleSecretByID)
}

func (api *secretsAPI) handleSecrets(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/api/secrets" {
		http.NotFound(w, r)
		return
	}

	secretsMap := api.mgr.GetAll()
	resp := make(map[string]map[string]any, len(secretsMap))
	for id, secret := range secretsMap {
		resp[id] = map[string]any{
			"value":       secret.Value,
			"placeholder": secret.Placeholder,
			"activations": secret.Activations,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (api *secretsAPI) handleSecretByID(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodPost:
		api.handlePostSecret(w, r, id)
	case http.MethodDelete:
		api.handleDeleteSecret(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type secretUpsertRequest struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

func (api *secretsAPI) handlePostSecret(w http.ResponseWriter, r *http.Request, pathID string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSecretPayloadBytes)
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		api.writeError(w, http.StatusBadRequest, "body required")
		return
	}

	var payload secretUpsertRequest
	if err := json.Unmarshal(body, &payload); err != nil {
		api.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if payload.Value == "" {
		api.writeError(w, http.StatusBadRequest, "value required")
		return
	}
	if len(payload.Value) > maxSecretPayloadBytes {
		api.writeError(w, http.StatusBadRequest, "value exceeds 1MiB limit")
		return
	}

	secret, err := api.mgr.Upsert(pathID, payload.ID, payload.Value)
	if err != nil {
		switch {
		case errors.Is(err, secrets.ErrInvalidID):
			api.writeError(w, http.StatusBadRequest, "invalid id")
		case errors.Is(err, secrets.ErrConflict):
			api.writeError(w, http.StatusConflict, "secret already exists")
		case errors.Is(err, secrets.ErrNotFound):
			api.writeError(w, http.StatusNotFound, "secret not found")
		default:
			api.writeError(w, http.StatusInternalServerError, "failed to upsert secret")
		}
		return
	}

	resp := map[string]any{
		"id":          secret.ID,
		"value":       secret.Value,
		"placeholder": secret.Placeholder,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (api *secretsAPI) handleDeleteSecret(w http.ResponseWriter, _ *http.Request, id string) {
	if err := api.mgr.Delete(id); err != nil {
		switch {
		case errors.Is(err, secrets.ErrInvalidID):
			api.writeError(w, http.StatusBadRequest, "invalid id")
		case errors.Is(err, secrets.ErrNotFound):
			api.writeError(w, http.StatusNotFound, "secret not found")
		default:
			api.writeError(w, http.StatusInternalServerError, "failed to delete secret")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *secretsAPI) writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": message,
		},
	})
}
