package runner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/leashd/listen"
)

func TestRegisterSecretsSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/secrets/"):
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if payload["id"] != "API_TOKEN" {
				t.Fatalf("expected id API_TOKEN, got %q", payload["id"])
			}
			if payload["value"] != "abcd1234" {
				t.Fatalf("expected value abcd1234, got %q", payload["value"])
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"placeholder":"ph_api_token"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	cfg := config{listenCfg: listenConfigFromURL(t, server.URL)}
	r := &runner{
		opts: options{
			secretSpecs: []secretSpec{
				{Key: "API_TOKEN", Value: "abcd1234"},
			},
		},
		cfg: cfg,
	}

	if err := r.registerSecrets(context.Background()); err != nil {
		t.Fatalf("registerSecrets returned error: %v", err)
	}

	if len(r.secretPlaceholders) != 1 {
		t.Fatalf("expected 1 placeholder, got %d", len(r.secretPlaceholders))
	}
	if got := r.secretPlaceholders["API_TOKEN"]; got != "ph_api_token" {
		t.Fatalf("placeholder mismatch: got %q want %q", got, "ph_api_token")
	}
}

func TestRegisterSecretsConflictFallback(t *testing.T) {
	t.Parallel()

	var postCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/secrets/"):
			postCount++
			if postCount > 1 {
				t.Fatalf("unexpected additional POST requests")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"message":"secret already exists"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/secrets":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"API_TOKEN":{"placeholder":"ph_from_get"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	cfg := config{listenCfg: listenConfigFromURL(t, server.URL)}
	r := &runner{
		opts: options{
			secretSpecs: []secretSpec{
				{Key: "API_TOKEN", Value: "existing"},
			},
		},
		cfg: cfg,
	}

	if err := r.registerSecrets(context.Background()); err != nil {
		t.Fatalf("registerSecrets returned error: %v", err)
	}
	if got := r.secretPlaceholders["API_TOKEN"]; got != "ph_from_get" {
		t.Fatalf("placeholder mismatch: got %q want %q", got, "ph_from_get")
	}
}

func TestRegisterSecretsServerError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"boom"}}`))
	}))
	t.Cleanup(server.Close)

	cfg := config{listenCfg: listenConfigFromURL(t, server.URL)}
	r := &runner{
		opts: options{
			secretSpecs: []secretSpec{
				{Key: "API_TOKEN", Value: "secret"},
			},
		},
		cfg: cfg,
	}

	if err := r.registerSecrets(context.Background()); err == nil {
		t.Fatal("expected error when server returns 500")
	}
	if len(r.secretPlaceholders) != 0 {
		t.Fatalf("expected no placeholders stored on error, got %+v", r.secretPlaceholders)
	}
}

func TestRegisterSecretsDisabledListen(t *testing.T) {
	t.Parallel()

	r := &runner{
		opts: options{
			secretSpecs: []secretSpec{
				{Key: "API_TOKEN", Value: "secret"},
			},
		},
		cfg: config{
			listenCfg: listen.Config{
				Disable: true,
			},
		},
	}

	if err := r.registerSecrets(context.Background()); err == nil {
		t.Fatal("expected error when listen is disabled")
	}
}

func listenConfigFromURL(t *testing.T, raw string) listen.Config {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	host = strings.Trim(host, "[]")
	return listen.Config{
		Host:    host,
		Port:    port,
		Disable: false,
	}
}

func TestSecretEnvDockerArgs(t *testing.T) {
	t.Parallel()

	r := &runner{
		secretPlaceholders: map[string]string{
			"FOO":   "foo_ph",
			"BAR":   "bar_ph",
			"EMPTY": "",
		},
	}

	args := r.secretEnvDockerArgs()
	want := []string{
		"-e", "BAR=bar_ph",
		"-e", "FOO=foo_ph",
	}

	if len(args) != len(want) {
		t.Fatalf("unexpected arg count: got %d want %d", len(args), len(want))
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg %d mismatch: got %q want %q", i, args[i], want[i])
		}
	}
}

func TestSecretEnvScript(t *testing.T) {
	t.Parallel()

	r := &runner{
		secretPlaceholders: map[string]string{
			"FOO": "foo_ph",
			"BAR": "bar_ph",
		},
	}

	script := r.secretEnvScript()
	const want = "export ENV=/etc/ksh.kshrc\nexport BAR=bar_ph\nexport FOO=foo_ph\n"
	if script != want {
		t.Fatalf("unexpected env script:\nwant:\n%s\ngot:\n%s", want, script)
	}

	r.secretPlaceholders = nil
	if script := r.secretEnvScript(); script != "export ENV=/etc/ksh.kshrc\n" {
		t.Fatalf("expected base script for empty placeholders, got %q", script)
	}
}
