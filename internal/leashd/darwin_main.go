//go:build darwin

package leashd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/httpserver"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/proxy"
	"github.com/strongdm/leash/internal/ui"
	websockethub "github.com/strongdm/leash/internal/websocket"
)

// MainDarwin launches a lightweight runtime that serves the Control UI and
// policy APIs locally on macOS without kernel hooks or container prerequisites.
func MainDarwin(args []string) error {
	if len(args) == 0 {
		args = os.Args
	}

	name := commandName(args)
	fs := flag.NewFlagSet(name+" darwin", flag.ContinueOnError)

	defaultLog := strings.TrimSpace(os.Getenv("LEASH_LOG"))
	logPath := fs.String("log", defaultLog, "Event log file path (optional)")

	defaultPolicy := strings.TrimSpace(os.Getenv("LEASH_POLICY"))
	if defaultPolicy == "" {
		defaultPolicy = filepath.Join(".", "leash.cedar")
	}
	policyPath := fs.String("policy", defaultPolicy, "Cedar policy file path")

	defaultServe := strings.TrimSpace(os.Getenv("LEASH_LISTEN"))
	if defaultServe == "" {
		defaultServe = ":18080"
	}
	serveAddr := fs.String("serve", defaultServe, "Serve Control UI and API on bind address (e.g. :18080)")

	historySize := fs.Int("history-size", 25000, "Number of events to keep in memory for new connections")
	bulkMaxEvents := fs.Int("ws-bulk-max-events", 2000, "Max events to include in initial WebSocket bulk message (0 = unlimited)")
	bulkMaxBytes := fs.Int("ws-bulk-max-bytes", 1_000_000, "Max bytes to include in initial WebSocket bulk message (0 = unlimited)")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s darwin [flags]\n\nFlags:\n", name)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(fs.Args()) > 0 {
		return fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}

	if err := policy.EnsureDefaultCedarFile(strings.TrimSpace(*policyPath)); err != nil {
		return err
	}

	cfg, err := policy.Parse(strings.TrimSpace(*policyPath))
	if err != nil {
		var detail *cedarutil.ErrorDetail
		if errors.As(err, &detail) {
			return errors.New(formatCedarErrorForCLI(detail))
		}
		return fmt.Errorf("failed to parse Cedar policy: %w", err)
	}

	logger, err := lsm.NewSharedLogger(strings.TrimSpace(*logPath))
	if err != nil {
		return err
	}
	defer logger.Close()

	wsHub := websockethub.NewWebSocketHub(logger, *historySize, *bulkMaxEvents, *bulkMaxBytes)
	go wsHub.Run()
	logger.SetBroadcaster(wsHub)

	headerRewriter := proxy.NewHeaderRewriter()
	headerRewriter.SetSharedLogger(logger)

	policyManager := policy.NewManager(nil, func(_ *lsm.PolicySet, httpRules []proxy.HeaderRewriteRule) {
		headerRewriter.SetRules(httpRules)
	})

	if err := policyManager.UpdateFileRules(cfg.LSMPolicies, cfg.HTTPRewrites); err != nil {
		return fmt.Errorf("failed to load file policies: %w", err)
	}
	headerRewriter.SetRules(cfg.HTTPRewrites)

	var policyReady atomic.Bool
	policyReady.Store(true)

	if err := serveDarwinHTTP(
		wsHub,
		policyManager,
		headerRewriter,
		strings.TrimSpace(*policyPath),
		strings.TrimSpace(*serveAddr),
		&policyReady,
	); err != nil {
		return err
	}

	return nil
}

func serveDarwinHTTP(
	wsHub *websockethub.WebSocketHub,
	policyManager *policy.Manager,
	headerRewriter *proxy.HeaderRewriter,
	policyPath string,
	bind string,
	policyReady *atomic.Bool,
) error {
	uiFS, err := fs.Sub(ui.Dir, "dist")
	if err != nil {
		return fmt.Errorf("failed to load embedded UI: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api", wsHub.HandleWebSocket)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/health/policy", func(w http.ResponseWriter, r *http.Request) {
		if !policyReady.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.Handle("/", ui.NewSPAHandler(http.FS(uiFS)))

	api := newPolicyAPI(policyManager, policyPath, wsHub)
	api.register(mux)

	suggest := newSuggestAPI(policyManager, wsHub)
	suggest.register(mux)

	server := httpserver.NewWebServer(bind, mux)

	errCh := make(chan error, 1)
	go func(addr string, srv *http.Server) {
		logPolicyEvent("frontend.start", map[string]any{"addr": addr})
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}(bind, server)

	cancelWatch, err := policy.WatchCedar(policyPath, time.Second, func(newCfg *policy.Config) {
		if err := policyManager.UpdateFileRules(newCfg.LSMPolicies, newCfg.HTTPRewrites); err != nil {
			logPolicyEvent("policy.update", map[string]any{"source": "file", "error": err.Error()})
			return
		}
		headerRewriter.SetRules(newCfg.HTTPRewrites)
		logPolicyEvent("policy.update", map[string]any{
			"source":        "file",
			"lsm_open":      len(newCfg.LSMPolicies.Open),
			"lsm_exec":      len(newCfg.LSMPolicies.Exec),
			"lsm_connect":   len(newCfg.LSMPolicies.Connect),
			"http_rewrites": len(newCfg.HTTPRewrites),
		})
		policyReady.Store(true)
	}, func(detail *cedarutil.ErrorDetail) {
		if detail == nil {
			return
		}
		policyReady.Store(false)
		logPolicyEvent("policy.update", map[string]any{
			"source":     "file",
			"error":      detail.Message,
			"line":       detail.Line,
			"column":     detail.Column,
			"code":       detail.Code,
			"suggestion": detail.Suggestion,
		})
	})
	if err != nil {
		return fmt.Errorf("failed to watch Cedar policy file: %w", err)
	}
	defer func() {
		if cancelWatch != nil {
			cancelWatch()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	var shutdownErr error
	select {
	case err := <-errCh:
		shutdownErr = err
	case sig := <-sigCh:
		logPolicyEvent("shutdown.signal", map[string]any{"signal": sig.String()})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("graceful shutdown failed: %v", err)
	}

	if shutdownErr != nil {
		return shutdownErr
	}
	return nil
}
