//go:build darwin

package darwind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/strongdm/leash/internal/assets"
	cedarutil "github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/httpserver"
	"github.com/strongdm/leash/internal/leashd/listen"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/macsync"
	"github.com/strongdm/leash/internal/messages"
	"github.com/strongdm/leash/internal/openflag"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/proxy"
	"github.com/strongdm/leash/internal/telemetry/statsig"
	"github.com/strongdm/leash/internal/ui"
	websockethub "github.com/strongdm/leash/internal/websocket"
)

// logPolicyEvent emits compact structured event logs: event=<name> key=value ...
func logPolicyEvent(event string, fields map[string]any) {
	buf := "event=" + event
	for k, v := range fields {
		buf += " " + k + "=" + fmt.Sprint(v)
	}
	log.Printf(buf)
	if event == "policy.update" {
		statsig.RecordPolicyUpdate(fields)
	}
}

type runtimeConfig struct {
	LogPath         string
	PolicyPath      string
	ProxyPort       string
	WebBind         string
	HistorySize     int
	CgroupPath      string
	SkipCgroup      bool
	AllowLSMFailure bool
	OpenBrowser     bool
}

type runtimeState struct {
	cfg               *runtimeConfig
	logger            *lsm.SharedLogger
	wsHub             *websockethub.WebSocketHub
	headerRewriter    *proxy.HeaderRewriter
	mitmProxy         *proxy.MITMProxy
	lsmManager        *lsm.LSMManager
	policyManager     *policy.Manager
	macSync           *macsync.Manager
	policyWatcherStop func()
	policyReady       atomic.Bool
	closeOnce         sync.Once
}

// main starts the sidecar runtime with the provided configuration.
func Main(args []string) error {
	if len(args) > 0 && args[0] == "exec" {
		return runExec(args[1:])
	}
	if len(args) > 0 && args[0] == "stop" {
		return stopManagedExecServer()
	}

	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}

	sessionID := strings.TrimSpace(os.Getenv("LEASH_SESSION_ID"))
	workspaceHash := strings.TrimSpace(os.Getenv("LEASH_WORKSPACE_HASH"))
	statsig.Start(context.Background(), statsig.StartPayload{
		Mode:        "darwin",
		SessionID:   sessionID,
		WorkspaceID: workspaceHash,
	})
	defer statsig.Stop(context.Background())

	if err := preFlight(cfg); err != nil {
		return err
	}

	rt, err := initRuntime(cfg)
	if err != nil {
		return err
	}
	defer rt.Close()

	return rt.Run()
}

const defaultLeashCLIPath = "/Applications/Leash.app/Contents/Resources/leashcli"

func runExec(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("command required")
	}

	cliPath, passthrough, err := parseExecCLIArgs(args)
	if err != nil {
		return err
	}

	if _, err := os.Stat(cliPath); err != nil {
		if isExecHelpRequest(passthrough) {
			printExecHelp()
			return nil
		}
		return fmt.Errorf("leashcli not found at %q: %w", cliPath, err)
	}

	handle, err := acquireExecServer()
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := handle.Release(); releaseErr != nil {
			log.Printf("failed to release darwin exec server: %v", releaseErr)
		}
	}()

	cmd := exec.Command(cliPath, passthrough...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func parseExecCLIArgs(args []string) (string, []string, error) {
	cliPath := defaultLeashCLIPath
	passthrough := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--leash-cli-path":
			i++
			if i >= len(args) {
				return "", nil, fmt.Errorf("--leash-cli-path requires a value")
			}
			value := strings.TrimSpace(args[i])
			if value == "" {
				return "", nil, fmt.Errorf("--leash-cli-path requires a value")
			}
			cliPath = value
		case strings.HasPrefix(arg, "--leash-cli-path="):
			value := strings.TrimSpace(strings.TrimPrefix(arg, "--leash-cli-path="))
			if value == "" {
				return "", nil, fmt.Errorf("--leash-cli-path requires a value")
			}
			cliPath = value
		default:
			passthrough = append(passthrough, arg)
		}
	}

	return cliPath, passthrough, nil
}

func isExecHelpRequest(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			continue
		}
		switch arg {
		case "--help", "-h", "help":
			return true
		default:
			return false
		}
	}
	return false
}

func printExecHelp() {
	fmt.Fprintln(os.Stdout, "Usage: leash --darwin exec [--leash-cli-path path] [--] <command> [args...]")
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "  --leash-cli-path PATH   Override the default /Applications/Leash.app/Contents/Resources/leashcli binary")
	fmt.Fprintln(os.Stdout, "                          when launching the companion leashcli executable.")
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "When no override is supplied, leash expects the macOS app bundle to be installed at")
	fmt.Fprintln(os.Stdout, "  /Applications/Leash.app/Contents/Resources/leashcli")
	fmt.Fprintln(os.Stdout, "Use --leash-cli-path to point at a locally built leashcli binary if the app bundle is not present.")
}

// parseConfig reads CLI flags and environment hints to build the runtime configuration.
func parseConfig(args []string) (*runtimeConfig, error) {
	fs := flag.NewFlagSet("leash darwin", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	defaultLogPath := strings.TrimSpace(os.Getenv("LEASH_LOG"))
	logPath := fs.String("log", defaultLogPath, "Event log file path (optional)")

	defaultPolicyPath := strings.TrimSpace(os.Getenv("LEASH_POLICY"))
	if defaultPolicyPath == "" {
		defaultPolicyPath = "/tmp/tmp.leash.policy"
	}
	policyPath := fs.String("policy", defaultPolicyPath, "Policy file path")

	proxyPort := fs.String("proxy-port", "18000", "Proxy port")
	wsPort := fs.String("ws-port", "18080", "WebSocket server port")

	serveAddr := fs.String("serve", "", "Serve Control UI and API on bind address (e.g. :18080, 0.0.0.0:8127)")
	openDefault := openflag.Enabled()
	openBrowser := openDefault
	fs.BoolVar(&openBrowser, "open", openDefault, "Open Control UI in default browser after startup")
	fs.BoolVar(&openBrowser, "o", openDefault, "Open Control UI in default browser after startup (shorthand)")

	historySize := fs.Int("history-size", 10000, "Number of events to keep in memory for new connections")
	cgroupFlag := fs.String("cgroup", "", "Cgroup path to monitor")
	allowLSMEnv := strings.TrimSpace(os.Getenv("LEASH_ALLOW_LSM_FAILURE"))
	allowLSMDefault := envTruthy(allowLSMEnv)
	allowLSMFailure := fs.Bool(
		"allow-lsm-failure",
		allowLSMDefault,
		"Skip exiting when kernel LSM attachment fails (handy on Docker Desktop macOS/Windows where eBPF LSM isn’t available)",
	)
	skipCgroupCheck := fs.Bool(
		"skip-cgroup",
		true,
		"Skip cgroup requirement (macOS developer mode; disables kernel enforcement)",
	)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: leash darwin [flags]\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if len(fs.Args()) > 0 {
		return nil, fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}

	uiBind := strings.TrimSpace(*serveAddr)
	wsDefault := strings.TrimSpace(*wsPort)
	if uiBind == "" {
		if wsDefault == "" {
			wsDefault = "18080"
		}
		uiBind = ":" + wsDefault
	} else if strings.Count(uiBind, ":") == 0 && !strings.HasPrefix(uiBind, "[") {
		uiBind = ":" + uiBind
	}

	cfg := &runtimeConfig{
		LogPath:         strings.TrimSpace(*logPath),
		PolicyPath:      strings.TrimSpace(*policyPath),
		ProxyPort:       strings.TrimSpace(*proxyPort),
		WebBind:         uiBind,
		HistorySize:     *historySize,
		CgroupPath:      strings.TrimSpace(*cgroupFlag),
		SkipCgroup:      *skipCgroupCheck,
		AllowLSMFailure: *allowLSMFailure,
		OpenBrowser:     openBrowser,
	}

	if cfg.SkipCgroup && runtime.GOOS != "linux" {
		cfg.AllowLSMFailure = true
	}

	return cfg, nil
}

func preFlight(cfg *runtimeConfig) error {
	if cfg == nil {
		return fmt.Errorf("runtime configuration required")
	}
	policyPath := strings.TrimSpace(cfg.PolicyPath)
	if policyPath == "" {
		return fmt.Errorf("policy file path required")
	}
	if err := policy.EnsureDefaultCedarFile(policyPath); err != nil {
		return err
	}
	if _, err := policy.Parse(policyPath); err != nil {
		var detail *cedarutil.ErrorDetail
		if errors.As(err, &detail) {
			return errors.New(formatCedarErrorForCLI(detail))
		}
		return fmt.Errorf("failed to parse policy file: %w", err)
	}

	if !cfg.SkipCgroup {
		if strings.TrimSpace(cfg.CgroupPath) == "" {
			return fmt.Errorf("cgroup path required (set --cgroup)")
		}
		info, err := os.Stat(cfg.CgroupPath)
		if err != nil {
			return fmt.Errorf("invalid cgroup path %q: %w", cfg.CgroupPath, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("invalid cgroup path %q: not a directory", cfg.CgroupPath)
		}
		controllersPath := filepath.Join(cfg.CgroupPath, "cgroup.controllers")
		if _, err := os.Stat(controllersPath); err != nil {
			return fmt.Errorf("invalid cgroup path %q: %v", cfg.CgroupPath, err)
		}
	} else {
		cfg.AllowLSMFailure = true
	}

	logPath := strings.TrimSpace(cfg.LogPath)
	if logPath != "" {
		dir := filepath.Dir(logPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create log directory %q: %w", dir, err)
			}
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("failed to access log file %q: %w", logPath, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close log file %q: %w", logPath, err)
		}
	}

	if !cfg.SkipCgroup {
		if strings.TrimSpace(cfg.ProxyPort) == "" {
			cfg.ProxyPort = "18000"
		}
		port, err := strconv.Atoi(cfg.ProxyPort)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid proxy port %q", cfg.ProxyPort)
		}
		if runtime.GOOS == "linux" {
			if _, err := exec.LookPath("mount"); err != nil {
				return fmt.Errorf("mount command not found: %w", err)
			}
			if _, err := findIptables(); err != nil {
				return err
			}
		}
	}

	publicDir := strings.TrimSpace(os.Getenv("LEASH_DIR"))
	if publicDir == "" {
		publicDir = filepath.Join(os.TempDir(), "leash")
		if err := os.Setenv("LEASH_DIR", publicDir); err != nil {
			return fmt.Errorf("set LEASH_DIR: %w", err)
		}
	}
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		return fmt.Errorf("prepare LEASH_DIR %q: %w", publicDir, err)
	}
	if info, err := os.Stat(publicDir); err != nil {
		return fmt.Errorf("inspect LEASH_DIR %q: %w", publicDir, err)
	} else if !info.IsDir() {
		return fmt.Errorf("LEASH_DIR %q is not a directory", publicDir)
	} else if perm := info.Mode().Perm(); perm != 0o755 {
		if err := os.Chmod(publicDir, 0o755); err != nil {
			return fmt.Errorf("enforce LEASH_DIR permissions for %q: %w", publicDir, err)
		}
		log.Printf("event=darwin.public-dir.permissions.adjust path=%q previous=%04o new=0755", publicDir, perm)
	}

	privateDir := strings.TrimSpace(os.Getenv("LEASH_PRIVATE_DIR"))
	if privateDir == "" {
		privateDir = filepath.Join(publicDir, "private")
		if err := os.Setenv("LEASH_PRIVATE_DIR", privateDir); err != nil {
			return fmt.Errorf("set LEASH_PRIVATE_DIR: %w", err)
		}
	}
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		return fmt.Errorf("prepare LEASH_PRIVATE_DIR %q: %w", privateDir, err)
	}
	info, err := os.Stat(privateDir)
	if err != nil {
		return fmt.Errorf("inspect LEASH_PRIVATE_DIR %q: %w", privateDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("LEASH_PRIVATE_DIR %q is not a directory", privateDir)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		if err := os.Chmod(privateDir, 0o700); err != nil {
			return fmt.Errorf("enforce LEASH_PRIVATE_DIR permissions for %q: %w", privateDir, err)
		}
		log.Printf("event=darwin.private-dir.permissions.adjust path=%q previous=%04o new=0700", privateDir, perm)
	}

	keyPath := filepath.Join(privateDir, "ca-key.pem")
	if keyInfo, err := os.Stat(keyPath); err == nil {
		if keyInfo.IsDir() {
			return fmt.Errorf("LEASH_PRIVATE_DIR key path %q is a directory", keyPath)
		}
		if perm := keyInfo.Mode().Perm(); perm != 0o600 {
			if err := os.Chmod(keyPath, 0o600); err != nil {
				return fmt.Errorf("enforce CA key permissions for %q: %w", keyPath, err)
			}
			log.Printf("event=darwin.private-key.permissions.adjust path=%q previous=%04o new=0600", keyPath, perm)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect CA key at %q: %w", keyPath, err)
	}

	return nil
}

func initRuntime(cfg *runtimeConfig) (*runtimeState, error) {
	if _, err := os.Stat(cfg.PolicyPath); err != nil {
		return nil, fmt.Errorf("policy file required: %w", err)
	}

	logger, err := lsm.NewSharedLogger(cfg.LogPath)
	if err != nil {
		return nil, err
	}

	macSync := macsync.NewManager(logger)

	wsHub := websockethub.NewWebSocketHub(logger, cfg.HistorySize, 0, 0)
	go wsHub.Run()
	logger.SetBroadcaster(wsHub)

	var lsmManager *lsm.LSMManager
	if !cfg.SkipCgroup {
		lsmManager = lsm.NewLSMManager(cfg.CgroupPath, logger)
		lsm.BumpMemlockRlimit()
	} else {
		logPolicyEvent("runtime.mode", map[string]any{
			"skip_cgroup": true,
			"os":          runtime.GOOS,
		})
	}

	headerRewriter := proxy.NewHeaderRewriter()
	headerRewriter.SetSharedLogger(logger)

	initialPolicy, err := policy.Parse(cfg.PolicyPath)
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	connectRules := lsm.ConvertToConnectRules(initialPolicy.LSMPolicies.Connect)
	defaultAllow := connectDefaultAllow(initialPolicy.LSMPolicies)
	policyChecker := lsm.NewSimplePolicyChecker(connectRules, defaultAllow, initialPolicy.LSMPolicies.MCP)

	var mitmProxy *proxy.MITMProxy
	if !cfg.SkipCgroup {
		mitmProxy, err = proxy.NewMITMProxy(cfg.ProxyPort, headerRewriter, policyChecker, logger, proxy.MCPConfig{})
		if err != nil {
			logger.Close()
			return nil, fmt.Errorf("failed to create MITM proxy: %w", err)
		}
	} else {
		logPolicyEvent("proxy.mode", map[string]any{"status": "disabled", "reason": "skip-cgroup"})
	}

	state := &runtimeState{
		cfg:            cfg,
		logger:         logger,
		wsHub:          wsHub,
		headerRewriter: headerRewriter,
		mitmProxy:      mitmProxy,
		lsmManager:     lsmManager,
		macSync:        macSync,
	}

	policyManager := policy.NewManager(lsmManager, func(rules *lsm.PolicySet, httpRules []proxy.HeaderRewriteRule) {
		state.headerRewriter.SetRules(httpRules)
		if state.mitmProxy != nil {
			applyPolicyToProxy(state.mitmProxy, rules)
		}
	})

	if err := policyManager.UpdateFileRules(initialPolicy.LSMPolicies, initialPolicy.HTTPRewrites); err != nil {
		state.Close()
		return nil, fmt.Errorf("failed to load file policies: %w", err)
	}
	headerRewriter.SetRules(initialPolicy.HTTPRewrites)
	if mitmProxy != nil {
		applyPolicyToProxy(mitmProxy, initialPolicy.LSMPolicies)
	}
	state.policyManager = policyManager

	state.syncMacPoliciesFrom(initialPolicy.LSMPolicies)

	logPolicyEvent("policy.restore", map[string]any{
		"source":        "file",
		"lsm_open":      len(initialPolicy.LSMPolicies.Open),
		"lsm_exec":      len(initialPolicy.LSMPolicies.Exec),
		"lsm_connect":   len(initialPolicy.LSMPolicies.Connect),
		"http_rewrites": len(initialPolicy.HTTPRewrites),
	})

	state.policyReady.Store(true)
	state.startClientMessageLoop()

	return state, nil
}

func (rt *runtimeState) Run() error {
	if err := rt.startFrontend(); err != nil {
		return err
	}

	rt.openControlUI()

	if err := rt.startPolicyWatcher(); err != nil {
		return err
	}

	if err := rt.configureNetwork(); err != nil {
		return err
	}

	if rt.mitmProxy != nil {
		go func() {
			if err := rt.mitmProxy.Run(); err != nil {
				log.Fatal(err)
			}
		}()
	}

	if rt.lsmManager == nil {
		logPolicyEvent("lsm.start", map[string]any{"status": "skipped", "reason": "skip-cgroup"})
		log.Printf("LSM manager disabled (skip-cgroup); operating in proxy-only mode")
		waitForShutdown()
		return nil
	}

	// Docker Desktop (macOS/Windows) runs containers inside a LinuxKit VM that lacks
	// the kernel features/capabilities required for eBPF LSM attachment. In that
	// environment the connect/exec/open LSM programs always fail to load. We allow
	// callers to opt into a degraded developer mode so the rest of the runtime/UI
	// can still function for UI/policy iteration, while emitting clear telemetry.
	err := rt.lsmManager.LoadAndStart()
	if err != nil {
		if rt.cfg.AllowLSMFailure {
			logPolicyEvent("lsm.start", map[string]any{"status": "skipped", "error": err.Error()})
			log.Printf("LSM initialization failed (continuing due to allow-lsm-failure): %v", err)
			waitForShutdown()
			return nil
		}
		return err
	}
	return nil
}

func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
}

func (rt *runtimeState) Close() {
	rt.closeOnce.Do(func() {
		if rt.policyWatcherStop != nil {
			rt.policyWatcherStop()
		}
		if rt.logger != nil {
			_ = rt.logger.Close()
		}
	})
}

func (rt *runtimeState) startFrontend() error {
	uiFS, err := fs.Sub(ui.Dir, "dist")
	if err != nil {
		return fmt.Errorf("failed to load embedded UI: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api", rt.wsHub.HandleWebSocket)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/health/policy", func(w http.ResponseWriter, r *http.Request) {
		if !rt.policyReady.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	title := ui.ComposeTitle(os.Getenv("LEASH_PROJECT"), os.Getenv("LEASH_COMMAND"))
	mux.Handle("/", ui.NewSPAHandlerWithTitle(http.FS(uiFS), title))

	api := newPolicyAPI(rt.policyManager, rt.cfg.PolicyPath, rt.wsHub, rt.mitmProxy, rt.wsHub)
	api.register(mux)

	server := httpserver.NewWebServer(rt.cfg.WebBind, mux)

	go func(addr string, srv *http.Server) {
		logPolicyEvent("frontend.start", map[string]any{"addr": addr})
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("web server failed: %v", err)
		}
	}(rt.cfg.WebBind, server)

	return nil
}

func (rt *runtimeState) openControlUI() {
	if !rt.cfg.OpenBrowser {
		return
	}

	cfg, err := listen.Parse(rt.cfg.WebBind)
	if err != nil {
		log.Printf("Failed to parse Control UI address for --open: %v", err)
		return
	}
	if cfg.Disable {
		log.Printf("Control UI disabled; skipping --open request")
		return
	}

	if err := listen.OpenURL(cfg.DisplayURL()); err != nil {
		log.Printf("Failed to open Control UI in browser: %v", err)
	}
}

func (rt *runtimeState) startPolicyWatcher() error {
	cancel, err := policy.WatchCedar(rt.cfg.PolicyPath, time.Second, func(newCfg *policy.Config) {
		if err := rt.policyManager.UpdateFileRules(newCfg.LSMPolicies, newCfg.HTTPRewrites); err != nil {
			logPolicyEvent("policy.update", map[string]any{"source": "file", "error": err.Error()})
			return
		}
		logPolicyEvent("policy.update", map[string]any{
			"source":        "file",
			"lsm_open":      len(newCfg.LSMPolicies.Open),
			"lsm_exec":      len(newCfg.LSMPolicies.Exec),
			"lsm_connect":   len(newCfg.LSMPolicies.Connect),
			"http_rewrites": len(newCfg.HTTPRewrites),
		})
		rt.syncMacPoliciesFrom(newCfg.LSMPolicies)
		rt.policyReady.Store(true)
	}, func(detail *cedarutil.ErrorDetail) {
		if detail == nil {
			return
		}
		rt.policyReady.Store(false)
		logPolicyEvent("policy.update", map[string]any{
			"source":     "file",
			"error":      detail.Message,
			"line":       detail.Line,
			"column":     detail.Column,
			"code":       detail.Code,
			"suggestion": detail.Suggestion,
		})
		log.Printf("%s", formatCedarErrorForCLI(detail))
	})
	if err != nil {
		return fmt.Errorf("failed to watch Cedar policy file: %w", err)
	}
	rt.policyWatcherStop = cancel
	return nil
}

func (rt *runtimeState) configureNetwork() error {
	if rt.cfg.SkipCgroup || runtime.GOOS != "linux" {
		log.Printf("iptables configuration skipped (skip-cgroup=%v os=%s)", rt.cfg.SkipCgroup, runtime.GOOS)
		return nil
	}

	fmt.Fprintf(os.Stderr, "leash: applying iptables rules\n")
	if err := applyIptablesRules(rt.cfg.ProxyPort); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "leash: mounting tracefs\n")
	tracefs := exec.Command("mount", "-t", "tracefs", "tracefs", "/sys/kernel/tracing")
	tracefs.Stdout = os.Stdout
	tracefs.Stderr = os.Stderr
	if err := tracefs.Run(); err != nil {
		log.Printf("Warning: Failed to mount tracefs: %v", err)
	}
	return nil
}

func connectDefaultAllow(policies *lsm.PolicySet) bool {
	if policies == nil {
		return false
	}
	return policies.ConnectDefaultAllow
}

func applyPolicyToProxy(mitmproxy *proxy.MITMProxy, rules *lsm.PolicySet) {
	if mitmproxy == nil || rules == nil {
		return
	}
	connectRules := lsm.ConvertToConnectRules(rules.Connect)
	defaultAllow := connectDefaultAllow(rules)
	mitmproxy.SetPolicyChecker(lsm.NewSimplePolicyChecker(connectRules, defaultAllow, rules.MCP))
}

func (rt *runtimeState) startClientMessageLoop() {
	if rt.wsHub == nil {
		return
	}
	go func() {
		for msg := range rt.wsHub.Incoming() {
			rt.handleClientMessage(msg.ClientID, msg.Payload)
		}
	}()
}

func (rt *runtimeState) handleClientMessage(clientID string, payload []byte) {
	chunks := bytes.Split(payload, []byte{'\n'})
	for _, raw := range chunks {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}

		var env messages.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			log.Printf("macsync: failed to decode envelope from %s: %v", clientID, err)
			rt.sendAck(clientID, nil, "error", "invalid envelope")
			continue
		}

		rt.dispatchClientEnvelope(clientID, &env)
	}
}

func (rt *runtimeState) dispatchClientEnvelope(clientID string, env *messages.Envelope) {
	switch env.Type {
	case messages.TypeClientHello:
		var hello messages.ClientHelloPayload
		if err := messages.UnmarshalPayload(env, &hello); err != nil {
			log.Printf("macsync: invalid client hello from %s: %v", clientID, err)
			rt.sendAck(clientID, env, "error", "invalid client hello")
			return
		}
		if rt.macSync != nil {
			rt.macSync.RegisterClient(clientID, &hello)
		}
		rt.pushMacStateToClient(clientID)
		rt.sendAck(clientID, env, "ok", "hello received")

	case messages.TypeMacPIDSync:
		var pidPayload messages.MacPIDSyncPayload
		if err := messages.UnmarshalPayload(env, &pidPayload); err != nil {
			log.Printf("macsync: invalid pid sync from %s: %v", clientID, err)
			rt.sendAck(clientID, env, "error", "invalid pid payload")
			return
		}
		if rt.macSync != nil {
			tracked := rt.macSync.UpdateTrackedPIDs(clientID, &pidPayload)
			logPolicyEvent("mac.pid.sync", map[string]any{
				"client":        clientID,
				"entries":       len(pidPayload.Entries),
				"tracked_total": len(tracked),
			})
			// Broadcast PID update to all clients (especially network filter)
			rt.broadcastPIDUpdate(tracked)
		}
		rt.sendAck(clientID, env, "ok", fmt.Sprintf("pids=%d", len(pidPayload.Entries)))

	case messages.TypeMacRuleSync:
		var rulesPayload messages.MacRuleSyncPayload
		if err := messages.UnmarshalPayload(env, &rulesPayload); err != nil {
			log.Printf("macsync: invalid rule sync from %s: %v", clientID, err)
			rt.sendAck(clientID, env, "error", "invalid rule payload")
			return
		}
		if rt.macSync != nil {
			snapshot := rt.macSync.UpdateRules(clientID, &rulesPayload)
			logPolicyEvent("mac.rule.sync", map[string]any{
				"client":        clientID,
				"file_rules":    len(snapshot.FileRules),
				"exec_rules":    len(snapshot.ExecRules),
				"network_rules": len(snapshot.NetworkRules),
				"version":       snapshot.Version,
			})
		}
		rt.sendAck(clientID, env, "ok", "rules updated")

	case messages.TypeMacEvent:
		var evt messages.MacEventPayload
		if err := messages.UnmarshalPayload(env, &evt); err != nil {
			log.Printf("macsync: invalid event payload from %s: %v", clientID, err)
			rt.sendAck(clientID, env, "error", "invalid event payload")
			return
		}
		if rt.macSync != nil {
			if err := rt.macSync.LogMacEvent(&evt); err != nil {
				log.Printf("macsync: failed to log mac event: %v", err)
			}
		}
		rt.sendAck(clientID, env, "ok", "event logged")

	case messages.TypeEvent:
		var evt messages.EventPayload
		if err := messages.UnmarshalPayload(env, &evt); err != nil {
			log.Printf("macsync: invalid generic event payload from %s: %v", clientID, err)
			rt.sendAck(clientID, env, "error", "invalid event payload")
			return
		}
		logPolicyEvent("mac.event", map[string]any{
			"client": clientID,
			"event":  evt.Event,
			"ts":     evt.TS,
			"rule":   evt.RuleID,
		})
		rt.sendAck(clientID, env, "ok", "event received")

	case messages.TypeMacPolicyEvent:
		var evt messages.MacPolicyEventPayload
		if err := messages.UnmarshalPayload(env, &evt); err != nil {
			log.Printf("macsync: invalid policy event from %s: %v", clientID, err)
			rt.sendResponse(clientID, env, "error", "invalid policy event", nil)
			return
		}
		if rt.macSync != nil {
			rt.macSync.StorePolicyEvent(&evt)
		}
		rt.sendResponse(clientID, env, "ok", "policy event stored", map[string]any{"success": true})

	case messages.TypeMacPolicyDecision:
		var decision messages.MacPolicyDecisionPayload
		if err := messages.UnmarshalPayload(env, &decision); err != nil {
			log.Printf("macsync: invalid policy decision from %s: %v", clientID, err)
			rt.sendResponse(clientID, env, "error", "invalid policy decision", nil)
			return
		}
		if rt.macSync != nil {
			if err := rt.macSync.ProcessPolicyDecision(&decision); err != nil {
				log.Printf("macsync: failed to process policy decision: %v", err)
				rt.sendResponse(clientID, env, "error", err.Error(), nil)
				return
			}
			// Broadcast rule update to all clients
			rt.broadcastRuleUpdate()
		}
		rt.sendResponse(clientID, env, "ok", "decision processed", map[string]any{"success": true})

	case messages.TypeMacRuleQuery:
		if rt.macSync == nil {
			rt.sendResponse(clientID, env, "error", "macsync not available", nil)
			return
		}
		rules := rt.macSync.GetPolicyRules()
		rt.sendResponse(clientID, env, "ok", "rules retrieved", map[string]any{"rules": rules})

	case messages.TypeMacRuleAdd:
		var payload messages.MacRuleAddPayload
		if err := messages.UnmarshalPayload(env, &payload); err != nil {
			log.Printf("macsync: invalid rule add from %s: %v", clientID, err)
			rt.sendResponse(clientID, env, "error", "invalid rule add payload", nil)
			return
		}
		if rt.macSync != nil {
			rt.macSync.AddPolicyRules(payload.Rules)
			rt.broadcastRuleUpdate()
		}
		rt.sendResponse(clientID, env, "ok", fmt.Sprintf("added %d rules", len(payload.Rules)), map[string]any{"success": true})

	case messages.TypeMacRuleRemove:
		var payload messages.MacRuleRemovePayload
		if err := messages.UnmarshalPayload(env, &payload); err != nil {
			log.Printf("macsync: invalid rule remove from %s: %v", clientID, err)
			rt.sendResponse(clientID, env, "error", "invalid rule remove payload", nil)
			return
		}
		if rt.macSync != nil {
			rt.macSync.RemovePolicyRules(payload.IDs)
			rt.broadcastRuleUpdate()
		}
		rt.sendResponse(clientID, env, "ok", fmt.Sprintf("removed %d rules", len(payload.IDs)), map[string]any{"success": true})

	case messages.TypeMacRuleClear:
		if rt.macSync != nil {
			rt.macSync.ClearPolicyRules()
			rt.broadcastRuleUpdate()
		}
		rt.sendResponse(clientID, env, "ok", "all rules cleared", map[string]any{"success": true})

	case messages.TypeMacNetworkRuleQuery:
		if rt.macSync == nil {
			rt.sendResponse(clientID, env, "error", "macsync not available", nil)
			return
		}
		rules := rt.macSync.GetNetworkRules()
		rt.sendResponse(clientID, env, "ok", "network rules retrieved", map[string]any{"rules": rules})

	case messages.TypeMacNetworkRuleUpdate:
		var payload messages.MacNetworkRuleUpdatePayload
		if err := messages.UnmarshalPayload(env, &payload); err != nil {
			log.Printf("macsync: invalid network rule update from %s: %v", clientID, err)
			rt.sendResponse(clientID, env, "error", "invalid network rule payload", nil)
			return
		}
		if rt.macSync != nil {
			rt.macSync.UpdateNetworkRules(payload.Rules)
			rt.broadcastNetworkRuleUpdate()
		}
		rt.sendResponse(clientID, env, "ok", fmt.Sprintf("updated %d network rules", len(payload.Rules)), map[string]any{"success": true})

	case messages.TypeMacMITMConfig:
		var cfg messages.MacMITMConfigPayload
		if err := messages.UnmarshalPayload(env, &cfg); err != nil {
			log.Printf("macsync: invalid mitm config from %s: %v", clientID, err)
			rt.sendResponse(clientID, env, "error", "invalid mitm config payload", nil)
			return
		}
		if rt.macSync != nil {
			rt.macSync.SetMITMConfig(&cfg)
			rt.broadcastMITMConfig(&cfg)
		}
		rt.sendResponse(clientID, env, "ok", "mitm config updated", map[string]any{"success": true})

	case messages.TypeMacMITMSession:
		var sess messages.MacMITMSessionPayload
		if err := messages.UnmarshalPayload(env, &sess); err != nil {
			log.Printf("macsync: invalid mitm session from %s: %v", clientID, err)
			rt.sendResponse(clientID, env, "error", "invalid mitm session payload", nil)
			return
		}
		if rt.macSync != nil {
			rt.macSync.UpsertMITMSession(sess)
			rt.broadcastMITMSession(&sess)
		}
		rt.sendResponse(clientID, env, "ok", "mitm session processed", map[string]any{"success": true})

	case messages.TypeMacMITMTelemetry:
		var telem messages.MacMITMTelemetryPayload
		if err := messages.UnmarshalPayload(env, &telem); err != nil {
			log.Printf("macsync: invalid mitm telemetry from %s: %v", clientID, err)
			rt.sendResponse(clientID, env, "error", "invalid mitm telemetry payload", nil)
			return
		}
		rt.logMITMTelemetry(&telem)
		rt.sendResponse(clientID, env, "ok", "telemetry received", map[string]any{"success": true})

	case messages.TypeMacMITMCertificate:
		var cert messages.MacMITMCertificatePayload
		if err := messages.UnmarshalPayload(env, &cert); err != nil {
			log.Printf("macsync: invalid mitm certificate request from %s: %v", clientID, err)
			rt.sendResponse(clientID, env, "error", "invalid mitm certificate payload", nil)
			return
		}
		rt.handleMITMCertificateRequest(clientID, env, &cert)

	default:
		log.Printf("macsync: unhandled message type from %s: %s", clientID, env.Type)
		rt.sendAck(clientID, env, "error", "unsupported message type")
	}
}

func (rt *runtimeState) sendAck(clientID string, env *messages.Envelope, status, message string) {
	if rt.wsHub == nil || clientID == "" {
		return
	}

	sessionID := ""
	shimID := ""
	version := 1
	cmd := ""
	if env != nil {
		sessionID = env.SessionID
		shimID = env.ShimID
		version = env.Version
		cmd = env.Type
	}

	ackPayload := messages.AckPayload{
		Cmd:     cmd,
		Status:  status,
		Message: message,
	}

	ackEnv, err := messages.WrapPayload(sessionID, shimID, messages.TypeMacAck, version, ackPayload)
	if err != nil {
		log.Printf("macsync: failed to craft ack envelope: %v", err)
		return
	}

	data, err := json.Marshal(ackEnv)
	if err != nil {
		log.Printf("macsync: failed to marshal ack: %v", err)
		return
	}

	if err := rt.wsHub.SendToClient(clientID, data); err != nil {
		log.Printf("macsync: failed to send ack to %s: %v", clientID, err)
	}
}

// sendResponse sends a response with matching request_id for request-response pattern.
func (rt *runtimeState) sendResponse(clientID string, env *messages.Envelope, status, message string, payload map[string]any) {
	if rt.wsHub == nil || clientID == "" {
		return
	}

	sessionID := ""
	shimID := ""
	requestID := ""
	version := 1
	if env != nil {
		sessionID = env.SessionID
		shimID = env.ShimID
		requestID = env.RequestID
		version = env.Version
	}

	// If no payload provided, send simple ack-style response
	if payload == nil {
		payload = map[string]any{
			"status":  status,
			"message": message,
		}
	}

	respEnv, err := messages.WrapPayloadWithRequestID(sessionID, shimID, env.Type+".response", requestID, version, payload)
	if err != nil {
		log.Printf("macsync: failed to craft response envelope: %v", err)
		return
	}

	data, err := json.Marshal(respEnv)
	if err != nil {
		log.Printf("macsync: failed to marshal response: %v", err)
		return
	}

	if err := rt.wsHub.SendToClient(clientID, data); err != nil {
		log.Printf("macsync: failed to send response to %s: %v", clientID, err)
	}
}

// broadcastRuleUpdate notifies all clients that policy rules have changed.
func (rt *runtimeState) broadcastRuleUpdate() {
	if rt.wsHub == nil || rt.macSync == nil {
		return
	}

	rules := rt.macSync.GetPolicyRules()
	payload := map[string]any{"rules": rules}

	env, err := messages.WrapPayload("", "", "mac.rule.snapshot", 1, payload)
	if err != nil {
		log.Printf("macsync: failed to create rule update broadcast: %v", err)
		return
	}

	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("macsync: failed to marshal rule update broadcast: %v", err)
		return
	}

	// Broadcast to all clients
	if rt.wsHub != nil {
		for _, client := range rt.snapshotMacClients() {
			if err := rt.wsHub.SendToClient(client.ID, data); err != nil {
				log.Printf("macsync: failed to broadcast rule update to %s: %v", client.ID, err)
			}
		}
	}

	log.Printf("macsync: broadcasted rule update (%d rules) to %d clients", len(rules), len(rt.snapshotMacClients()))
}

// broadcastNetworkRuleUpdate notifies all clients that network rules have changed.
func (rt *runtimeState) broadcastNetworkRuleUpdate() {
	if rt.wsHub == nil || rt.macSync == nil {
		return
	}

	rules := rt.macSync.GetNetworkRules()
	payload := map[string]any{"rules": rules}

	env, err := messages.WrapPayload("", "", messages.TypeMacNetworkRuleUpdate, 1, payload)
	if err != nil {
		log.Printf("macsync: failed to create network rule update broadcast: %v", err)
		return
	}

	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("macsync: failed to marshal network rule update broadcast: %v", err)
		return
	}

	// Broadcast to all clients
	for _, client := range rt.snapshotMacClients() {
		if err := rt.wsHub.SendToClient(client.ID, data); err != nil {
			log.Printf("macsync: failed to broadcast network rule update to %s: %v", client.ID, err)
		}
	}

	log.Printf("macsync: broadcasted network rule update (%d rules) to %d clients", len(rules), len(rt.snapshotMacClients()))
}

// broadcastMITMConfig pushes the latest MITM configuration to all mac clients.
func (rt *runtimeState) broadcastMITMConfig(cfg *messages.MacMITMConfigPayload) {
	if rt.wsHub == nil || cfg == nil {
		return
	}

	version := cfg.Version
	if version == 0 {
		version = 1
	}

	env, err := messages.WrapPayload("", "", messages.TypeMacMITMConfig, version, cfg)
	if err != nil {
		log.Printf("macsync: failed to create MITM config broadcast: %v", err)
		return
	}

	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("macsync: failed to marshal MITM config broadcast: %v", err)
		return
	}

	for _, client := range rt.snapshotMacClients() {
		if err := rt.wsHub.SendToClient(client.ID, data); err != nil {
			log.Printf("macsync: failed to broadcast MITM config to %s: %v", client.ID, err)
		}
	}

	log.Printf("macsync: broadcasted MITM config (enabled=%v listen=%s)", cfg.Enabled, cfg.ListenAddress)
}

// broadcastMITMSession notifies clients of a session lifecycle update.
func (rt *runtimeState) broadcastMITMSession(sess *messages.MacMITMSessionPayload) {
	if rt.wsHub == nil || sess == nil {
		return
	}

	env, err := messages.WrapPayload("", "", messages.TypeMacMITMSession, 1, sess)
	if err != nil {
		log.Printf("macsync: failed to create MITM session broadcast: %v", err)
		return
	}

	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("macsync: failed to marshal MITM session broadcast: %v", err)
		return
	}

	for _, client := range rt.snapshotMacClients() {
		if err := rt.wsHub.SendToClient(client.ID, data); err != nil {
			log.Printf("macsync: failed to broadcast MITM session to %s: %v", client.ID, err)
		}
	}
}

// logMITMTelemetry emits MITM telemetry to the shared logger and websocket history.
func (rt *runtimeState) logMITMTelemetry(telem *messages.MacMITMTelemetryPayload) {
	if telem == nil {
		return
	}

	ts := telem.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	fields := map[string]any{
		"session":    telem.SessionID,
		"method":     telem.Method,
		"host":       telem.Host,
		"path":       telem.Path,
		"status":     telem.StatusCode,
		"decision":   telem.Decision,
		"bytes_in":   telem.BytesIn,
		"bytes_out":  telem.BytesOut,
		"latency_ms": telem.LatencyMS,
	}
	if telem.RuleID != "" {
		fields["rule_id"] = telem.RuleID
	}
	if telem.Error != "" {
		fields["error"] = telem.Error
	}

	logPolicyEvent("mac.mitm.telemetry", fields)
}

// handleMITMCertificateRequest logs the request and rebroadcasts it so UI helpers can respond.
func (rt *runtimeState) handleMITMCertificateRequest(clientID string, env *messages.Envelope, req *messages.MacMITMCertificatePayload) {
	if req == nil {
		rt.sendResponse(clientID, env, "error", "nil certificate request", nil)
		return
	}

	logPolicyEvent("mac.mitm.certificate", map[string]any{
		"client": clientID,
		"action": req.Action,
		"prompt": req.PromptUser,
		"system": req.InstallSystem,
	})

	// Broadcast request so the SwiftUI app/helper can act on it.
	if rt.wsHub != nil {
		envOut, err := messages.WrapPayload("", "", messages.TypeMacMITMCertificate, 1, req)
		if err == nil {
			if data, err := json.Marshal(envOut); err == nil {
				for _, client := range rt.snapshotMacClients() {
					if err := rt.wsHub.SendToClient(client.ID, data); err != nil {
						log.Printf("macsync: failed to forward MITM certificate request to %s: %v", client.ID, err)
					}
				}
			} else {
				log.Printf("macsync: failed to marshal certificate broadcast: %v", err)
			}
		} else {
			log.Printf("macsync: failed to wrap certificate broadcast: %v", err)
		}
	}

	rt.sendResponse(clientID, env, "ok", "certificate request dispatched", map[string]any{
		"action": req.Action,
	})
}

// snapshotMacClients returns all currently connected macOS clients.
func (rt *runtimeState) snapshotMacClients() []*macsync.ClientState {
	if rt.macSync == nil {
		return nil
	}
	return rt.macSync.GetAllClients()
}

// broadcastPIDUpdate notifies all clients of tracked PID changes.
func (rt *runtimeState) broadcastPIDUpdate(pids []messages.MacTrackedPID) {
	if rt.wsHub == nil {
		return
	}

	payload := map[string]any{
		"entries": pids,
	}

	env, err := messages.WrapPayload("", "", messages.TypeMacPIDSync, 1, payload)
	if err != nil {
		log.Printf("macsync: failed to create PID broadcast: %v", err)
		return
	}

	data, err := json.Marshal(env)
	if err != nil {
		log.Printf("macsync: failed to marshal PID broadcast: %v", err)
		return
	}

	// Broadcast to all clients
	for _, client := range rt.snapshotMacClients() {
		if err := rt.wsHub.SendToClient(client.ID, data); err != nil {
			log.Printf("macsync: failed to broadcast PID update to %s: %v", client.ID, err)
		}
	}

	log.Printf("macsync: broadcasted PID update (%d PIDs) to %d clients", len(pids), len(rt.snapshotMacClients()))
}

func (rt *runtimeState) syncMacPoliciesFrom(policies *lsm.PolicySet) {
	if rt.macSync == nil {
		return
	}

	rules, networkRules := macsync.ConvertPolicyToMacRules(policies)

	rt.macSync.ClearPolicyRules()
	if len(rules) > 0 {
		rt.macSync.AddPolicyRules(rules)
	}
	rt.broadcastRuleUpdate()

	rt.macSync.UpdateNetworkRules(networkRules)
	rt.broadcastNetworkRuleUpdate()

	for _, rule := range networkRules {
		log.Printf("macsync: network rule %s %s=%s", rule.Action, rule.TargetType, rule.TargetValue)
	}
}

func (rt *runtimeState) pushMacStateToClient(clientID string) {
	if rt.wsHub == nil || rt.macSync == nil || clientID == "" {
		return
	}

	rules := rt.macSync.GetPolicyRules()
	rulePayload := map[string]any{"rules": rules}
	if env, err := messages.WrapPayload("", "", "mac.rule.snapshot", 1, rulePayload); err == nil {
		if data, err := json.Marshal(env); err == nil {
			if err := rt.wsHub.SendToClient(clientID, data); err != nil {
				log.Printf("macsync: failed to push rule snapshot to %s: %v", clientID, err)
			}
		}
	}

	netRules := rt.macSync.GetNetworkRules()
	netPayload := map[string]any{"rules": netRules}
	if netEnv, err := messages.WrapPayload("", "", messages.TypeMacNetworkRuleUpdate, 1, netPayload); err == nil {
		if data, err := json.Marshal(netEnv); err == nil {
			if err := rt.wsHub.SendToClient(clientID, data); err != nil {
				log.Printf("macsync: failed to push network rules to %s: %v", clientID, err)
			}
		}
	}

	if cfg := rt.macSync.CurrentMITMConfig(); cfg != nil {
		version := cfg.Version
		if version == 0 {
			version = 1
		}
		if mitmEnv, err := messages.WrapPayload("", "", messages.TypeMacMITMConfig, version, cfg); err == nil {
			if data, err := json.Marshal(mitmEnv); err == nil {
				if err := rt.wsHub.SendToClient(clientID, data); err != nil {
					log.Printf("macsync: failed to push MITM config to %s: %v", clientID, err)
				}
			}
		}
	}
}

const proxyMark = "0x2000"

func formatCedarErrorForCLI(detail *cedarutil.ErrorDetail) string {
	if detail == nil {
		return "error: invalid Cedar policy"
	}
	var b strings.Builder
	b.WriteString("error: invalid Cedar policy\n")
	if detail.File != "" {
		line := detail.Line
		if line <= 0 {
			line = 1
		}
		col := detail.Column
		if col <= 0 {
			col = detail.CaretStart
		}
		if col <= 0 {
			col = 1
		}
		fmt.Fprintf(&b, "file: %s:%d:%d\n", detail.File, line, col)
	}
	if detail.Snippet != "" && detail.Line > 0 {
		fmt.Fprintf(&b, "%d | %s\n", detail.Line, detail.Snippet)
		caretPos := detail.CaretStart
		if caretPos <= 0 {
			caretPos = detail.Column
		}
		if caretPos <= 0 {
			caretPos = 1
		}
		fmt.Fprintf(&b, "   | %s^", strings.Repeat(" ", caretPos-1))
		if msg := strings.TrimSpace(detail.Message); msg != "" {
			fmt.Fprintf(&b, " %s", msg)
		}
		b.WriteByte('\n')
	}
	if hint := strings.TrimSpace(detail.Suggestion); hint != "" {
		fmt.Fprintf(&b, "hint: %s\n", hint)
	}
	return strings.TrimSpace(b.String())
}

func applyIptablesRules(port string) error {
	if port == "" {
		port = "18000"
	}
	if _, err := findIptables(); err != nil {
		return err
	}

	shell := "/bin/sh"
	if _, err := exec.LookPath(shell); err != nil {
		return fmt.Errorf("shell not found: %w", err)
	}

	cmd := exec.Command(shell, "-s", port)
	cmd.Stdin = strings.NewReader(assets.ApplyIptablesScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "PROXY_MARK="+proxyMark)
	return cmd.Run()
}

// findIptables locates the iptables binary by searching PATH first,
// then common sbin locations used in minimal containers.
func findIptables() (string, error) {
	// PATH first
	if p, err := exec.LookPath("iptables"); err == nil {
		return p, nil
	}
	// Fallback dirs
	candidates := []string{"/usr/sbin/iptables", "/sbin/iptables"}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Mode()&0111 != 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("iptables not found (checked PATH, /usr/sbin, /sbin)")
}
