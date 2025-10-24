package leashd

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
	"github.com/strongdm/leash/internal/entrypoint"
	"github.com/strongdm/leash/internal/httpserver"
	"github.com/strongdm/leash/internal/leashd/listen"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/proxy"
	"github.com/strongdm/leash/internal/telemetry/otel"
	"github.com/strongdm/leash/internal/telemetry/statsig"
	"github.com/strongdm/leash/internal/ui"
	websockethub "github.com/strongdm/leash/internal/websocket"
)

const (
	defaultBootstrapTimeout = 2 * time.Minute
)

type stringFlag struct {
	value string
	set   bool
}

func (s *stringFlag) String() string {
	return s.value
}

func (s *stringFlag) Set(value string) error {
	s.value = value
	s.set = true
	return nil
}

// Main runs the leash daemon runtime using the provided argv slice.
// When args is empty, os.Args is used.
func Main(args []string) error {
	if len(args) == 0 {
		args = os.Args
	}

	if extra := strings.TrimSpace(os.Getenv("LEASH_EXTRA_ARGS")); extra != "" {
		args = append(args, splitExtraArgs(extra)...)
	}

	cfg, err := parseConfig(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	statsig.Start(context.Background(), statsig.StartPayload{Mode: "leashd"})
	defer statsig.Stop(context.Background())

	if err := preFlight(cfg); err != nil {
		return err
	}

	leashDir := getLeashDirFromEnv()
	if err := entrypoint.InflateBinaries(leashDir); err != nil {
		return err
	}

	if err := clearBootstrapMarker(leashDir); err != nil {
		return fmt.Errorf("prepare bootstrap marker: %w", err)
	}

	rt, err := initRuntime(cfg, leashDir)
	if err != nil {
		return err
	}
	defer rt.Close()

	return rt.Run()
}

// logPolicyEvent emits compact structured event logs: event=<name> key=value ...
func logPolicyEvent(event string, fields map[string]any) {
	buf := "event=" + event
	for k, v := range fields {
		buf += " " + k + "=" + fmt.Sprint(v)
	}
	log.Printf(buf)
	if event == "policy.update" {
		failed := false
		if fields != nil {
			if value, ok := fields["error"]; ok {
				switch typed := value.(type) {
				case string:
					failed = strings.TrimSpace(typed) != ""
				default:
					failed = true
				}
			}
		}
		statsig.IncPolicyUpdate(failed)
	}
}

type runtimeConfig struct {
	LogPath          string
	PolicyPath       string
	ProxyPort        string
	WebBind          string
	WebDisabled      bool
	HistorySize      int
	BulkMaxEvents    int
	BulkMaxBytes     int
	CgroupPath       string
	BootstrapTimeout time.Duration
	MCPConfig        proxy.MCPConfig
	TelemetryConfig  otel.Config
}

type runtimeState struct {
	cfg               *runtimeConfig
	logger            *lsm.SharedLogger
	wsHub             *websockethub.WebSocketHub
	headerRewriter    *proxy.HeaderRewriter
	mitmProxy         *proxy.MITMProxy
	lsmManager        *lsm.LSMManager
	policyManager     *policy.Manager
	policyWatcherStop func()
	policyReady       atomic.Bool
	closeOnce         sync.Once
	bootstrapPath     string
	telemetryProvider *otel.Provider
}

// parseConfig reads CLI flags and environment hints to build the runtime configuration.
func parseConfig(args []string) (*runtimeConfig, error) {
	name := commandName(args)
	fs := flag.NewFlagSet(name, flag.ContinueOnError)

	defaultLogPath := strings.TrimSpace(os.Getenv("LEASH_LOG"))
	logPath := fs.String("log", defaultLogPath, "Event log file path (optional)")

	defaultPolicyPath := strings.TrimSpace(os.Getenv("LEASH_POLICY"))
	if defaultPolicyPath == "" {
		defaultPolicyPath = "/cfg/leash.cedar"
	}
	policyPath := fs.String("policy", defaultPolicyPath, "Cedar policy file path")

	proxyPort := fs.String("proxy-port", "18000", "Proxy port")
	listenFlag := &stringFlag{}
	fs.Var(listenFlag, "listen", "Serve Control UI and API on the provided address (e.g. :18080, 127.0.0.1:18080). Leave blank to disable.")
	fs.Var(listenFlag, "l", "Alias for --listen")

	historySize := fs.Int("history-size", 25000, "Number of events to keep in memory for new connections")
	bulkMaxEvents := fs.Int("ws-bulk-max-events", 2000, "Max events to include in initial WebSocket bulk message (0 = unlimited)")
	bulkMaxBytes := fs.Int("ws-bulk-max-bytes", 1_000_000, "Max bytes to include in initial WebSocket bulk message (0 = unlimited)")
	defaultCgroupPath := strings.TrimSpace(os.Getenv("LEASH_CGROUP_PATH"))
	cgroupFlag := fs.String("cgroup", defaultCgroupPath, "Cgroup path to monitor")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [flags]\n\n", name)
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nEnvironment:\n  LEASH_CGROUP_PATH  Default value for --cgroup\n  LEASH_LISTEN       Default value for --listen (blank disables Control UI)\n  LEASH_EXTRA_ARGS   Additional CLI arguments\n")
	}

	var flagArgs []string
	if len(args) > 1 {
		flagArgs = args[1:]
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}

	if len(fs.Args()) > 0 {
		return nil, fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}

	listenCfg := listen.Default()
	if listenFlag.set {
		parsed, err := listen.Parse(listenFlag.value)
		if err != nil {
			return nil, fmt.Errorf("parse --listen: %w", err)
		}
		listenCfg = parsed
	} else if raw, ok := os.LookupEnv("LEASH_LISTEN"); ok {
		parsed, err := listen.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse LEASH_LISTEN: %w", err)
		}
		listenCfg = parsed
	}

	timeout := defaultBootstrapTimeout
	if raw := strings.TrimSpace(os.Getenv("LEASH_BOOTSTRAP_TIMEOUT")); raw != "" {
		parsed, err := parseBootstrapTimeout(raw)
		if err != nil {
			return nil, fmt.Errorf("parse LEASH_BOOTSTRAP_TIMEOUT: %w", err)
		}
		if parsed <= 0 {
			return nil, fmt.Errorf("LEASH_BOOTSTRAP_TIMEOUT must be positive")
		}
		timeout = parsed
	}

	cfg := &runtimeConfig{
		LogPath:          strings.TrimSpace(*logPath),
		PolicyPath:       strings.TrimSpace(*policyPath),
		ProxyPort:        strings.TrimSpace(*proxyPort),
		WebBind:          listenCfg.Address(),
		WebDisabled:      listenCfg.Disable,
		HistorySize:      *historySize,
		BulkMaxEvents:    *bulkMaxEvents,
		BulkMaxBytes:     *bulkMaxBytes,
		CgroupPath:       strings.TrimSpace(*cgroupFlag),
		BootstrapTimeout: timeout,
	}
	cfg.MCPConfig = loadMCPConfigFromEnv()
	cfg.TelemetryConfig = otel.LoadConfigFromEnv()

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
		return fmt.Errorf("failed to parse Cedar policy: %w", err)
	}

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

	if strings.TrimSpace(cfg.ProxyPort) == "" {
		return fmt.Errorf("proxy port required")
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

	return nil
}

func initRuntime(cfg *runtimeConfig, leashDir string) (*runtimeState, error) {
	logger, err := lsm.NewSharedLogger(cfg.LogPath)
	if err != nil {
		return nil, err
	}

	wsHub := websockethub.NewWebSocketHub(logger, cfg.HistorySize, cfg.BulkMaxEvents, cfg.BulkMaxBytes)
	go wsHub.Run()
	logger.SetBroadcaster(wsHub)

	lsmManager := lsm.NewLSMManager(cfg.CgroupPath, logger)
	lsm.BumpMemlockRlimit()

	headerRewriter := proxy.NewHeaderRewriter()
	headerRewriter.SetSharedLogger(logger)

	telemetryProvider, err := otel.Setup(context.Background(), cfg.TelemetryConfig)
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to initialize telemetry: %w", err)
	}
	cfg.MCPConfig.Telemetry = telemetryProvider.MCP()

	initialPolicy, err := policy.Parse(cfg.PolicyPath)
	if err != nil {
		logger.Close()
		var detail *cedarutil.ErrorDetail
		if errors.As(err, &detail) {
			return nil, errors.New(formatCedarErrorForCLI(detail))
		}
		return nil, fmt.Errorf("failed to parse Cedar policy: %w", err)
	}

	connectRules := lsm.ConvertToConnectRules(initialPolicy.LSMPolicies.Connect)
	defaultAllow := connectDefaultAllow(initialPolicy.LSMPolicies)
	policyChecker := lsm.NewSimplePolicyChecker(connectRules, defaultAllow, initialPolicy.LSMPolicies.MCP)

	// n.b. This kicks off certificate creation.
	mitmProxy, err := proxy.NewMITMProxy(cfg.ProxyPort, headerRewriter, policyChecker, logger, cfg.MCPConfig)
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to create MITM proxy: %w", err)
	}

	if strings.TrimSpace(leashDir) == "" {
		leashDir = getLeashDirFromEnv()
	}

	state := &runtimeState{
		cfg:               cfg,
		logger:            logger,
		wsHub:             wsHub,
		headerRewriter:    headerRewriter,
		mitmProxy:         mitmProxy,
		lsmManager:        lsmManager,
		bootstrapPath:     filepath.Join(leashDir, entrypoint.BootstrapReadyFileName),
		telemetryProvider: telemetryProvider,
	}

	policyManager := policy.NewManager(lsmManager, func(rules *lsm.PolicySet, httpRules []proxy.HeaderRewriteRule) {
		state.headerRewriter.SetRules(httpRules)
		applyPolicyToProxy(state.mitmProxy, rules)
	})

	if err := policyManager.UpdateFileRules(initialPolicy.LSMPolicies, initialPolicy.HTTPRewrites); err != nil {
		state.Close()
		return nil, fmt.Errorf("failed to load file policies: %w", err)
	}
	headerRewriter.SetRules(initialPolicy.HTTPRewrites)
	state.policyManager = policyManager

	logPolicyEvent("policy.restore", map[string]any{
		"source":        "file",
		"lsm_open":      len(initialPolicy.LSMPolicies.Open),
		"lsm_exec":      len(initialPolicy.LSMPolicies.Exec),
		"lsm_connect":   len(initialPolicy.LSMPolicies.Connect),
		"http_rewrites": len(initialPolicy.HTTPRewrites),
	})

	state.policyReady.Store(false)

	return state, nil
}

func (rt *runtimeState) Run() error {
	if err := rt.startFrontend(); err != nil {
		return err
	}

	if err := rt.waitForBootstrap(); err != nil {
		return err
	}

	return rt.activate()
}

func (rt *runtimeState) activate() error {
	if skipEnforcement() {
		logPolicyEvent("bootstrap.activate", map[string]any{"status": "skipped"})
		rt.policyReady.Store(true)
		waitForShutdown()
		return nil
	}

	if err := rt.startPolicyWatcher(); err != nil {
		return err
	}

	if err := rt.configureNetwork(); err != nil {
		return err
	}

	go func() {
		if err := rt.mitmProxy.Run(); err != nil {
			log.Fatal(err)
		}
	}()

	if err := rt.lsmManager.LoadAndStart(); err != nil {
		return err
	}

	logPolicyEvent("bootstrap.activate", map[string]any{"status": "ok"})
	rt.policyReady.Store(true)
	return nil
}

func (rt *runtimeState) waitForBootstrap() error {
	path := rt.bootstrapPath
	if strings.TrimSpace(path) == "" {
		path = filepath.Join(getLeashDirFromEnv(), entrypoint.BootstrapReadyFileName)
		rt.bootstrapPath = path
	}

	deadline := time.Now().Add(rt.cfg.BootstrapTimeout)
	logPolicyEvent("bootstrap.wait", map[string]any{
		"path":    path,
		"timeout": rt.cfg.BootstrapTimeout.String(),
	})

	for {
		info, err := os.Stat(path)
		if err == nil {
			meta, metaErr := readBootstrapMetadata(path)
			if metaErr != nil {
				logPolicyEvent("bootstrap.ready", map[string]any{"path": path, "error": metaErr.Error()})
			} else {
				meta["mtime"] = info.ModTime().UTC().Format(time.RFC3339Nano)
				logPolicyEvent("bootstrap.ready", meta)
			}
			return nil
		}
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("check bootstrap marker: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("bootstrap marker %s not observed within %s", path, rt.cfg.BootstrapTimeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func readBootstrapMetadata(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	meta := map[string]any{"path": path}
	if len(data) == 0 {
		return meta, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return meta, err
	}
	for k, v := range payload {
		meta[k] = v
	}
	return meta, nil
}

func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
}

func (rt *runtimeState) Close() {
	rt.closeOnce.Do(func() {
		if rt.telemetryProvider != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = rt.telemetryProvider.Shutdown(ctx)
		}
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

	api := newPolicyAPI(rt.policyManager, rt.cfg.PolicyPath, rt.wsHub)
	api.register(mux)

	// Suggestion API for raw suggestions preview
	suggest := newSuggestAPI(rt.policyManager, rt.wsHub)
	suggest.register(mux)

	if rt.cfg.WebDisabled {
		logPolicyEvent("frontend.disabled", map[string]any{"addr": ""})
		log.Printf("control UI disabled: no listen address configured (LEASH_LISTEN empty)")
		return nil
	}

	server := httpserver.NewWebServer(rt.cfg.WebBind, mux)

	go func(addr string, srv *http.Server) {
		logPolicyEvent("frontend.start", map[string]any{"addr": addr})
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("web server failed: %v", err)
		}
	}(rt.cfg.WebBind, server)

	return nil
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
	if runtime.GOOS != "linux" {
		log.Printf("iptables configuration skipped on %s", runtime.GOOS)
		return nil
	}

	fmt.Fprintf(os.Stderr, "leash: applying iptables rules\n")
	if err := applyIptablesRules(rt.cfg.ProxyPort); err != nil {
		return err
	}

	// Best-effort mounts and environment probe
	fmt.Fprintf(os.Stderr, "leash: mounting securityfs\n")
	secfs := exec.Command("mount", "-t", "securityfs", "securityfs", "/sys/kernel/security")
	secfs.Stdout = os.Stdout
	secfs.Stderr = os.Stderr
	if err := secfs.Run(); err != nil {
		log.Printf("Warning: Failed to mount securityfs: %v", err)
	}

	// Print LSM list if available so operators can confirm BPF LSM
	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		lsmList := strings.TrimSpace(string(data))
		logPolicyEvent("env.lsm", map[string]any{"lsm": lsmList})
		if !strings.Contains(lsmList, "bpf") {
			log.Printf("Warning: BPF LSM not present in LSM list; exec/file/connect LSM may fail to attach")
		}
	} else {
		log.Printf("Warning: Unable to read /sys/kernel/security/lsm: %v", err)
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
	connectRules := lsm.ConvertToConnectRules(rules.Connect)
	defaultAllow := connectDefaultAllow(rules)
	mitmproxy.SetPolicyChecker(lsm.NewSimplePolicyChecker(connectRules, defaultAllow, rules.MCP))
}

const proxyMark = "0x2000"

func clearBootstrapMarker(dir string) error {
	if dir == "" {
		dir = "/leash"
	}
	marker := filepath.Join(dir, entrypoint.BootstrapReadyFileName)
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func skipEnforcement() bool {
	if strings.TrimSpace(os.Getenv("LEASH_E2E")) != "1" {
		return false
	}
	return strings.TrimSpace(os.Getenv("LEASH_BOOTSTRAP_SKIP_ENFORCE")) != ""
}

// iptablesBinaryName declares the command name used to locate iptables binaries.
// Tests override this to simulate hosts where iptables is absent without mutating the real filesystem.
var iptablesBinaryName = "iptables"

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
	if p, err := exec.LookPath(iptablesBinaryName); err == nil {
		return p, nil
	}
	// Fallback dirs
	candidates := []string{
		filepath.Join("/usr/sbin", iptablesBinaryName),
		filepath.Join("/sbin", iptablesBinaryName),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("iptables not found (checked PATH, /usr/sbin, /sbin)")
}

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

func splitExtraArgs(raw string) []string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func commandName(args []string) string {
	if len(args) == 0 {
		return "leash"
	}
	if strings.TrimSpace(args[0]) == "" {
		return "leash"
	}
	return args[0]
}

func parseBootstrapTimeout(raw string) (time.Duration, error) {
	if d, err := time.ParseDuration(raw); err == nil {
		return d, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", raw)
	}
	return time.Duration(seconds) * time.Second, nil
}
