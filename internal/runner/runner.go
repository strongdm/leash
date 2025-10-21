package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/strongdm/leash/internal/assets"
	"github.com/strongdm/leash/internal/configstore"
	"github.com/strongdm/leash/internal/entrypoint"
	"github.com/strongdm/leash/internal/leashd/listen"
)

const (
	defaultTargetImage = "ghcr.io/strongdm/coder:latest"
	defaultLeashImage  = "ghcr.io/strongdm/leash:latest"

	defaultProxyPort = "18000"

	cgroupHintName = "cgroup-path"

	defaultBootstrapTimeout = 2 * time.Minute
)

const (
	envAnthropicAPIKey = "ANTHROPIC_API_KEY"
	envOpenAIAPIKey    = "OPENAI_API_KEY"
	envDashscopeAPIKey = "DASHSCOPE_API_KEY"
	envGeminiAPIKey    = "GEMINI_API_KEY"
)

var baseEnvVarsByCommand = map[string][]string{
	"claude": {envAnthropicAPIKey},
	"codex":  {envOpenAIAPIKey},
	"qwen":   {envDashscopeAPIKey},
	"gemini": {envGeminiAPIKey},
}

var autoEnvForCommand = func() map[string][]string {
	out := make(map[string][]string, len(baseEnvVarsByCommand)+1)
	aggregateSet := make(map[string]struct{})
	var aggregate []string

	for cmd, vars := range baseEnvVarsByCommand {
		copied := make([]string, len(vars))
		copy(copied, vars)
		out[cmd] = copied
		for _, v := range vars {
			if _, seen := aggregateSet[v]; seen {
				continue
			}
			aggregateSet[v] = struct{}{}
			aggregate = append(aggregate, v)
		}
	}
	out["opencode"] = aggregate
	return out
}()

type options struct {
	noInteractive  bool
	policyOverride string
	verbose        bool
	volumes        []string
	envVars        []string
	command        []string
	subcommand     string
	targetImage    string
	leashImage     string
	listen         string
	listenSet      bool
	openUI         bool
}

type config struct {
	callerDir           string
	hostOS              string
	workDir             string
	workDirIsTemp       bool
	shareDir            string
	shareDirFromEnv     bool
	logDir              string
	cfgDir              string
	workspaceDir        string
	targetImage         string
	leashImage          string
	targetContainer     string
	leashContainer      string
	targetContainerBase string
	leashContainerBase  string
	proxyPort           string
	extraArgs           string
	cgroupPathOverride  string
	policyPath          string
	policyOverride      bool
	bootstrapTimeout    time.Duration
	listenCfg           listen.Config
	listenExplicit      bool
}

type runner struct {
	opts options
	cfg  config

	verbose         bool
	shareDirCreated bool
	keepContainers  bool

	logger     *log.Logger
	mountState *mountState
}

// ExitCodeError propagates the exact exit status produced by the leashed command
// running inside the target container. Returning a plain error would flatten every
// failure to exit code 1; this wrapper keeps the original status while still fitting
// into our error handling.
type ExitCodeError struct {
	code int
}

func (e *ExitCodeError) Error() string {
	return fmt.Sprintf("command exited with code %d", e.code)
}

func (e *ExitCodeError) ExitCode() int {
	return e.code
}

// Main orchestrates the leash runtime workflow using the provided argv slice. When args is
// empty, os.Args is used to mirror standard command invocation.
func Main(args []string) error {
	if len(args) == 0 {
		args = os.Args
	}
	name := commandName(args)
	return execute(name, args[1:])
}

func execute(cmdName string, args []string) error {
	opts, err := parseArgs(args)
	if err != nil {
		if errors.Is(err, errShowUsage) {
			fmt.Println(usage(cmdName))
			return nil
		}
		return err
	}

	if len(opts.command) == 0 {
		return fmt.Errorf("a command is required; provide one after '--'")
	}

	callerDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}

	if _, err := workspaceDir(); err != nil {
		return fmt.Errorf("determine workspace directory: %w", err)
	}

	cfg, configEnv, err := loadConfig(callerDir, opts)
	if err != nil {
		return err
	}

	opts.envVars = resolveEnvVars(opts.envVars, configEnv, opts.subcommand)

	if err := ensureCommand("docker"); err != nil {
		return err
	}

	r := &runner{
		opts:    opts,
		cfg:     cfg,
		verbose: opts.verbose,
		logger:  log.New(os.Stderr, "", 0),
	}

	if err := r.initMountState(context.Background(), callerDir); err != nil {
		return err
	}

	defer func() {
		if !r.cfg.workDirIsTemp || r.cfg.workDir == "" || r.keepContainers {
			return
		}
		if err := os.RemoveAll(r.cfg.workDir); err != nil {
			r.debugf("failed to remove work dir %s: %v", r.cfg.workDir, err)
		}
	}()

	defer func() {
		if r.mountState == nil {
			return
		}
		for _, tmpPath := range r.mountState.tempFiles {
			if err := os.Remove(tmpPath); err != nil {
				r.debugf("failed to remove temp file %s: %v", tmpPath, err)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	var interrupted int32
	go func() {
		for range sigCh {
			if atomic.CompareAndSwapInt32(&interrupted, 0, 1) {
				cancel()
				continue
			}
			os.Exit(1)
		}
	}()

	if err := r.startContainers(ctx); err != nil {
		if errors.Is(err, context.Canceled) && atomic.LoadInt32(&interrupted) == 1 {
			return &ExitCodeError{code: 1}
		}
		return err
	}
	return nil
}

var errShowUsage = errors.New("show usage")

func usage(cmdName string) string {
	return fmt.Sprintf(`Usage: %s [flags] [command [args...]]

Start the coder agent and leash manager containers, then optionally run a
command inside the target container. If no command is provided, the target image's default
entrypoint is left running.

Flags:
  -I, --no-interactive          Skip the interactive TTY; run the command non-interactively.
  -p, -policy, --policy <path>  Policy file to mount into the leash runtime.
  -l, --listen <addr>           Control UI bind address (e.g. :18080, 127.0.0.1:18080; blank disables UI).
  -o, --open                    Open Control UI in default browser once ready.
  -v, --volume <src:dst[:ro]>   Bind mount to pass through to the target container (repeatable).
  -e, --env <key[=value]>       Set environment variables inside the leash containers (repeatable).
  --image <name[:tag]>          Override the target container image (defaults to %s).
  --leash-image <name[:tag]>    Override the leash manager image (defaults to %s).
  -V, --verbose                 Enable verbose logging.

Environment variables:
  LEASH_TARGET_IMAGE           Default target image (overridden by --image).
  LEASH_IMAGE                  Default leash manager image (overridden by --leash-image).
  LEASH_WORK_DIR               Working directory root for leash tooling.
  LEASH_LOG_DIR                Log directory (defaults to $LEASH_WORK_DIR/log).
  LEASH_CFG_DIR                Config directory (defaults to $LEASH_WORK_DIR/cfg).
  LEASH_WORKSPACE_DIR          Workspace directory (defaults to $LEASH_WORK_DIR/workspace).
  LEASH_SHARE_DIR              Override for the shared state directory.
  LEASH_POLICY_FILE            Policy file to mount into the runtime.
  LEASH_WORKSPACE              Overrides project workspace detection.
  LEASH_BOOTSTRAP_TIMEOUT      Controls bootstrap timeout duration.
  LEASH_LISTEN                 Overrides Control UI bind address.
  LEASH_EXTRA_ARGS             Additional arguments passed into leash-entry.
  LEASH_CGROUP_PATH            Override cgroup path for the leash container.
  LEASH_HOME                   Base directory for persisted leash state.

	Persisted mount decisions live at $XDG_CONFIG_HOME/leash/config.toml (or ~/.config/leash/config.toml). Set LEASH_HOME to override this base directory.
	Global and per-project sections in that file control whether ~/.codex, ~/.claude, and other tool directories
are mounted automatically.`, cmdName, defaultTargetImage, defaultLeashImage)
}

func commandName(args []string) string {
	if len(args) == 0 {
		return "leash"
	}
	name := strings.TrimSpace(args[0])
	if name == "" {
		return "leash"
	}
	return filepath.Base(name)
}

func parseArgs(args []string) (options, error) {
	opts := options{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-I", "--no-interactive":
			opts.noInteractive = true
		case "-e", "--env":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("missing argument for %s", arg)
			}
			value := args[i+1]
			if err := appendEnvSpec(&opts, value); err != nil {
				return opts, err
			}
			i++
		case "-p", "-policy", "--policy":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("missing argument for %s", arg)
			}
			opts.policyOverride = args[i+1]
			i++
		case "-v":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && strings.Contains(args[i+1], ":") {
				opts.volumes = append(opts.volumes, args[i+1])
				i++
				break
			}
			opts.verbose = true
		case "--volume":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("missing argument for %s", arg)
			}
			value := args[i+1]
			if !strings.Contains(value, ":") {
				return opts, fmt.Errorf("invalid volume mount %q; expected src:dst[:ro]", value)
			}
			opts.volumes = append(opts.volumes, value)
			i++
		case "-V", "--verbose":
			opts.verbose = true
		case "--image":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("missing argument for %s", arg)
			}
			opts.targetImage = strings.TrimSpace(args[i+1])
			i++
		case "--leash-image":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("missing argument for %s", arg)
			}
			opts.leashImage = strings.TrimSpace(args[i+1])
			i++
		case "-l", "--listen":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("missing argument for %s", arg)
			}
			opts.listen = args[i+1]
			opts.listenSet = true
			i++
		case "-o", "--open":
			opts.openUI = true
		case "-h", "--help", "help":
			return opts, errShowUsage
		case "--":
			opts.command = append(opts.command, args[i+1:]...)
			if opts.subcommand == "" && len(opts.command) > 0 {
				opts.subcommand = opts.command[0]
			}
			return finalizeOptions(opts)
		default:
			switch {
			case strings.HasPrefix(arg, "--listen="):
				opts.listen = strings.TrimPrefix(arg, "--listen=")
				opts.listenSet = true
			case strings.HasPrefix(arg, "-l="):
				opts.listen = strings.TrimPrefix(arg, "-l=")
				opts.listenSet = true
			case strings.HasPrefix(arg, "--open="):
				return opts, fmt.Errorf("--open does not take a value")
			case strings.HasPrefix(arg, "-o="):
				return opts, fmt.Errorf("-o does not take a value")
			case strings.HasPrefix(arg, "-v="):
				volume := strings.TrimPrefix(arg, "-v=")
				if volume == "" {
					return opts, fmt.Errorf("missing argument for -v")
				}
				if strings.Contains(volume, ":") {
					opts.volumes = append(opts.volumes, volume)
				} else {
					return opts, fmt.Errorf("invalid volume mount %q; expected src:dst[:ro]", volume)
				}
			case strings.HasPrefix(arg, "--volume="):
				volume := strings.TrimPrefix(arg, "--volume=")
				if volume == "" {
					return opts, fmt.Errorf("missing argument for --volume")
				}
				if !strings.Contains(volume, ":") {
					return opts, fmt.Errorf("invalid volume mount %q; expected src:dst[:ro]", volume)
				}
				opts.volumes = append(opts.volumes, volume)
			case strings.HasPrefix(arg, "-e="):
				value := strings.TrimPrefix(arg, "-e=")
				if err := appendEnvSpec(&opts, value); err != nil {
					return opts, err
				}
			case strings.HasPrefix(arg, "--env="):
				value := strings.TrimPrefix(arg, "--env=")
				if err := appendEnvSpec(&opts, value); err != nil {
					return opts, err
				}
			case strings.HasPrefix(arg, "-V="):
				if strings.TrimPrefix(arg, "-V=") != "" {
					return opts, fmt.Errorf("-V does not take a value")
				}
				opts.verbose = true
			default:
				if strings.HasPrefix(arg, "-") {
					return opts, fmt.Errorf("unknown flag: %s", arg)
				}
				opts.command = append(opts.command, args[i:]...)
				if opts.subcommand == "" && len(opts.command) > 0 {
					opts.subcommand = opts.command[0]
				}
				return finalizeOptions(opts)
			}
		}
	}
	return finalizeOptions(opts)
}

func finalizeOptions(opts options) (options, error) {
	return opts, nil
}

func appendEnvSpec(opts *options, spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return fmt.Errorf("environment variable specification cannot be empty")
	}
	if strings.HasPrefix(spec, "-") {
		return fmt.Errorf("environment variable specification %q must not start with '-'; did you forget the value?", spec)
	}
	if strings.HasPrefix(spec, "=") {
		return fmt.Errorf("environment variable name is required in %q", spec)
	}

	opts.envVars = append(opts.envVars, spec)
	return nil
}

func envSpecKey(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	if idx := strings.Index(spec, "="); idx >= 0 {
		return strings.TrimSpace(spec[:idx])
	}
	return spec
}

func resolveEnvVars(cliSpecs []string, configEnv map[string]configstore.EnvVarValue, subcommand string) []string {
	cliLayer := cliEnvLayer(cliSpecs)
	autoLayer := autoEnvLayer(subcommand, cliLayer)
	globalLayer, projectLayer := configEnvLayers(configEnv)

	layers := make([]configstore.EnvLayer, 0, 4)
	if len(autoLayer.Specs) > 0 {
		layers = append(layers, autoLayer)
	}
	if len(globalLayer.Specs) > 0 {
		layers = append(layers, globalLayer)
	}
	if len(projectLayer.Specs) > 0 {
		layers = append(layers, projectLayer)
	}
	if len(cliLayer.Specs) > 0 {
		layers = append(layers, cliLayer)
	}

	return configstore.MergeEnvLayers(layers...)
}

func autoEnvLayer(subcommand string, cliLayer configstore.EnvLayer) configstore.EnvLayer {
	keys, ok := autoEnvForCommand[subcommand]
	// Keep going even when the command maps to an empty slice so that claude's
	// extra IS_SANDBOX handling below still runs.
	if !ok {
		return configstore.EnvLayer{}
	}

	skip := make(map[string]struct{}, len(cliLayer.Specs))
	for key := range cliLayer.Specs {
		skip[key] = struct{}{}
	}

	specs := make(map[string]string, len(keys)+1)
	order := make([]string, 0, len(keys)+1)

	for _, key := range keys {
		if _, dup := skip[key]; dup {
			continue
		}
		if value, present := os.LookupEnv(key); present {
			specs[key] = fmt.Sprintf("%s=%s", key, value)
			order = append(order, key)
		}
	}

	// Only claude cares about the sandbox flag; keep the handling local so it may
	// later be removed without modifying the generalized auto-env plumbing.
	if subcommand == "claude" {
		const sandboxKey = "IS_SANDBOX"
		if _, dup := skip[sandboxKey]; !dup {
			if value, present := os.LookupEnv(sandboxKey); present {
				specs[sandboxKey] = fmt.Sprintf("%s=%s", sandboxKey, value)
				order = append(order, sandboxKey)
			}
		}
	}

	if len(specs) == 0 {
		return configstore.EnvLayer{}
	}

	return configstore.EnvLayer{
		Specs: specs,
		Order: order,
	}
}

func configEnvLayers(configEnv map[string]configstore.EnvVarValue) (configstore.EnvLayer, configstore.EnvLayer) {
	if len(configEnv) == 0 {
		return configstore.EnvLayer{}, configstore.EnvLayer{}
	}

	globalSpecs := make(map[string]string)
	projectSpecs := make(map[string]string)

	for rawKey, entry := range configEnv {
		key := strings.TrimSpace(rawKey)
		if key == "" {
			continue
		}
		spec := fmt.Sprintf("%s=%s", key, entry.Value)
		if entry.Scope == configstore.ScopeProject {
			projectSpecs[key] = spec
		} else {
			globalSpecs[key] = spec
		}
	}

	globalOrder := sortedKeys(globalSpecs)
	projectOrder := sortedKeys(projectSpecs)

	globalLayer := configstore.EnvLayer{Specs: globalSpecs, Order: globalOrder}
	projectLayer := configstore.EnvLayer{Specs: projectSpecs, Order: projectOrder}
	return globalLayer, projectLayer
}

func cliEnvLayer(cliSpecs []string) configstore.EnvLayer {
	if len(cliSpecs) == 0 {
		return configstore.EnvLayer{}
	}

	specs := make(map[string]string, len(cliSpecs))
	order := make([]string, 0, len(cliSpecs))
	seen := make(map[string]struct{})

	for _, spec := range cliSpecs {
		key := envSpecKey(spec)
		if key == "" {
			continue
		}
		specs[key] = spec
		if _, already := seen[key]; !already {
			order = append(order, key)
			seen[key] = struct{}{}
		}
	}

	return configstore.EnvLayer{
		Specs: specs,
		Order: order,
	}
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func workspaceDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("LEASH_WORKSPACE")); override != "" {
		return resolveWorkspaceCandidate(override)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("determine working directory: %w", err)
	}
	return resolveWorkspaceCandidate(cwd)
}

func resolveWorkspaceCandidate(candidate string) (string, error) {
	if candidate == "" {
		return "", errors.New("empty workspace candidate")
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", candidate, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path %s is not a directory", abs)
	}
	return abs, nil
}

func createTempWorkDir(callerDir string) (string, error) {
	prefix := tempWorkDirPrefix(callerDir)
	return os.MkdirTemp("", prefix)
}

func tempWorkDirPrefix(callerDir string) string {
	base := filepath.Base(filepath.Clean(callerDir))
	if base == string(os.PathSeparator) || base == "." {
		base = "workspace"
	}

	var b strings.Builder
	b.Grow(len(base))
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}

	component := strings.Trim(b.String(), "-")
	if component == "" {
		component = "workspace"
	}
	return fmt.Sprintf("leash.%s.", component)
}

func workspaceNameFrom(dir string) string {
	clean := strings.TrimSpace(dir)
	if clean == "" {
		return ""
	}
	base := filepath.Base(filepath.Clean(clean))
	if base == "" || base == "." || base == string(os.PathSeparator) {
		return filepath.Clean(clean)
	}
	return base
}

func defaultContainerBaseNames(callerDir string) (string, string) {
	project := sanitizeProjectName(workspaceNameFrom(callerDir))
	if project == "" {
		project = "agent"
	}
	return project, fmt.Sprintf("%s-leash", project)
}

func sanitizeProjectName(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}

	var (
		builder    strings.Builder
		lastHyphen bool
	)

	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
			lastHyphen = false
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastHyphen = false
		case r == '-' || r == '_' || r == ' ' || r == '.':
			if builder.Len() == 0 || lastHyphen {
				continue
			}
			builder.WriteRune('-')
			lastHyphen = true
		default:
			if builder.Len() == 0 || lastHyphen {
				continue
			}
			builder.WriteRune('-')
			lastHyphen = true
		}
	}

	result := strings.Trim(builder.String(), "-")
	if len(result) > 63 {
		result = result[:63]
		result = strings.Trim(result, "-")
	}
	return result
}

func loadConfig(callerDir string, opts options) (config, map[string]configstore.EnvVarValue, error) {
	workDirEnv := strings.TrimSpace(os.Getenv("LEASH_WORK_DIR"))
	var (
		workDir       string
		workDirIsTemp bool
	)
	if workDirEnv != "" {
		workDir = workDirEnv
	} else {
		tempDir, err := createTempWorkDir(callerDir)
		if err != nil {
			return config{}, nil, fmt.Errorf("create work dir: %w", err)
		}
		workDir = tempDir
		workDirIsTemp = true
	}
	cleanupTemp := workDirIsTemp
	defer func() {
		if cleanupTemp && workDir != "" {
			_ = os.RemoveAll(workDir)
		}
	}()

	defaultTarget, defaultLeash := defaultContainerBaseNames(callerDir)
	targetBase := envOrDefault("TARGET_CONTAINER", defaultTarget)
	leashBase := envOrDefault("LEASH_CONTAINER", defaultLeash)

	cfg := config{
		callerDir:           callerDir,
		hostOS:              runtime.GOOS,
		workDir:             workDir,
		workDirIsTemp:       workDirIsTemp,
		targetImage:         defaultTargetImage,
		leashImage:          envOrDefault("LEASH_IMAGE", defaultLeashImage),
		targetContainer:     targetBase,
		leashContainer:      leashBase,
		targetContainerBase: targetBase,
		leashContainerBase:  leashBase,
		proxyPort:           envOrDefault("LEASH_PROXY_PORT", defaultProxyPort),
		extraArgs:           os.Getenv("LEASH_EXTRA_ARGS"),
		cgroupPathOverride:  strings.TrimSpace(os.Getenv("LEASH_CGROUP_PATH")),
	}

	cfg.logDir = envOrDefault("LEASH_LOG_DIR", filepath.Join(workDir, "log"))
	cfg.cfgDir = envOrDefault("LEASH_CFG_DIR", filepath.Join(workDir, "cfg"))
	cfg.workspaceDir = envOrDefault("LEASH_WORKSPACE_DIR", filepath.Join(workDir, "workspace"))

	if share := strings.TrimSpace(os.Getenv("LEASH_SHARE_DIR")); share != "" {
		cfg.shareDir = share
		cfg.shareDirFromEnv = true
	}

	envPolicy := strings.TrimSpace(os.Getenv("LEASH_POLICY_FILE"))
	// Do not default to docs/example.cedar anymore. If LEASH_POLICY_FILE is
	// unset, we allow the runtime to generate a permissive policy from Cedar.
	if envPolicy != "" {
		resolvedPolicy, err := resolvePolicyPath(callerDir, envPolicy)
		if err != nil {
			return config{}, nil, err
		}
		cfg.policyPath = resolvedPolicy
		cfg.policyOverride = true
	} else {
		cfg.policyPath = ""
		cfg.policyOverride = false
	}

	cfgData, err := configstore.Load()
	if err != nil {
		return config{}, nil, fmt.Errorf("load leash config: %w", err)
	}

	resolvedEnv, err := cfgData.ResolveEnvVars(callerDir)
	if err != nil {
		return config{}, nil, fmt.Errorf("resolve config env vars: %w", err)
	}
	if resolvedEnv == nil {
		resolvedEnv = make(map[string]configstore.EnvVarValue)
	}

	targetFromConfig := ""
	if image, _, imgErr := cfgData.GetTargetImage(callerDir); imgErr == nil && strings.TrimSpace(image) != "" {
		targetFromConfig = strings.TrimSpace(image)
	}

	if targetFromConfig != "" {
		cfg.targetImage = targetFromConfig
	}

	envTarget := strings.TrimSpace(os.Getenv("LEASH_TARGET_IMAGE"))
	if envTarget == "" {
		envTarget = strings.TrimSpace(os.Getenv("TARGET_IMAGE"))
	}
	if envTarget != "" {
		cfg.targetImage = envTarget
	}

	if opts.targetImage != "" {
		cfg.targetImage = opts.targetImage
	}

	if opts.leashImage != "" {
		cfg.leashImage = opts.leashImage
	}

	if opts.policyOverride != "" {
		customPolicy, err := resolvePolicyPath(callerDir, opts.policyOverride)
		if err != nil {
			return config{}, nil, err
		}
		cfg.policyPath = customPolicy
		cfg.policyOverride = true
	}

	timeout := defaultBootstrapTimeout
	if raw := strings.TrimSpace(os.Getenv("LEASH_BOOTSTRAP_TIMEOUT")); raw != "" {
		parsed, err := parseTimeout(raw)
		if err != nil {
			return config{}, nil, fmt.Errorf("parse LEASH_BOOTSTRAP_TIMEOUT: %w", err)
		}
		if parsed <= 0 {
			return config{}, nil, fmt.Errorf("LEASH_BOOTSTRAP_TIMEOUT must be positive")
		}
		timeout = parsed
	}
	cfg.bootstrapTimeout = timeout

	listenCfg := listen.Default()
	listenExplicit := false
	if opts.listenSet {
		parsed, err := listen.Parse(opts.listen)
		if err != nil {
			return config{}, nil, fmt.Errorf("parse listen flag: %w", err)
		}
		listenCfg = parsed
		listenExplicit = true
	} else if raw, ok := os.LookupEnv("LEASH_LISTEN"); ok {
		parsed, err := listen.Parse(raw)
		if err != nil {
			return config{}, nil, fmt.Errorf("parse LEASH_LISTEN: %w", err)
		}
		listenCfg = parsed
		listenExplicit = true
	}
	cfg.listenCfg = listenCfg
	cfg.listenExplicit = listenExplicit
	cleanupTemp = false
	return cfg, resolvedEnv, nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func resolvePolicyPath(base, candidate string) (string, error) {
	path := strings.TrimSpace(candidate)
	if path == "" {
		return "", errors.New("policy path must not be empty")
	}
	switch {
	case path == "~":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = home
	case strings.HasPrefix(path, "~/"):
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[2:])
	case !filepath.IsAbs(path):
		path = filepath.Join(base, path)
	}
	return filepath.Clean(path), nil
}

func parseTimeout(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, errors.New("timeout string must not be empty")
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", raw)
	}
	return time.Duration(seconds) * time.Second, nil
}

func ensureCommand(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("required command %q not found in PATH", name)
	}
	return nil
}

func (r *runner) debugf(format string, args ...interface{}) {
	if r.verbose {
		r.logger.Printf(format, args...)
	}
}

func (r *runner) startContainers(ctx context.Context) error {
	if err := r.assignContainerNames(ctx); err != nil {
		return err
	}

	if err := r.ensureNotRunning(ctx); err != nil {
		return err
	}

	if err := r.allocateListenPort(ctx); err != nil {
		return err
	}

	if err := r.ensureLocalImage(ctx, r.cfg.targetImage); err != nil {
		return err
	}
	if err := r.ensureLocalImage(ctx, r.cfg.leashImage); err != nil {
		return err
	}

	if err := os.MkdirAll(r.cfg.workDir, 0o755); err != nil {
		return fmt.Errorf("create work dir: %w", err)
	}
	if err := r.ensureShareDir(); err != nil {
		return err
	}
	bootstrapMarker := filepath.Join(r.cfg.shareDir, entrypoint.BootstrapReadyFileName)
	if err := os.Remove(bootstrapMarker); err == nil {
		r.debugf("removed stale bootstrap marker at %s", bootstrapMarker)
	}
	if err := os.MkdirAll(r.cfg.logDir, 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	if err := os.MkdirAll(r.cfg.cfgDir, 0o755); err != nil {
		return fmt.Errorf("create cfg dir: %w", err)
	}
	if err := os.MkdirAll(r.cfg.workspaceDir, 0o755); err != nil {
		return fmt.Errorf("create workspace dir: %w", err)
	}

	if err := r.syncPolicyFile(); err != nil {
		return err
	}

	if err := entrypoint.InflateBinaries(r.cfg.shareDir); err != nil {
		return fmt.Errorf("prepare leash-entry binaries: %w", err)
	}

	stopSignal, err := r.getImageStopSignal(ctx)
	if err != nil {
		return err
	}

	for {
		if err := r.launchTargetContainer(ctx, stopSignal); err != nil {
			retry, retryErr := r.handleListenPortRetry(ctx, err)
			if retryErr != nil {
				return r.finishLifecycle(ctx, 0, retryErr)
			}
			if retry {
				continue
			}
			return r.finishLifecycle(ctx, 0, err)
		}
		break
	}

	cgroupPath, err := r.resolveCgroupPath()
	if err != nil {
		return r.finishLifecycle(ctx, 0, err)
	}

	if err := r.launchLeashContainer(ctx, cgroupPath); err != nil {
		return r.finishLifecycle(ctx, 0, err)
	}

	if err := r.waitForFile(filepath.Join(r.cfg.shareDir, "ca-cert.pem"), 50, 200*time.Millisecond); err != nil {
		r.logger.Println("Warning: Leash CA certificate was not detected after waiting.")
	} else {
		r.logger.Printf("Leash CA certificate is available at %s\n", filepath.Join(r.cfg.shareDir, "ca-cert.pem"))
	}

	if err := r.waitForBootstrap(ctx); err != nil {
		return r.finishLifecycle(ctx, 0, err)
	}

	if err := r.installPromptAssets(ctx); err != nil {
		fmt.Printf("Warning: failed to install leash prompt: %v\n", err)
		if r.logger != nil {
			r.logger.Printf("Warning: failed to install leash prompt: %v", err)
		}
	}

	if r.cfg.listenCfg.Disable {
		fmt.Println()
	} else {
		url := r.cfg.listenCfg.DisplayURL()
		fmt.Printf("\nLeash UI (Control UI): %s\n", url)
		if r.opts.openUI {
			if err := listen.OpenURL(url); err != nil {
				r.logger.Printf("Failed to open Control UI in browser: %v", err)
			}
		}
	}
	fmt.Printf("Target logs: docker logs -f %s\n", r.cfg.targetContainer)
	fmt.Printf("Leash logs: docker logs -f %s\n", r.cfg.leashContainer)
	fmt.Printf("Stop everything with: docker rm -f %s %s\n\n", r.cfg.targetContainer, r.cfg.leashContainer)

	runCmd := shellQuote(r.opts.command)

	shellBin, err := r.detectShell(ctx)
	if err != nil {
		return r.finishLifecycle(ctx, 0, err)
	}

	if r.opts.noInteractive {
		fmt.Printf("Running non-interactive command (--no-interactive): %s\n", runCmd)
		exitCode, err := r.execNonInteractive(ctx, shellBin, runCmd)
		return r.finishLifecycle(ctx, exitCode, err)
	}

	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		exitCode, err := r.execNonInteractive(ctx, shellBin, runCmd)
		return r.finishLifecycle(ctx, exitCode, err)
	}

	if err := r.precheckInteractive(ctx, shellBin, runCmd); err != nil {
		r.keepContainers = true
		return r.finishLifecycle(ctx, 0, err)
	}

	exitCode, err := r.execInteractive(shellBin, runCmd)
	if err != nil {
		r.keepContainers = true
		return r.finishLifecycle(ctx, exitCode, err)
	}

	fmt.Printf("Interactive session exited (code=%d). Stopping containers...\n", exitCode)
	return r.finishLifecycle(ctx, exitCode, nil)
}

func (r *runner) assignContainerNames(ctx context.Context) error {
	baseTarget := r.cfg.targetContainerBase
	if strings.TrimSpace(baseTarget) == "" {
		baseTarget = r.cfg.targetContainer
	}
	baseLeash := r.cfg.leashContainerBase
	if strings.TrimSpace(baseLeash) == "" {
		baseLeash = r.cfg.leashContainer
	}

	const maxAttempts = 1000
	for attempt := 0; attempt < maxAttempts; attempt++ {
		targetCandidate := containerNameWithSuffix(baseTarget, attempt)
		leashCandidate := containerNameWithSuffix(baseLeash, attempt)

		targetExists, err := r.containerExists(ctx, targetCandidate)
		if err != nil {
			return err
		}
		leashExists, err := r.containerExists(ctx, leashCandidate)
		if err != nil {
			return err
		}

		if targetExists || leashExists {
			continue
		}

		if attempt > 0 && r.logger != nil {
			r.logger.Printf("Container names %s/%s already in use; selected %s/%s instead.", baseTarget, baseLeash, targetCandidate, leashCandidate)
		}

		r.cfg.targetContainer = targetCandidate
		r.cfg.leashContainer = leashCandidate
		return nil
	}

	return fmt.Errorf("unable to determine unique container names based on %q and %q", baseTarget, baseLeash)
}

func containerNameWithSuffix(base string, attempt int) string {
	if attempt == 0 || strings.TrimSpace(base) == "" {
		return base
	}
	const leashSuffix = "-leash"
	if strings.HasSuffix(base, leashSuffix) {
		prefix := strings.TrimSuffix(base, leashSuffix)
		return fmt.Sprintf("%s%d%s", prefix, attempt, leashSuffix)
	}
	return fmt.Sprintf("%s%d", base, attempt)
}

func (r *runner) allocateListenPort(ctx context.Context) error {
	if r.cfg.listenCfg.Disable {
		return nil
	}

	if r.cfg.listenExplicit {
		if err := r.ensurePortFree(ctx, r.cfg.listenCfg.Port); err != nil {
			var inUse *portInUseError
			if errors.As(err, &inUse) {
				return fmt.Errorf("listen port %s is already in use; specify a different value with --listen", inUse.port)
			}
			return err
		}
		return nil
	}

	port := r.cfg.listenCfg.Port
	for attempts := 0; attempts < 1000; attempts++ {
		if err := r.ensurePortFree(ctx, port); err != nil {
			var inUse *portInUseError
			if errors.As(err, &inUse) {
				next, err := incrementPort(port)
				if err != nil {
					return err
				}
				r.debugf("Port %s is unavailable; retrying with %s.", port, next)
				port = next
				continue
			}
			return err
		}

		r.cfg.listenCfg.Port = port
		return nil
	}

	return fmt.Errorf("failed to locate an available listen port starting at %s", r.cfg.listenCfg.Port)
}

func incrementPort(raw string) (string, error) {
	value, err := strconv.Atoi(raw)
	if err != nil {
		return "", fmt.Errorf("increment listen port %q: %w", raw, err)
	}
	value++
	if value > 65535 {
		return "", fmt.Errorf("no available ports after %s", raw)
	}
	return strconv.Itoa(value), nil
}

type portInUseError struct {
	port string
}

func (e *portInUseError) Error() string {
	return fmt.Sprintf("port %s is already in use", e.port)
}

func (r *runner) handleListenPortRetry(ctx context.Context, originalErr error) (bool, error) {
	const maxLaunchRetries = 100

	if r.cfg.listenCfg.Disable || r.cfg.listenExplicit {
		return false, nil
	}
	if !isPortConflictError(originalErr) {
		return false, nil
	}
	if err := r.bumpListenPort(ctx, maxLaunchRetries); err != nil {
		return false, err
	}
	if r.logger != nil {
		r.logger.Printf("Retrying with listen port %s after conflict.", r.cfg.listenCfg.Port)
	}
	return true, nil
}

func (r *runner) bumpListenPort(ctx context.Context, maxAttempts int) error {
	// Probe using Docker's view to avoid holding the port, then retry container launch with the first free slot observed.
	current := r.cfg.listenCfg.Port
	for attempts := 0; attempts < maxAttempts; attempts++ {
		next, err := incrementPort(current)
		if err != nil {
			return err
		}
		if err := r.ensurePortFree(ctx, next); err != nil {
			var inUse *portInUseError
			if errors.As(err, &inUse) {
				current = next
				continue
			}
			return err
		}
		r.cfg.listenCfg.Port = next
		return nil
	}
	return fmt.Errorf("failed to locate an available port after conflict starting at %s", current)
}

func isPortConflictError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "port is already allocated"):
		return true
	case strings.Contains(msg, "bind: address already in use"):
		return true
	case strings.Contains(msg, "address already in use"):
		return true
	case strings.Contains(msg, "port is already in use"):
		return true
	default:
		return false
	}
}

// Additional helper methods will be defined below.

func (r *runner) ensureNotRunning(ctx context.Context) error {
	running, err := r.containerRunning(ctx, r.cfg.targetContainer)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("error: containers already running (target='%s', leash='%s').\nRun: docker rm -f %s %s   to stop them, then try again.", r.cfg.targetContainer, r.cfg.leashContainer, r.cfg.targetContainer, r.cfg.leashContainer)
	}
	running, err = r.containerRunning(ctx, r.cfg.leashContainer)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("error: containers already running (target='%s', leash='%s').\nRun: docker rm -f %s %s   to stop them, then try again.", r.cfg.targetContainer, r.cfg.leashContainer, r.cfg.targetContainer, r.cfg.leashContainer)
	}

	if exists, _ := r.containerExists(ctx, r.cfg.targetContainer); exists {
		_ = runCommand(ctx, "docker", "rm", "-f", r.cfg.targetContainer)
	}
	if exists, _ := r.containerExists(ctx, r.cfg.leashContainer); exists {
		_ = runCommand(ctx, "docker", "rm", "-f", r.cfg.leashContainer)
	}
	return nil
}

func (r *runner) ensureShareDir() error {
	if r.cfg.shareDirFromEnv {
		if err := os.MkdirAll(r.cfg.shareDir, 0o755); err != nil {
			return fmt.Errorf("create share dir: %w", err)
		}
		r.shareDirCreated = false
		return nil
	}
	dir, err := os.MkdirTemp(r.cfg.workDir, "leash-")
	if err != nil {
		return fmt.Errorf("create share dir: %w", err)
	}
	r.cfg.shareDir = dir
	r.shareDirCreated = true
	return nil
}

func (r *runner) syncPolicyFile() error {
	// When no policy path is configured, skip copying; the runtime will
	// bootstrap a permissive Cedar policy.
	if strings.TrimSpace(r.cfg.policyPath) == "" {
		return nil
	}
	source := r.cfg.policyPath
	dest := filepath.Join(r.cfg.cfgDir, "leash.cedar")

	data, err := os.ReadFile(source)
	if err != nil {
		if r.cfg.policyOverride {
			return fmt.Errorf("Cedar policy file not found: %w", err)
		}
		r.logger.Printf("Warning: missing Cedar policy file at %s\n", source)
		return nil
	}

	if existing, err := os.ReadFile(dest); err == nil {
		if bytes.Equal(data, existing) {
			return nil
		}
	}

	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return fmt.Errorf("copy Cedar policy: %w", err)
	}
	fmt.Printf("Updated Cedar policy from %s\n", source)
	return nil
}

func (r *runner) imageDefaultCommand(ctx context.Context) ([]string, error) {
	entryJSON, err := commandOutput(ctx, "docker", "inspect", "--format", "{{json .Config.Entrypoint}}", r.cfg.targetImage)
	if err != nil {
		return nil, err
	}
	cmdJSON, err := commandOutput(ctx, "docker", "inspect", "--format", "{{json .Config.Cmd}}", r.cfg.targetImage)
	if err != nil {
		return nil, err
	}

	entryJSON = strings.TrimSpace(entryJSON)
	cmdJSON = strings.TrimSpace(cmdJSON)

	var entry, cmd []string
	if entryJSON != "" && entryJSON != "null" {
		if err := json.Unmarshal([]byte(entryJSON), &entry); err != nil {
			return nil, fmt.Errorf("parse entrypoint: %w", err)
		}
	}
	if cmdJSON != "" && cmdJSON != "null" {
		if err := json.Unmarshal([]byte(cmdJSON), &cmd); err != nil {
			return nil, fmt.Errorf("parse command: %w", err)
		}
	}

	return append(entry, cmd...), nil
}

func (r *runner) getImageStopSignal(ctx context.Context) (string, error) {
	out, err := commandOutput(ctx, "docker", "inspect", "--format", "{{.Config.StopSignal}}", r.cfg.targetImage)
	if err != nil {
		return "", fmt.Errorf("query stop signal: %w", err)
	}
	sig := strings.TrimSpace(out)
	if sig == "" || sig == "<no value>" {
		sig = "SIGTERM"
	}
	return sig, nil
}

func (r *runner) ensurePortFree(ctx context.Context, port string) error {
	out, err := commandOutput(ctx, "docker", "ps", "--format", "{{.Names}} {{.Ports}}")
	if err != nil {
		return fmt.Errorf("list docker ports: %w", err)
	}
	needle := fmt.Sprintf(":%s->", port)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return &portInUseError{port: port}
		}
	}
	return nil
}

func (r *runner) launchTargetContainer(ctx context.Context, stopSignal string) error {
	arch, err := r.detectImageArch(ctx)
	if err != nil {
		return err
	}
	entryName := fmt.Sprintf("leash-entry-linux-%s", arch)

	args := []string{
		"run", "--pull=missing", "-d",
		"--name", r.cfg.targetContainer,
		"--entrypoint", filepath.Join("/leash", entryName),
		"--cgroupns", "host",
	}
	if !r.cfg.listenCfg.Disable {
		if publish := r.cfg.listenCfg.DockerPublish(); publish != "" {
			args = append(args, "-p", publish)
		}
	}
	args = append(args,
		"-v", fmt.Sprintf("%s:/leash", r.cfg.shareDir),
		"-v", fmt.Sprintf("%s:%s", r.cfg.callerDir, r.cfg.callerDir),
		"-w", r.cfg.callerDir,
		"-e", fmt.Sprintf("LEASH_ENTRY_READY_FILE=/leash/%s", entrypoint.ReadyFileName),
		"-e", fmt.Sprintf("LEASH_ENTRY_STOP_SIGNAL=%s", stopSignal),
		"-e", "LEASH_ENTRY_KILL_SIGNAL=SIGKILL",
		"-e", "NODE_OPTIONS=--use-openssl-ca",
	)
	for _, env := range r.opts.envVars {
		args = append(args, "-e", env)
	}
	existingContainers := make(map[string]struct{})
	existingPairs := make(map[string]struct{})
	for _, volume := range r.opts.volumes {
		if host, container, ok := volumeHostContainer(volume); ok {
			key := volumePairKey(host, container)
			existingPairs[key] = struct{}{}
			existingContainers[container] = struct{}{}
			continue
		}
		if dest := volumeContainerPath(volume); dest != "" {
			existingContainers[dest] = struct{}{}
		}
	}
	if r.mountState != nil {
		for _, mount := range r.mountState.mounts {
			host := filepath.Clean(mount.Host)
			container := filepath.Clean(mount.Container)
			key := volumePairKey(host, container)
			label := strings.TrimSpace(mount.Name)
			if label == "" {
				label = strings.TrimSpace(r.mountState.command)
			}

			if _, exists := existingPairs[key]; exists {
				r.logger.Printf("Mount %s -> %s already configured; skipping duplicate.", host, container)
				continue
			}
			if _, exists := existingContainers[container]; exists {
				r.logger.Printf("Mount %s -> %s already configured; skipping duplicate.", host, container)
				continue
			}

			info, err := os.Stat(host)
			if err != nil {
				if os.IsNotExist(err) {
					if label != "" {
						r.logger.Printf("Warning: mount %s requested but %s does not exist; skipping.", label, host)
					} else {
						r.logger.Printf("Warning: mount requested for %s but %s does not exist; skipping.", container, host)
					}
				} else {
					r.logger.Printf("Warning: failed to access %s: %v; skipping auto-mount.", host, err)
				}
				continue
			}
			switch mount.Kind {
			case configstore.MountKindDirectory:
				if !info.IsDir() {
					r.logger.Printf("Warning: expected %s to be a directory; skipping auto-mount.", host)
					continue
				}
			case configstore.MountKindFile:
				if info.IsDir() {
					r.logger.Printf("Warning: expected %s to be a file; skipping auto-mount.", host)
					continue
				}
			case configstore.MountKindUnknown:
				// No additional validation; defer to docker `-v` handling.
			}

			args = append(args, "-v", fmt.Sprintf("%s:%s:%s", host, container, mount.Mode))
			existingPairs[key] = struct{}{}
			existingContainers[container] = struct{}{}
			if label != "" {
				r.logger.Printf("Auto-mounted %s (%s) -> %s (scope=%s)", host, label, container, mount.Scope)
			} else {
				r.logger.Printf("Auto-mounted %s -> %s (scope=%s)", host, container, mount.Scope)
			}
		}
	}
	for _, volume := range r.opts.volumes {
		args = append(args, "-v", volume)
	}
	args = append(args, r.cfg.targetImage)
	return runCommand(ctx, "docker", args...)
}

func (r *runner) detectImageArch(ctx context.Context) (string, error) {
	out, err := commandOutput(ctx, "docker", "inspect", "--format", "{{.Architecture}}", r.cfg.targetImage)
	if err != nil {
		return "", fmt.Errorf("detect architecture: %w", err)
	}
	return normalizeArch(out)
}

func normalizeArch(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "amd64", "x86_64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported architecture %q for leash-entry", strings.TrimSpace(raw))
	}
}

func volumePairKey(host, container string) string {
	return host + "->" + container
}

func (r *runner) resolveCgroupPath() (string, error) {
	if override := strings.TrimSpace(r.cfg.cgroupPathOverride); override != "" {
		return override, nil
	}

	hint := filepath.Join(r.cfg.shareDir, cgroupHintName)
	if err := r.waitForFile(hint, 50, 200*time.Millisecond); err != nil {
		return "", fmt.Errorf("failed to locate cgroup path hint: %w", err)
	}
	// Handle rare race where the file is created before content is written.
	for i := 0; i < 50; i++ {
		data, err := os.ReadFile(hint)
		if err != nil {
			// If it disappeared briefly, retry.
			if os.IsNotExist(err) {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return "", fmt.Errorf("read cgroup hint: %w", err)
		}
		path := strings.TrimSpace(string(data))
		if path != "" {
			return path, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", errors.New("cgroup path hint file empty")
}

func (r *runner) launchLeashContainer(ctx context.Context, cgroupPath string) error {
	args := []string{
		"run", "--pull=missing", "-d",
		"--name", r.cfg.leashContainer,
		"--privileged",
		"--cap-add", "NET_ADMIN",
		"--network", fmt.Sprintf("container:%s", r.cfg.targetContainer),
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:ro",
		"-v", fmt.Sprintf("%s:/log", r.cfg.logDir),
		"-v", fmt.Sprintf("%s:/cfg", r.cfg.cfgDir),
		"-v", fmt.Sprintf("%s:/leash", r.cfg.shareDir),
		"-e", fmt.Sprintf("LEASH_PROXY_PORT=%s", r.cfg.proxyPort),
		"-e", fmt.Sprintf("LEASH_LISTEN=%s", r.cfg.listenCfg.Address()),
		"-e", "LEASH_LOG=/log/events.log",
		"-e", "LEASH_POLICY=/cfg/leash.cedar",
		"-e", fmt.Sprintf("LEASH_CGROUP_PATH=%s", cgroupPath),
		"-e", fmt.Sprintf("LEASH_BOOTSTRAP_TIMEOUT=%s", r.cfg.bootstrapTimeout.String()),
	}

	// n.b. Used to show `<title>Leash | {workspace} > {command}</title>` in the frontend.
	if workspace := strings.TrimSpace(workspaceNameFrom(r.cfg.callerDir)); workspace != "" {
		args = append(args, "-e", fmt.Sprintf("LEASH_PROJECT=%s", workspace))
	}
	if len(r.opts.command) > 0 {
		args = append(args, "-e", fmt.Sprintf("LEASH_COMMAND=%s", strings.Join(r.opts.command, " ")))
	}

	if r.cfg.extraArgs != "" {
		args = append(args, "-e", fmt.Sprintf("LEASH_EXTRA_ARGS=%s", r.cfg.extraArgs))
	}
	for _, env := range r.opts.envVars {
		args = append(args, "-e", env)
	}

	args = append(args, r.cfg.leashImage, "--cgroup", cgroupPath)
	return runCommand(ctx, "docker", args...)
}

func (r *runner) waitForFile(path string, attempts int, delay time.Duration) error {
	for i := 0; i < attempts; i++ {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(delay)
	}
	return fmt.Errorf("file %s not found after waiting", path)
}

func (r *runner) waitForBootstrap(ctx context.Context) error {
	marker := filepath.Join(r.cfg.shareDir, entrypoint.BootstrapReadyFileName)
	deadline := time.Now().Add(r.cfg.bootstrapTimeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		if _, err := os.Stat(marker); err == nil {
			if info := describeBootstrapMarker(marker); info != "" {
				fmt.Printf("Bootstrap complete (%s)\n", info)
			} else {
				fmt.Println("Bootstrap complete.")
			}
			return nil
		}

		if time.Now().After(deadline) {
			targetState := r.containerSummary(ctx, r.cfg.targetContainer)
			leashState := r.containerSummary(ctx, r.cfg.leashContainer)
			return fmt.Errorf("bootstrap timed out after %s (target=%s, leash=%s). Ensure leash-entry is up to date and policy allows CA installation tooling (/bin/sh, update-ca-certificates).", r.cfg.bootstrapTimeout, targetState, leashState)
		}

		if state := r.containerSummary(ctx, r.cfg.targetContainer); isTerminalStatus(state) {
			logs := r.containerLogs(ctx, r.cfg.targetContainer)
			if logs != "" {
				return fmt.Errorf("target container terminated before bootstrap completed (state=%s).\nRecent docker logs (%s):\n%s", state, r.cfg.targetContainer, indentLines(logs, "  "))
			}
			return fmt.Errorf("target container terminated before bootstrap completed (state=%s). Inspect docker logs %s", state, r.cfg.targetContainer)
		}

		if state := r.containerSummary(ctx, r.cfg.leashContainer); isTerminalStatus(state) {
			logs := r.containerLogs(ctx, r.cfg.leashContainer)
			if logs != "" {
				return fmt.Errorf("leash container terminated before bootstrap completed (state=%s).\nRecent docker logs (%s):\n%s", state, r.cfg.leashContainer, indentLines(logs, "  "))
			}
			return fmt.Errorf("leash container terminated before bootstrap completed (state=%s). Inspect docker logs %s", state, r.cfg.leashContainer)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *runner) containerSummary(ctx context.Context, name string) string {
	format := "{{.State.Status}} {{.State.ExitCode}}"
	out, err := commandOutput(ctx, "docker", "inspect", "-f", format, name)
	if err != nil {
		if strings.Contains(err.Error(), "No such object") {
			return "missing"
		}
		return "error"
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return "unknown"
	}
	fields := strings.Fields(out)
	status := fields[0]
	var exitCode string
	if len(fields) > 1 {
		exitCode = fields[1]
	}
	if exitCode != "" && status != "running" && status != "created" && status != "starting" {
		return fmt.Sprintf("%s (exit=%s)", status, exitCode)
	}
	return status
}

func (r *runner) containerLogs(ctx context.Context, name string) string {
	out, err := commandOutput(ctx, "docker", "logs", "--tail", "200", name)
	if err != nil {
		return fmt.Sprintf("unavailable: %v", err)
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return "(no output)"
	}
	return out
}

func indentLines(text, prefix string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

func isTerminalStatus(summary string) bool {
	cat := statusCategory(summary)
	switch cat {
	case "exited", "dead", "removing", "missing":
		return true
	case "error":
		return true
	default:
		return false
	}
}

func statusCategory(summary string) string {
	if summary == "" {
		return ""
	}
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return ""
	}
	for i := 0; i < len(summary); i++ {
		if summary[i] == ' ' || summary[i] == '(' {
			return summary[:i]
		}
	}
	return summary
}

func describeBootstrapMarker(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return ""
	}
	var payload struct {
		PID       int    `json:"pid"`
		Hostname  string `json:"hostname"`
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return ""
	}
	var parts []string
	if payload.Hostname != "" {
		parts = append(parts, "hostname="+payload.Hostname)
	}
	if payload.PID > 0 {
		parts = append(parts, fmt.Sprintf("pid=%d", payload.PID))
	}
	if payload.Timestamp != "" {
		parts = append(parts, "ts="+payload.Timestamp)
	}
	return strings.Join(parts, " ")
}

func (r *runner) detectShell(ctx context.Context) (string, error) {
	if err := runCommand(ctx, "docker", "exec", "-w", r.cfg.callerDir, r.cfg.targetContainer, "bash", "-lc", "true"); err == nil {
		return "bash", nil
	}
	if err := runCommand(ctx, "docker", "exec", "-w", r.cfg.callerDir, r.cfg.targetContainer, "sh", "-lc", "true"); err == nil {
		return "sh", nil
	}
	return "", fmt.Errorf("failed to locate a usable shell (bash or sh) inside %s", r.cfg.targetContainer)
}

func (r *runner) execNonInteractive(ctx context.Context, shellBin, cmd string) (int, error) {
	dockerArgs := []string{"exec", "-i", "-w", r.cfg.callerDir, r.cfg.targetContainer, shellBin, "-lc", "exec " + cmd}
	execCmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	if err := execCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 0, err
	}
	return 0, nil
}

func (r *runner) precheckInteractive(ctx context.Context, shellBin, runCmd string) error {
	tmp, err := os.CreateTemp("", "leash-runner-precheck-*.log")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	args := []string{"exec", "-it", "-w", r.cfg.callerDir, r.cfg.targetContainer, shellBin, "-lc", "true"}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, tmp)
	cmd.Stdin = os.Stdin
	err = cmd.Run()
	if err == nil {
		return nil
	}

	data, _ := os.ReadFile(tmp.Name())
	msg := strings.ToLower(string(data))
	fmt.Fprintln(os.Stderr, "Interactive docker exec precheck failed; containers will remain running.")
	if strings.Contains(msg, "setns") && strings.Contains(msg, "permission denied") {
		fmt.Fprintf(os.Stderr, "Hint: Docker Desktop blocks setns; attach manually with: docker exec -it %s %s -lc 'exec %s'\n", r.cfg.targetContainer, shellBin, runCmd)
	} else if len(data) > 0 {
		fmt.Fprintln(os.Stderr, strings.TrimSpace(string(data)))
		fmt.Fprintf(os.Stderr, "Attach manually with: docker exec -it %s %s -lc 'exec %s'\n", r.cfg.targetContainer, shellBin, runCmd)
	} else {
		fmt.Fprintf(os.Stderr, "Attach manually with: docker exec -it %s %s -lc 'exec %s'\n", r.cfg.targetContainer, shellBin, runCmd)
	}
	return fmt.Errorf("docker exec precheck failed: %w", err)
}

func (r *runner) execInteractive(shellBin, cmd string) (int, error) {
	tmp, err := os.CreateTemp("", "leash-runner-exec-*.log")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	args := []string{"exec", "-it", "-w", r.cfg.callerDir, r.cfg.targetContainer, shellBin, "-lc", "exec " + cmd}
	execCmd := exec.Command("docker", args...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = io.MultiWriter(os.Stderr, tmp)
	err = execCmd.Run()
	if err == nil {
		return 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		data, _ := os.ReadFile(tmp.Name())
		msg := strings.ToLower(string(data))
		if strings.Contains(msg, "setns") && strings.Contains(msg, "permission denied") {
			fmt.Fprintf(os.Stderr, "Interactive docker exec failed due to setns permission issue; containers remain running. Attach manually with: docker exec -it %s %s -lc 'exec %s'\n", r.cfg.targetContainer, shellBin, cmd)
			return exitErr.ExitCode(), fmt.Errorf("docker exec failed: %w", err)
		}
		return exitErr.ExitCode(), nil
	}
	return 0, err
}

// finalizeSession keeps two concerns separate:
//   - Container teardown is best-effort. Cleanup failures log under verbose mode
//     but never override the exit status returned by the leashed command.
//   - The leashed command's exit code flows back to the caller unchanged, preserving
//     distinct status values.
func (r *runner) finalizeSession(stopErr error, exitCode int) error {
	if stopErr != nil {
		r.debugf("failed to stop containers cleanly: %v", stopErr)
	}
	if exitCode != 0 {
		// Do not wrap inside fmt.Errorf; Main() unwraps ExitCodeError so it can
		// call os.Exit with the original status.
		return &ExitCodeError{code: exitCode}
	}
	return nil
}

func cleanupContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	if ctx.Err() != nil {
		return context.Background()
	}
	return ctx
}

// finishLifecycle centralizes teardown so callers only pass the command result and any error;
// it stops containers unless keepContainers is set and preserves the command's exit semantics.
func (r *runner) finishLifecycle(ctx context.Context, exitCode int, runErr error) error {
	if r.keepContainers {
		if runErr != nil {
			return runErr
		}
		if exitCode != 0 {
			return &ExitCodeError{code: exitCode}
		}
		return nil
	}

	stopCtx := cleanupContext(ctx)
	stopErr := r.stopContainers(stopCtx)
	if runErr != nil {
		if stopErr != nil {
			r.debugf("failed to stop containers after error: %v", stopErr)
		}
		return runErr
	}
	return r.finalizeSession(stopErr, exitCode)
}

func (r *runner) stopContainers(ctx context.Context) error {
	if r.cfg.shareDir == "" {
		if share := r.discoverShareDir(ctx); share != "" {
			r.cfg.shareDir = share
		}
	}

	remove := func(name string) {
		cmd := exec.CommandContext(ctx, "docker", "rm", "-f", name)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		_ = cmd.Run()
	}
	remove(r.cfg.leashContainer)
	remove(r.cfg.targetContainer)

	if r.cfg.shareDir != "" && !r.cfg.shareDirFromEnv {
		if r.shareDirCreated || strings.HasPrefix(r.cfg.shareDir, r.cfg.workDir+string(os.PathSeparator)) {
			_ = os.RemoveAll(r.cfg.shareDir)
		}
	}
	if r.cfg.workDirIsTemp && r.cfg.workDir != "" {
		if err := os.RemoveAll(r.cfg.workDir); err != nil {
			r.debugf("failed to remove work dir %s: %v", r.cfg.workDir, err)
		}
	}
	return nil
}

func (r *runner) showStatus(ctx context.Context) error {
	out, err := commandOutput(ctx, "docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}")
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var printed bool
	for _, line := range lines {
		if strings.Contains(line, r.cfg.targetContainer) || strings.Contains(line, r.cfg.leashContainer) {
			fmt.Println(line)
			printed = true
		}
	}
	if !printed {
		fmt.Println("No leash-related containers are running.")
	}
	return nil
}

func (r *runner) containerRunning(ctx context.Context, name string) (bool, error) {
	out, err := commandOutput(ctx, "docker", "inspect", "-f", "{{.State.Running}}", name)
	if err != nil {
		if strings.Contains(err.Error(), "No such object") {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(out) == "true", nil
}

func (r *runner) containerExists(ctx context.Context, name string) (bool, error) {
	if _, err := commandOutput(ctx, "docker", "inspect", "-f", "{{.Name}}", name); err != nil {
		if strings.Contains(err.Error(), "No such object") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *runner) discoverShareDir(ctx context.Context) string {
	for _, name := range []string{r.cfg.targetContainer, r.cfg.leashContainer} {
		out, err := commandOutput(ctx, "docker", "inspect", "--format", "{{range .Mounts}}{{if eq .Destination \"/leash\"}}{{.Source}}{{end}}{{end}}", name)
		if err == nil {
			candidate := strings.TrimSpace(out)
			if candidate != "" {
				return candidate
			}
		}
	}
	return ""
}

func (r *runner) installPromptAssets(ctx context.Context) error {
	script := strings.TrimSpace(assets.LeashPromptScript)
	if script == "" {
		return nil
	}

	if err := r.execShellInTarget(ctx, "mkdir -p /etc/profile.d /etc/zshrc.d"); err != nil {
		return fmt.Errorf("prepare profile directories: %w", err)
	}

	if err := r.execShellInTargetWithInput(ctx, "cat > /etc/profile.d/000-leash_prompt.sh && chmod 0644 /etc/profile.d/000-leash_prompt.sh", strings.NewReader(script+"\n")); err != nil {
		return fmt.Errorf("install prompt script: %w", err)
	}

	loader := ". /etc/profile.d/000-leash_prompt.sh\n"
	if err := r.execShellInTargetWithInput(ctx, "cat > /etc/zshrc.d/000-leash_prompt.zsh && chmod 0644 /etc/zshrc.d/000-leash_prompt.zsh", strings.NewReader(loader)); err != nil {
		return fmt.Errorf("install zsh loader: %w", err)
	}

	if err := r.execShellInTargetWithInput(ctx, "cat > /etc/ksh.kshrc && chmod 0644 /etc/ksh.kshrc", strings.NewReader(loader)); err != nil {
		return fmt.Errorf("install ksh loader: %w", err)
	}

	if err := r.execShellInTargetWithInput(ctx, "cat > /etc/profile.d/000-leash_env.sh && chmod 0644 /etc/profile.d/000-leash_env.sh", strings.NewReader("export ENV=/etc/ksh.kshrc\n")); err != nil {
		return fmt.Errorf("install ENV shim: %w", err)
	}

	bashHook := "\n# leash prompt\nif [ -f /etc/profile.d/000-leash_prompt.sh ]; then . /etc/profile.d/000-leash_prompt.sh; fi\n"
	if err := r.execShellInTargetWithInput(ctx, "if [ -f /etc/bash.bashrc ]; then if ! grep -F '/etc/profile.d/000-leash_prompt.sh' /etc/bash.bashrc >/dev/null 2>&1; then cat >> /etc/bash.bashrc; fi; fi", strings.NewReader(bashHook)); err != nil {
		return fmt.Errorf("install bash hook: %w", err)
	}

	zshHook := "\n# leash prompt\nif [ -f /etc/profile.d/000-leash_prompt.sh ]; then source /etc/profile.d/000-leash_prompt.sh; fi\n"
	if err := r.execShellInTargetWithInput(ctx, "if [ -f /etc/zshrc ]; then if ! grep -F '/etc/profile.d/000-leash_prompt.sh' /etc/zshrc >/dev/null 2>&1; then cat >> /etc/zshrc; fi; fi", strings.NewReader(zshHook)); err != nil {
		return fmt.Errorf("install zsh hook: %w", err)
	}

	return nil
}

func (r *runner) execShellInTarget(ctx context.Context, command string) error {
	return r.execShellInTargetWithInput(ctx, command, nil)
}

func (r *runner) execShellInTargetWithInput(ctx context.Context, command string, input io.Reader) error {
	return dockerExecWithInput(ctx, r.cfg.targetContainer, command, input)
}

var runCommand = runCommandImpl
var dockerExecWithInput = dockerExecWithInputImpl

func runCommandImpl(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func dockerExecWithInputImpl(ctx context.Context, container string, shellCommand string, input io.Reader) error {
	args := []string{"exec"}
	if input != nil {
		args = append(args, "-i")
	}
	args = append(args, container, "sh", "-c", shellCommand)
	cmd := exec.CommandContext(ctx, "docker", args...)
	if input != nil {
		cmd.Stdin = input
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *runner) ensureLocalImage(ctx context.Context, image string) error {
	if _, err := commandOutput(ctx, "docker", "image", "inspect", image); err != nil {
		if strings.Contains(err.Error(), "No such object") || strings.Contains(err.Error(), "No such image") {
			fmt.Printf("Pulling container image %s...\n", image)
			if pullErr := runCommand(ctx, "docker", "pull", image); pullErr != nil {
				return fmt.Errorf("pull image %s: %w", image, pullErr)
			}
			return nil
		}
		return err
	}
	return nil
}

var commandOutput = commandOutputImpl

func commandOutputImpl(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
		}
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func shellQuote(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = quoteShellArg(p)
	}
	return strings.Join(quoted, " ")
}

func quoteShellArg(s string) string {
	if s == "" {
		return "''"
	}
	if isSafeShellWord(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func isSafeShellWord(s string) bool {
	for _, r := range s {
		if !isSafeShellRune(r) {
			return false
		}
	}
	return true
}

func isSafeShellRune(r rune) bool {
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case '@', '%', '_', '+', '=', ':', ',', '.', '/', '-':
		return true
	}
	return false
}
