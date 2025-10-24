package statsig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sdkKey           = "client-GgqUQggPklOqt6EpkH0vw12Q9zikBWiofrvObmo0esU"
	defaultEndpoint  = "https://events.statsigapi.net/v1/rgstr"
	sdkType          = "leash-go"
	httpTimeout      = 2 * time.Second
	maxAttempts      = 2
	baseBackoff      = 500 * time.Millisecond
	backoffJitterCap = 500 * time.Millisecond
	maxRetryBackoff  = 30 * time.Second
	eventQueueSize   = 20
)

var (
	endpointURL = defaultEndpoint

	configureMu   sync.Mutex
	configuredVer atomic.Value // string
	globalClient  *Client
)

func init() {
	configuredVer.Store("dev")
}

// Configure sets the version string propagated to Statsig metadata. Empty values are ignored.
func Configure(version string) {
	version = strings.TrimSpace(version)
	if version == "" {
		return
	}

	configuredVer.Store(version)

	configureMu.Lock()
	if globalClient != nil {
		globalClient.setVersion(version)
	}
	configureMu.Unlock()
}

// StartPayload captures metadata describing the active Leash mode.
type StartPayload struct {
	Mode              string
	CLIFlags          map[string]bool
	SubcommandPresent bool
}

// Client is a minimal Statsig event emitter for privacy-preserving telemetry.
type Client struct {
	disabled bool

	httpClient *http.Client

	mu        sync.Mutex
	version   string
	started   bool
	stopped   bool
	startTime time.Time
	mode      string
	cliFlags  map[string]bool
	hasSubcmd bool

	policyTotal       atomic.Uint64
	policyErrorsTotal atomic.Uint64

	sendOnce     sync.Once
	shutdownOnce sync.Once
	events       chan eventPayload
}

// Start begins telemetry for the provided payload. Subsequent calls are ignored.
func Start(ctx context.Context, payload StartPayload) {
	getClient().start(ctx, payload)
}

// Stop flushes aggregated telemetry. Subsequent calls are ignored.
func Stop(ctx context.Context) {
	getClient().stop(ctx)
}

// IncPolicyUpdate increments the policy update counters tracked for the current session.
func IncPolicyUpdate(failed bool) {
	getClient().incPolicyUpdate(failed)
}

// RecordPolicyUpdate inspects the provided fields and increments policy update counters.
func RecordPolicyUpdate(fields map[string]any) {
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
	IncPolicyUpdate(failed)
}

func getClient() *Client {
	configureMu.Lock()
	defer configureMu.Unlock()

	if globalClient != nil {
		return globalClient
	}

	version, _ := configuredVer.Load().(string)
	globalClient = newClient(version)
	return globalClient
}

func newClient(version string) *Client {
	key := strings.TrimSpace(sdkKey)
	disabled := telemetryDisabled() || key == ""

	c := &Client{
		disabled:   disabled,
		version:    sanitizeVersion(version),
		httpClient: &http.Client{Timeout: httpTimeout},
		events:     make(chan eventPayload, eventQueueSize),
	}
	return c
}

func (c *Client) setVersion(version string) {
	version = sanitizeVersion(version)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version = version
}

func (c *Client) start(ctx context.Context, payload StartPayload) {
	if c.disabled {
		return
	}
	_ = ctx

	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}

	c.started = true
	c.mode = strings.TrimSpace(payload.Mode)
	c.cliFlags = cloneBoolMap(payload.CLIFlags)
	c.hasSubcmd = payload.SubcommandPresent
	c.startTime = time.Now()
	version := c.version
	c.mu.Unlock()

	event := buildStartEvent(version, c.mode, c.cliFlags, c.hasSubcmd)
	c.enqueueEvent(event)
}

func (c *Client) stop(ctx context.Context) {
	if c.disabled {
		return
	}
	_ = ctx

	c.mu.Lock()
	if !c.started || c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	start := c.startTime
	mode := c.mode
	version := c.version
	c.mu.Unlock()

	duration := time.Since(start)
	event := buildSessionEvent(version, mode, duration, c.policyTotal.Load(), c.policyErrorsTotal.Load())
	c.enqueueEvent(event)
}

func (c *Client) enqueueEvent(event eventPayload) {
	if c.disabled {
		return
	}

	c.startSender()

	select {
	case c.events <- event:
	default:
	}
}

func (c *Client) startSender() {
	c.sendOnce.Do(func() {
		go c.sender()
	})
}

func (c *Client) sender() {
	for event := range c.events {
		c.deliverWithRetry(event)
	}
}

func (c *Client) deliverWithRetry(event eventPayload) {
	attempt := 0
	for {
		if err := c.sendEvents(context.Background(), []eventPayload{event}); err == nil {
			return
		}

		attempt++
		time.Sleep(retryBackoff(attempt))
	}
}

func (c *Client) incPolicyUpdate(failed bool) {
	if failed {
		c.policyErrorsTotal.Add(1)
	}
	c.policyTotal.Add(1)
}

func (c *Client) sendEvents(ctx context.Context, events []eventPayload) error {
	if c.disabled {
		return nil
	}
	if len(events) == 0 {
		return nil
	}

	payload := requestPayload{
		Events: events,
		StatsigMetadata: statsigMetadata{
			SDKType:    sdkType,
			SDKVersion: c.version,
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	reqURL, err := buildRequestURL(len(events), c.version)
	if err != nil {
		return err
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
		if reqErr != nil {
			return reqErr
		}

		req.Header.Set("Content-Type", "application/json")

		resp, doErr := c.httpClient.Do(req)
		if doErr == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		if doErr == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		if !shouldRetry(doErr, resp) {
			if doErr != nil {
				return doErr
			}
			return errors.New(resp.Status)
		}

		backoff := baseBackoff + time.Duration(randN(int64(backoffJitterCap)))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil
}

func buildRequestURL(eventCount int, version string) (string, error) {
	base, err := url.Parse(endpointURL)
	if err != nil {
		return "", err
	}

	params := base.Query()
	params.Set("k", sdkKey)
	params.Set("st", sdkType)
	params.Set("sv", version)
	params.Set("t", strconv.FormatInt(time.Now().UnixMilli(), 10))
	params.Set("ec", strconv.Itoa(eventCount))
	base.RawQuery = params.Encode()
	return base.String(), nil
}

func shouldRetry(err error, resp *http.Response) bool {
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) {
			return true
		}
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return true
		}
		return false
	}

	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusRequestTimeout {
		return true
	}
	if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
		return true
	}
	return false
}

func buildStartEvent(version, mode string, flags map[string]bool, hasSubcommand bool) eventPayload {
	metadata := map[string]any{
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
		"mode":    sanitizeMode(mode),
		"version": version,
	}

	if len(flags) > 0 {
		metadata["cli_flags"] = flags
	}
	metadata["subcommand_present"] = hasSubcommand

	return eventPayload{
		EventName: "leash.start",
		Time:      time.Now().UnixMilli(),
		Metadata:  metadata,
	}
}

func buildSessionEvent(version, mode string, duration time.Duration, policyTotal, policyErrors uint64) eventPayload {
	metadata := map[string]any{
		"mode":                       sanitizeMode(mode),
		"version":                    version,
		"duration_ms":                roundDurationMillis(duration),
		"policy_updates_total":       policyTotal,
		"policy_update_errors_total": policyErrors,
	}

	return eventPayload{
		EventName: "leash.session",
		Time:      time.Now().UnixMilli(),
		Metadata:  metadata,
	}
}

func roundDurationMillis(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	const step = 10 * time.Second
	rounded := time.Duration((d + step/2) / step * step)
	return rounded.Milliseconds()
}

func sanitizeMode(mode string) string {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return "unknown"
	}
	return mode
}

func sanitizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "dev"
	}
	return v
}

func telemetryDisabled() bool {
	value, ok := os.LookupEnv("LEASH_DISABLE_TELEMETRY")
	if !ok {
		return false
	}
	return strings.TrimSpace(value) != ""
}

func cloneBoolMap(input map[string]bool) map[string]bool {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]bool, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

type eventPayload struct {
	EventName string         `json:"eventName"`
	User      interface{}    `json:"user"`
	Time      int64          `json:"time"`
	Metadata  map[string]any `json:"metadata"`
}

type statsigMetadata struct {
	SDKType    string `json:"sdkType"`
	SDKVersion string `json:"sdkVersion"`
}

type requestPayload struct {
	Events          []eventPayload  `json:"events"`
	StatsigMetadata statsigMetadata `json:"statsigMetadata"`
}

var randSource atomic.Uint64

func randN(limit int64) int64 {
	if limit <= 0 {
		return 0
	}
	next := randSource.Add(1)
	return int64(next % uint64(limit))
}

func retryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}

	delay := baseBackoff
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= maxRetryBackoff {
			delay = maxRetryBackoff
			break
		}
	}

	delay += time.Duration(randN(int64(backoffJitterCap)))
	if delay > maxRetryBackoff {
		return maxRetryBackoff
	}
	return delay
}

func (c *Client) shutdown() {
	c.shutdownOnce.Do(func() {
		close(c.events)
	})
}
