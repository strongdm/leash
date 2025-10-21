package listen

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const defaultPort = "18080"

// Config represents a normalized listen target derived from CLI/environment input.
type Config struct {
	Host    string
	Port    string
	Disable bool
}

// Default returns the standard listen configuration when no explicit value is provided.
func Default() Config {
	return Config{Host: "", Port: defaultPort, Disable: false}
}

// Parse interprets a raw listen argument. Empty strings disable listening, host-only
// values inherit the default port, and bare ports or :port forms override the default.
func Parse(raw string) (Config, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Config{Disable: true}, nil
	}

	var host, port string

	switch {
	case strings.HasPrefix(value, "[") && strings.Contains(value, "]:"):
		closing := strings.LastIndex(value, "]:")
		if closing == -1 {
			return Config{}, fmt.Errorf("invalid listen address %q", value)
		}
		host = strings.TrimSpace(value[1:closing])
		port = strings.TrimSpace(value[closing+2:])
	case strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]"):
		host = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
	case strings.HasPrefix(value, ":"):
		port = strings.TrimSpace(value[1:])
	case isDigits(value):
		port = value
	case strings.Contains(value, ":"):
		h, p, err := net.SplitHostPort(value)
		if err != nil {
			return Config{}, fmt.Errorf("invalid listen address %q: %w", value, err)
		}
		host = strings.TrimSpace(h)
		port = strings.TrimSpace(p)
	default:
		host = value
	}

	if port == "" {
		port = defaultPort
	}

	if err := validatePort(port); err != nil {
		return Config{}, err
	}

	return Config{
		Host:    normalizeHost(host),
		Port:    port,
		Disable: false,
	}, nil
}

// Address returns the bind string for http.ListenAndServe.
func (c Config) Address() string {
	if c.Disable {
		return ""
	}
	if c.Host == "" {
		return ":" + c.Port
	}
	return net.JoinHostPort(c.Host, c.Port)
}

// DockerPublish returns the docker -p argument for this listen configuration.
func (c Config) DockerPublish() string {
	if c.Disable {
		return ""
	}
	if c.Host == "" {
		return fmt.Sprintf("%s:%s", c.Port, c.Port)
	}
	host := c.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%s:%s", host, c.Port, c.Port)
}

// DisplayURL renders a human-friendly URL for CLI output.
func (c Config) DisplayURL() string {
	if c.Disable {
		return ""
	}
	host := c.Host
	switch host {
	case "", "0.0.0.0":
		host = "localhost"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("http://%s:%s/", host, c.Port)
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func validatePort(value string) error {
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 || n > 65535 {
		return fmt.Errorf("invalid listen port %q", value)
	}
	return nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return host
}

// OpenURL launches the default browser with the provided URL using platform-specific commands.
func OpenURL(url string) error {
	var err error
	rt := runtime.GOOS
	switch rt {
	case "darwin":
		err = exec.Command("open", url).Start()
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		err = fmt.Errorf("Unsupported runtime")
	}

	if err != nil {
		return fmt.Errorf("Unable to open browser window for runtime, %s: %v", rt, err)
	}
	return nil
}
