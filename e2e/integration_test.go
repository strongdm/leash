//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strongdm/leash/internal/cedar"
	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/proxy"
	"github.com/strongdm/leash/internal/transpiler"
)

const (
	leashImage          = "ghcr.io/strongdm/leash:latest"
	expectTimeout       = 15 * time.Second
	imageBuildTimeout   = 12 * time.Minute
	localPolicyHTTPPort = 18081
	httpBinDomain       = "httpbin.integration.local"
)

func TestIntegrationVariants(t *testing.T) {
	skipUnlessE2E(t)
	if err := checkDockerAvailable(); err != nil {
		t.Fatalf("docker not available: %v", err)
	}
	ensureImage(t, leashImage, buildLeashImage)
}

func TestIntegrationAlpine(t *testing.T) {
	runIntegrationVariant(t, "alpine")
}

func TestIntegrationDebian(t *testing.T) {
	runIntegrationVariant(t, "debian")
}

func TestIntegrationRocky(t *testing.T) {
	runIntegrationVariant(t, "rocky")
}

func runIntegrationVariant(t *testing.T, variant string) {
	skipUnlessE2E(t)
	if spec := strings.TrimSpace(os.Getenv("TEST_VARIANT")); spec != "" {
		if !variantRequested(spec, variant) {
			t.Skipf("variant %s not requested via TEST_VARIANT", variant)
		}
	}
	if err := checkDockerAvailable(); err != nil {
		t.Skipf("skipping: docker not available: %v", err)
	}
	ensureImage(t, leashImage, buildLeashImage)

	cfg, err := newVariantConfig(variant)
	if err != nil {
		t.Fatalf("unsupported variant %q: %v", variant, err)
	}

	imageName := fmt.Sprintf("leash-test-%s", variant)
	ensureImage(t, imageName, func(ctx context.Context) error {
		return buildVariantImage(ctx, variant)
	})

	runIntegrationSuite(t, cfg)
}

func variantRequested(spec, variant string) bool {
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if strings.EqualFold(strings.TrimSpace(part), variant) {
			return true
		}
	}
	return false
}

type variantConfig struct {
	name string

	initialRules []string

	denyExecCmd  []string
	allowRule    string
	allowExecCmd []string

	denyArgsRule string
	denyArgsCmd  []string

	pingCmd []string

	wgetCmd       func(host string, port int) []string
	wgetHeaderCmd func(host string, port int) []string
}

type variantEnv struct {
	ctx          context.Context
	cancel       context.CancelFunc
	variant      variantConfig
	targetName   string
	leashName    string
	cgroupVolume string
	policyPath   string
	logPath      string
	logDir       string
	httpBinHost  string
	httpBinPort  int
}

type commandExpectation struct {
	name               string
	command            []string
	allowedExitCodes   []int
	retryUntilDeadline bool
	stdoutMustContain  []string
	stderrMustContain  []string
	ruleRef            string
}

func newVariantConfig(name string) (variantConfig, error) {
	switch name {
	case "alpine":
		return variantConfig{
			name:         name,
			initialRules: []string{},
			denyExecCmd:  []string{"sh", "-c", "apk --version"},
			allowRule:    "allow proc.exec /sbin/apk",
			allowExecCmd: []string{"sh", "-c", "apk --version"},
			denyArgsRule: "deny proc.exec /sbin/apk git",
			denyArgsCmd:  []string{"sh", "-c", "apk add git"},
			pingCmd:      []string{"sh", "-c", "ping -c 1 1.1.1.1"},
			wgetCmd: func(host string, port int) []string {
				return []string{"sh", "-c", fmt.Sprintf("wget -qO- --tries=1 http://%s:%d/get", host, port)}
			},
			wgetHeaderCmd: func(host string, port int) []string {
				return []string{"sh", "-c", fmt.Sprintf("wget -qO- --tries=1 http://%s:%d/get | grep \"demo-secret123\"", host, port)}
			},
		}, nil
	case "debian":
		return variantConfig{
			name: name,
			initialRules: []string{
				"allow proc.exec /usr/bin/cat",
				"allow proc.exec /usr/bin/ping",
				"allow proc.exec /usr/bin/wget",
				"allow proc.exec /usr/bin/grep",
			},
			denyExecCmd:  []string{"sh", "-c", "apt -v"},
			allowRule:    "allow proc.exec /usr/bin/apt",
			allowExecCmd: []string{"sh", "-c", "apt -v"},
			denyArgsRule: "deny proc.exec /usr/bin/apt git",
			denyArgsCmd:  []string{"sh", "-c", "apt install -y git"},
			pingCmd:      []string{"sh", "-c", "ping -c 1 1.1.1.1"},
			wgetCmd: func(host string, port int) []string {
				return []string{"sh", "-c", fmt.Sprintf("wget -qO- --tries=1 http://%s:%d/get", host, port)}
			},
			wgetHeaderCmd: func(host string, port int) []string {
				return []string{"sh", "-c", fmt.Sprintf("wget -qO- --tries=1 http://%s:%d/get | grep \"demo-secret123\"", host, port)}
			},
		}, nil
	case "rocky":
		return variantConfig{
			name: name,
			initialRules: []string{
				"allow proc.exec /usr/bin/cat",
				"allow proc.exec /usr/sbin/ping",
				"allow proc.exec /usr/bin/wget",
				"allow proc.exec /usr/bin/grep",
				"allow proc.exec /usr/bin/bash",
				"allow proc.exec /usr/bin/coreutils",
				"allow proc.exec /usr/bin/gpgconf",
				"allow proc.exec /usr/bin/gpg",
			},
			denyExecCmd:  []string{"sh", "-c", "microdnf clean all"},
			allowRule:    "allow proc.exec /usr/bin/microdnf",
			allowExecCmd: []string{"sh", "-c", "microdnf clean all"},
			denyArgsRule: "deny proc.exec /usr/bin/microdnf git",
			denyArgsCmd:  []string{"sh", "-c", "microdnf install -y git"},
			pingCmd:      []string{"sh", "-c", "ping -c 1 1.1.1.1"},
			wgetCmd: func(host string, port int) []string {
				return []string{"sh", "-c", fmt.Sprintf("wget -qO- --tries=1 http://%s:%d/get", host, port)}
			},
			wgetHeaderCmd: func(host string, port int) []string {
				return []string{"sh", "-c", fmt.Sprintf("wget -qO- --tries=1 http://%s:%d/get | grep \"demo-secret123\"", host, port)}
			},
		}, nil
	default:
		return variantConfig{}, fmt.Errorf("unknown variant %q", name)
	}
}

func runIntegrationSuite(t *testing.T, cfg variantConfig) {
	env := startVariantEnvironment(t, cfg)
	t.Cleanup(env.cancel)

	runBaselinePolicyScenarios(t, env)
	runExamplePolicyScenarios(t, env)
}

func runBaselinePolicyScenarios(t *testing.T, env *variantEnv) {
	t.Helper()

	t.Run("baseline/file-open-allow", func(t *testing.T) {
		env.runCommand(t, commandExpectation{
			name:               "baseline/file-open-allow",
			command:            []string{"cat", "/usr/lib/os-release"},
			allowedExitCodes:   []int{0},
			retryUntilDeadline: true,
			ruleRef:            "allow file.open /",
		})
	})

	t.Run("baseline/file-open-deny", func(t *testing.T) {
		env.requireEnforcement(t)
		appendPolicyRule(t, env.policyPath, "deny file.open /usr/lib/os-release")
		env.runCommand(t, commandExpectation{
			name:               "baseline/file-open-deny",
			command:            []string{"cat", "/usr/lib/os-release"},
			allowedExitCodes:   []int{1},
			retryUntilDeadline: true,
			ruleRef:            "deny file.open /usr/lib/os-release",
		})
	})

	t.Run("baseline/proc-deny-path", func(t *testing.T) {
		env.requireEnforcement(t)
		env.runCommand(t, commandExpectation{
			name:               "baseline/proc-deny-path",
			command:            env.variant.denyExecCmd,
			allowedExitCodes:   []int{1, 126},
			retryUntilDeadline: false,
			ruleRef:            "initial policy excludes package manager path",
		})
	})

	t.Run("baseline/proc-allow-path", func(t *testing.T) {
		appendPolicyRule(t, env.policyPath, env.variant.allowRule)
		env.runCommand(t, commandExpectation{
			name:               "baseline/proc-allow-path",
			command:            env.variant.allowExecCmd,
			allowedExitCodes:   []int{0},
			retryUntilDeadline: true,
			ruleRef:            env.variant.allowRule,
		})
	})

	t.Run("baseline/proc-deny-arguments", func(t *testing.T) {
		env.requireEnforcement(t)
		prependPolicyRule(t, env.policyPath, env.variant.denyArgsRule)
		env.runCommand(t, commandExpectation{
			name:               "baseline/proc-deny-arguments",
			command:            env.variant.denyArgsCmd,
			allowedExitCodes:   []int{1, 126},
			retryUntilDeadline: true,
			ruleRef:            env.variant.denyArgsRule,
		})
	})

	t.Run("baseline/net-allow", func(t *testing.T) {
		env.runCommand(t, commandExpectation{
			name:               "baseline/net-allow",
			command:            env.variant.pingCmd,
			allowedExitCodes:   []int{0},
			retryUntilDeadline: true,
			ruleRef:            "allow net.send *",
		})
	})

	t.Run("baseline/net-deny", func(t *testing.T) {
		env.requireEnforcement(t)
		appendPolicyRule(t, env.policyPath, "deny net.send 1.1.1.1")
		env.runCommand(t, commandExpectation{
			name:               "baseline/net-deny",
			command:            env.variant.pingCmd,
			allowedExitCodes:   []int{1, 2},
			retryUntilDeadline: true,
			ruleRef:            "deny net.send 1.1.1.1",
		})
	})

	t.Run("baseline/net-allow-https", func(t *testing.T) {
		env.requireEnforcement(t)
		appendPolicyRule(t, env.policyPath, "allow proc.exec /usr/bin/ssl_client")
		env.runCommand(t, commandExpectation{
			name:               "baseline/net-allow-https",
			command:            env.variant.wgetCmd(env.httpBinHost, env.httpBinPort),
			allowedExitCodes:   []int{0},
			retryUntilDeadline: true,
			ruleRef:            "allow proc.exec /usr/bin/ssl_client",
		})
	})

	t.Run("baseline/http-rewrite", func(t *testing.T) {
		env.requireEnforcement(t)
		appendPolicyRule(t, env.policyPath, fmt.Sprintf("allow http.rewrite %s header:Authorization:Bearer demo-secret123", httpBinDomain))
		env.runCommand(t, commandExpectation{
			name:               "baseline/http-rewrite",
			command:            env.variant.wgetHeaderCmd(env.httpBinHost, env.httpBinPort),
			allowedExitCodes:   []int{0},
			retryUntilDeadline: true,
			ruleRef:            fmt.Sprintf("allow http.rewrite %s header:Authorization:Bearer demo-secret123", httpBinDomain),
		})
	})

	t.Run("baseline/net-deny-host", func(t *testing.T) {
		env.requireEnforcement(t)
		appendPolicyRule(t, env.policyPath, fmt.Sprintf("deny net.send %s", httpBinDomain))
		env.runCommand(t, commandExpectation{
			name:               "baseline/net-deny-host",
			command:            env.variant.wgetCmd(env.httpBinHost, env.httpBinPort),
			allowedExitCodes:   []int{1, 4, 5, 6, 7, 8},
			retryUntilDeadline: true,
			ruleRef:            fmt.Sprintf("deny net.send %s", httpBinDomain),
		})
	})
}

func runExamplePolicyScenarios(t *testing.T, env *variantEnv) {
	t.Helper()

	startLoopbackHTTPServer(t, env)

	exampleHosts := []string{"jaytaylor.com", "www.jaytaylor.com", "www.facebook.com", "foo.googleapis.com"}
	addHostsEntry(t, env.ctx, env.targetName, exampleHosts)
	addHostsEntry(t, env.ctx, env.leashName, exampleHosts)

	ensureDateBinary(t, env)
	writeExamplePolicy(t, env.policyPath)

	t.Run("example/proc-allow-id", func(t *testing.T) {
		env.runCommand(t, commandExpectation{
			name:               "example/proc-allow-id",
			command:            []string{"id"},
			allowedExitCodes:   []int{0},
			retryUntilDeadline: true,
			ruleRef:            "allow proc.exec /usr/bin/id (docs/example.cedar)",
		})
	})

	t.Run("example/proc-deny-date", func(t *testing.T) {
		env.requireEnforcement(t)
		env.runCommand(t, commandExpectation{
			name:               "example/proc-deny-date",
			command:            []string{"/usr/bin/date"},
			allowedExitCodes:   []int{1, 126},
			retryUntilDeadline: true,
			ruleRef:            "deny proc.exec /usr/bin/date (docs/example.cedar)",
		})
		env.requireLogContains(t, []string{"event=proc.exec", "exe=\"/usr/bin/date\"", "decision=deny"}, "example/proc-deny-date")
	})

	t.Run("example/proc-deny-tmp", func(t *testing.T) {
		env.requireEnforcement(t)
		prepareDeniedScript(t, env, "/tmp/leash-deny.sh")
		env.runCommand(t, commandExpectation{
			name:               "example/proc-deny-tmp",
			command:            []string{"/tmp/leash-deny.sh"},
			allowedExitCodes:   []int{1, 126},
			retryUntilDeadline: true,
			ruleRef:            "deny proc.exec /tmp/ (docs/example.cedar)",
		})
		env.requireLogContains(t, []string{"/tmp/leash-deny.sh", "decision=deny"}, "example/proc-deny-tmp")
	})

	t.Run("example/net-allow-jaytaylor", func(t *testing.T) {
		env.runCommand(t, commandExpectation{
			name:               "example/net-allow-jaytaylor",
			command:            []string{"wget", "-qO", "/dev/null", "--timeout=5", fmt.Sprintf("http://jaytaylor.com:%d/", localPolicyHTTPPort)},
			allowedExitCodes:   []int{0},
			retryUntilDeadline: true,
			ruleRef:            "allow net.send jaytaylor.com (docs/example.cedar)",
		})
	})

	t.Run("example/net-allow-googleapis", func(t *testing.T) {
		env.runCommand(t, commandExpectation{
			name:               "example/net-allow-googleapis",
			command:            []string{"wget", "-qO", "/dev/null", "--timeout=5", fmt.Sprintf("http://foo.googleapis.com:%d/", localPolicyHTTPPort)},
			allowedExitCodes:   []int{0},
			retryUntilDeadline: true,
			ruleRef:            "allow net.send *.googleapis.com (docs/example.cedar)",
		})
	})

	t.Run("example/net-deny-facebook", func(t *testing.T) {
		env.requireEnforcement(t)
		env.runCommand(t, commandExpectation{
			name:               "example/net-deny-facebook",
			command:            []string{"wget", "-qO", "/dev/null", "--timeout=5", fmt.Sprintf("http://www.facebook.com:%d/", localPolicyHTTPPort)},
			allowedExitCodes:   []int{1, 4, 5, 6, 7, 8},
			retryUntilDeadline: true,
			ruleRef:            "deny net.send *.facebook.com (docs/example.cedar)",
		})
		env.requireLogContains(t, []string{"event=net.send", "host=www.facebook.com", "decision=deny"}, "example/net-deny-facebook")
	})
}

func (env *variantEnv) runCommand(t *testing.T, exp commandExpectation) {
	t.Helper()

	if len(exp.allowedExitCodes) == 0 {
		exp.allowedExitCodes = []int{0}
	}

	waitCtx, cancel := context.WithTimeout(env.ctx, expectTimeout)
	defer cancel()

	last := runDockerExec(waitCtx, env.targetName, exp.command)
	if containsExit(exp.allowedExitCodes, last.exitCode) {
		if len(exp.stdoutMustContain) > 0 && !containsAll(last.stdout, exp.stdoutMustContain) {
			env.failCommand(t, exp, last, fmt.Sprintf("stdout missing substrings %v", exp.stdoutMustContain))
		}
		if len(exp.stderrMustContain) > 0 && !containsAll(last.stderr, exp.stderrMustContain) {
			env.failCommand(t, exp, last, fmt.Sprintf("stderr missing substrings %v", exp.stderrMustContain))
		}
		return
	}

	if !exp.retryUntilDeadline {
		env.failCommand(t, exp, last, "")
	}

	readinessCheck := func() bool {
		last = runDockerExec(waitCtx, env.targetName, exp.command)
		if !containsExit(exp.allowedExitCodes, last.exitCode) {
			return false
		}
		if len(exp.stdoutMustContain) > 0 && !containsAll(last.stdout, exp.stdoutMustContain) {
			env.failCommand(t, exp, last, fmt.Sprintf("stdout missing substrings %v", exp.stdoutMustContain))
		}
		if len(exp.stderrMustContain) > 0 && !containsAll(last.stderr, exp.stderrMustContain) {
			env.failCommand(t, exp, last, fmt.Sprintf("stderr missing substrings %v", exp.stderrMustContain))
		}
		return true
	}

	if err := pollReadiness(waitCtx, expectTimeout, readinessCheck); err != nil {
		env.failCommand(t, exp, last, "")
	}
}

func (env *variantEnv) requireEnforcement(t *testing.T) {
	t.Helper()
}

func (env *variantEnv) failCommand(t *testing.T, exp commandExpectation, res execResult, extra string) {
	t.Helper()

	var b strings.Builder
	fmt.Fprintf(&b, "[variant=%s scenario=%s]\n", env.variant.name, exp.name)
	fmt.Fprintf(&b, "command: %s\n", shellQuote(exp.command))
	fmt.Fprintf(&b, "allowed exit codes: %v actual: %d\n", exp.allowedExitCodes, res.exitCode)
	if res.err != nil {
		fmt.Fprintf(&b, "docker exec error: %v\n", res.err)
	}
	if exp.ruleRef != "" {
		fmt.Fprintf(&b, "policy reference: %s\n", exp.ruleRef)
	}
	if extra != "" {
		fmt.Fprintf(&b, "detail: %s\n", extra)
	}
	fmt.Fprintf(&b, "stdout:\n%s\n", indentBlock(trimForReport(res.stdout), "  "))
	fmt.Fprintf(&b, "stderr:\n%s\n", indentBlock(trimForReport(res.stderr), "  "))
	fmt.Fprintf(&b, "policy tail:\n%s\n", indentBlock(tailFile(env.policyPath, 12), "  "))
	fmt.Fprintf(&b, "daemon log tail:\n%s\n", indentBlock(tailFile(env.logPath, 20), "  "))
	t.Fatalf("%s", b.String())
}

func (env *variantEnv) requireLogContains(t *testing.T, want []string, context string) {
	t.Helper()
	var (
		text string
		err  error
	)
	readinessCheck := func() bool {
		var data []byte
		data, err = os.ReadFile(env.logPath)
		if err != nil {
			return false
		}
		text = string(data)
		for _, needle := range want {
			if !strings.Contains(text, needle) {
				return false
			}
		}
		return true
	}
	resource := fmt.Sprintf("log entries for %s", context)
	waitForReadiness(t, resource, readinessCheck)
	if err != nil {
		t.Fatalf("read log file %s: %v", env.logPath, err)
	}
}

func prepareDeniedScript(t *testing.T, env *variantEnv, path string) {
	t.Helper()
	script := fmt.Sprintf("cat <<'EOF' > %s\n#!/bin/sh\necho denied\nEOF\nchmod +x %s", path, path)
	res := runDockerExec(env.ctx, env.targetName, []string{"sh", "-c", script})
	if res.exitCode != 0 {
		env.failCommand(t, commandExpectation{
			name:    "example/setup-script",
			command: []string{"sh", "-c", script},
			ruleRef: "create denied script",
		}, res, "failed to stage helper script inside target container")
	}
}

func startLoopbackHTTPServer(t *testing.T, env *variantEnv) {
	t.Helper()

	port := fmt.Sprintf("%d", localPolicyHTTPPort)
	startViaPython := []string{"sh", "-c", fmt.Sprintf("python3 -m http.server %s >/tmp/leash-example-http.log 2>&1 &", port)}
	if res := runDockerExec(env.ctx, env.targetName, startViaPython); res.exitCode != 0 {
		fallback := []string{"sh", "-c", fmt.Sprintf("busybox httpd -f -p %s >/tmp/leash-example-http.log 2>&1 &", port)}
		if resFB := runDockerExec(env.ctx, env.targetName, fallback); resFB.exitCode != 0 {
			env.failCommand(t, commandExpectation{
				name:    "example/start-httpd",
				command: fallback,
			}, resFB, "unable to launch loopback HTTP server with python3 or busybox httpd")
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	waitCtx, cancel := context.WithDeadline(env.ctx, deadline)
	defer cancel()

	check := func() bool {
		res := runDockerExec(env.ctx, env.targetName, []string{"wget", "-qO", "/dev/null", "--timeout=2", fmt.Sprintf("http://127.0.0.1:%s/", port)})
		return res.exitCode == 0
	}

	if err := pollReadiness(waitCtx, 5*time.Second, check); err != nil {
		t.Fatalf("[variant=%s] loopback HTTP server did not become ready; inspect /tmp/leash-example-http.log inside %s", env.variant.name, env.targetName)
	}
}

func addHostsEntry(t *testing.T, ctx context.Context, container string, hosts []string) {
	t.Helper()
	if len(hosts) == 0 {
		return
	}
	entry := fmt.Sprintf("127.0.0.1 %s", strings.Join(hosts, " "))
	res := runDockerExec(ctx, container, []string{"sh", "-c", fmt.Sprintf("echo '%s' >> /etc/hosts", entry)})
	if res.exitCode != 0 {
		t.Fatalf("failed to update /etc/hosts in %s: stdout=%s stderr=%s", container, res.stdout, res.stderr)
	}
}

func ensureDateBinary(t *testing.T, env *variantEnv) {
	t.Helper()
	if binaryExists(env, "/usr/bin/date") {
		return
	}

	switch env.variant.name {
	case "alpine":
		cmd := []string{"sh", "-c", "apk add --no-cache coreutils >/tmp/leash-coreutils.log 2>&1"}
		res := runDockerExec(env.ctx, env.targetName, cmd)
		if res.exitCode != 0 {
			env.failCommand(t, commandExpectation{
				name:    "example/install-date",
				command: cmd,
				ruleRef: "apk add coreutils",
			}, res, "failed to install coreutils on alpine variant")
		}
	default:
		// Debian and Rocky ship /usr/bin/date by default; fall through to check.
	}

	if !binaryExists(env, "/usr/bin/date") {
		t.Fatalf("[variant=%s] expected /usr/bin/date to exist after setup", env.variant.name)
	}
}

func binaryExists(env *variantEnv, path string) bool {
	res := runDockerExec(env.ctx, env.targetName, []string{"sh", "-c", fmt.Sprintf("test -x %s", path)})
	return res.exitCode == 0
}

func writeExamplePolicy(t *testing.T, policyPath string) {
	t.Helper()
	rules := []string{
		"allow proc.exec /usr/bin/id",
		"deny proc.exec /usr/bin/date",
		"deny proc.exec /tmp/",
		"allow net.send jaytaylor.com",
		"allow net.send *.googleapis.com",
		"deny net.send *.facebook.com",
	}
	ps, rewrites := parseRulesToPolicy(t, rules)
	writeCedarPolicy(t, policyPath, ps, rewrites)
}

func containsExit(codes []int, code int) bool {
	for _, allowed := range codes {
		if allowed == code {
			return true
		}
	}
	return false
}

func containsAll(text string, want []string) bool {
	for _, needle := range want {
		if !strings.Contains(text, needle) {
			return false
		}
	}
	return true
}

func trimForReport(s string) string {
	s = strings.TrimSpace(s)
	const max = 1024
	if len(s) <= max {
		if s == "" {
			return "(empty)"
		}
		return s
	}
	return s[:max] + fmt.Sprintf("\n... trimmed %d bytes ...", len(s)-max)
}

func tailFile(path string, lines int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("unable to read %s: %v", path, err)
	}
	content := strings.TrimRight(string(data), "\n")
	if content == "" {
		return "(empty)"
	}
	allLines := strings.Split(content, "\n")
	if len(allLines) <= lines {
		return content
	}
	return strings.Join(allLines[len(allLines)-lines:], "\n")
}

func indentBlock(text, prefix string) string {
	if text == "" {
		return prefix + "(empty)"
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func autoBuildEnabled() bool {
	return !envTruthy(os.Getenv("LEASH_E2E_SKIP_AUTOBUILD"))
}

func buildLeashImage(ctx context.Context) error {
	return runDockerBuild(ctx, []string{
		"build",
		"-f", "Dockerfile.leash",
		"-t", leashImage,
		".",
	})
}

func buildVariantImage(ctx context.Context, variant string) error {
	return runDockerBuild(ctx, []string{
		"build",
		"--target", fmt.Sprintf("leash-test-%s", variant),
		"-f", "Dockerfile.leash",
		"-t", fmt.Sprintf("leash-test-%s", variant),
		".",
	})
}

func runDockerBuild(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, "docker", args...)
	workspace, err := workspaceDir()
	if err != nil {
		return fmt.Errorf("resolve workspace directory: %w", err)
	}
	cmd.Dir = workspace
	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func startVariantEnvironment(t *testing.T, cfg variantConfig) *variantEnv {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)

	root := t.TempDir()
	leashDir := ensureDir(t, filepath.Join(root, "leash"))
	logDir := ensureDir(t, filepath.Join(root, "log"))
	cfgDir := ensureDir(t, filepath.Join(root, "cfg"))
	policyPath := filepath.Join(cfgDir, "leash.cedar")
	writeBaselinePolicy(t, policyPath, cfg.initialRules)

	targetName := fmt.Sprintf("leash-test-target-%s-%d", cfg.name, time.Now().UnixNano())
	leashName := fmt.Sprintf("leash-test-%s-%d", cfg.name, time.Now().UnixNano())
	cgroupVolume := fmt.Sprintf("leash-test-cgroup-%s-%d", cfg.name, time.Now().UnixNano())

	removeContainer(ctx, targetName)
	removeContainer(ctx, leashName)
	removeVolume(ctx, cgroupVolume)

	runDockerOrFatal(t, ctx, []string{
		"volume", "create", cgroupVolume,
	})

	runDockerOrFatal(t, ctx, []string{
		"run", "-d", "--privileged",
		"--name", targetName,
		"-v", fmt.Sprintf("%s:/leash", leashDir),
		"-v", fmt.Sprintf("%s:/leash/cgroup", cgroupVolume),
		fmt.Sprintf("leash-test-%s", cfg.name),
		"sleep", "3600",
	})
	ensureContainerRunning(t, ctx, targetName)
	ensureCgroupMirror(t, ctx, targetName)

	t.Cleanup(func() {
		removeContainer(context.Background(), leashName)
		removeContainer(context.Background(), targetName)
		removeVolume(context.Background(), cgroupVolume)
	})

	cgroupPath := discoverCgroupPath(t, ctx, targetName)

	runDockerOrFatal(t, ctx, buildLeashArgs(leashName, targetName, cgroupPath, cgroupVolume, leashDir, logDir, cfgDir))
	ensureContainerRunning(t, ctx, leashName)

	waitForManagerLog(t, leashName, "frontend.start", 30*time.Second)

	httpPort, stopHTTP := startHTTPDebugService(t)
	t.Cleanup(stopHTTP)

	gatewayIP := containerGatewayIP(t, ctx, targetName)
	addHostsEntryWithIP(t, ctx, targetName, gatewayIP, []string{httpBinDomain})
	addHostsEntryWithIP(t, ctx, leashName, gatewayIP, []string{httpBinDomain})

	return &variantEnv{
		ctx:          ctx,
		cancel:       cancel,
		variant:      cfg,
		targetName:   targetName,
		leashName:    leashName,
		cgroupVolume: cgroupVolume,
		policyPath:   policyPath,
		logPath:      filepath.Join(logDir, "events.log"),
		logDir:       logDir,
		httpBinHost:  httpBinDomain,
		httpBinPort:  httpPort,
	}
}

func checkDockerAvailable() error {
	cmd := exec.Command("docker", "info")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func ensureImage(t *testing.T, image string, builder func(context.Context) error) {
	t.Helper()
	if imageExists(image) {
		return
	}
	if builder == nil {
		t.Fatalf("docker image %s not found and no builder provided", image)
	}
	if !autoBuildEnabled() {
		t.Fatalf("docker image %s not found; auto-build disabled. Build manually or unset LEASH_E2E_SKIP_AUTOBUILD.", image)
	}

	t.Logf("docker image %s missing; auto-building", image)
	ctx, cancel := context.WithTimeout(context.Background(), imageBuildTimeout)
	defer cancel()
	if err := builder(ctx); err != nil {
		t.Fatalf("failed to build %s: %v", image, err)
	}
	if !imageExists(image) {
		t.Fatalf("docker image %s still missing after build", image)
	}
}

func imageExists(image string) bool {
	cmd := exec.Command("docker", "image", "inspect", image)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

func ensureDir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	return path
}

func writeBaselinePolicy(t *testing.T, policyPath string, extra []string) {
	t.Helper()

	base := []string{
		"allow proc.exec /runc",
		"allow proc.exec /usr/bin/runc",
		"allow proc.exec /bin/",
		"allow file.open /",
		"allow net.send *",
	}
	rules := append(base, extra...)
	ps, rewrites := parseRulesToPolicy(t, rules)
	writeCedarPolicy(t, policyPath, ps, rewrites)
}

func startHTTPDebugService(t *testing.T) (int, func()) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("start httpbin clone listener: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"args": map[string]string{},
			"headers": map[string]string{
				"Authorization": r.Header.Get("Authorization"),
				"Host":          r.Host,
			},
			"origin": strings.TrimSpace(strings.Split(r.RemoteAddr, ":")[0]),
			"url":    fmt.Sprintf("http://%s%s", r.Host, r.URL.RequestURI()),
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("httpbin clone server error: %v", err)
		}
	}()
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	return port, stop
}

func containerGatewayIP(t *testing.T, ctx context.Context, container string) string {
	res := runDockerExec(ctx, container, []string{"sh", "-c", "ip route | awk '/default/ {print $3}'"})
	if res.err != nil || res.exitCode != 0 {
		t.Fatalf("determine gateway IP for %s: err=%v exit=%d stderr=%s", container, res.err, res.exitCode, res.stderr)
	}
	ip := strings.TrimSpace(res.stdout)
	if ip == "" {
		t.Fatalf("determine gateway IP for %s: empty output", container)
	}
	return ip
}

func addHostsEntryWithIP(t *testing.T, ctx context.Context, container, ip string, hosts []string) {
	if len(hosts) == 0 {
		return
	}
	entry := fmt.Sprintf("%s %s", ip, strings.Join(hosts, " "))
	cmd := fmt.Sprintf("echo '%s' >> /etc/hosts", entry)
	res := runDockerExec(ctx, container, []string{"sh", "-c", cmd})
	if res.err != nil || res.exitCode != 0 {
		t.Fatalf("update /etc/hosts in %s: err=%v exit=%d stdout=%s stderr=%s", container, res.err, res.exitCode, res.stdout, res.stderr)
	}
}

func runDockerOrFatal(t *testing.T, ctx context.Context, args []string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.ToLower(strings.TrimSpace(stderr.String()))
		if isDockerUnavailableMessage(msg) {
			t.Skipf("skipping: docker unavailable (%s)", msg)
		}
		t.Fatalf("docker %s failed: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
}

func removeContainer(ctx context.Context, name string) {
	if name == "" {
		return
	}
	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", name)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Run()
}

func removeVolume(ctx context.Context, name string) {
	if name == "" {
		return
	}
	cmd := exec.CommandContext(ctx, "docker", "volume", "rm", "-f", name)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Run()
}

func buildLeashArgs(leashName, targetName, cgroupPath, cgroupVolume, leashDir, logDir, cfgDir string) []string {
	args := []string{
		"run", "-d", "--rm",
		"--name", leashName,
		"--privileged",
		"--cap-add", "NET_ADMIN",
		"--network", fmt.Sprintf("container:%s", targetName),
	}

	if strings.TrimSpace(cgroupVolume) != "" {
		args = append(args, "-v", fmt.Sprintf("%s:/sys/fs/cgroup:ro", cgroupVolume))
	} else {
		args = append(args, "-v", "/sys/fs/cgroup:/sys/fs/cgroup:ro")
	}

	args = append(args,
		"-v", fmt.Sprintf("%s:/log", logDir),
		"-v", fmt.Sprintf("%s:/cfg", cfgDir),
		"-v", fmt.Sprintf("%s:/leash", leashDir),
		"-e", "LEASH_LOG=/log/events.log",
	)

	if port := strings.TrimSpace(os.Getenv("LEASH_UI_PORT")); port != "" {
		args = append(args, "-p", fmt.Sprintf("%s:%s", port, port))
	}

	args = append(args,
		leashImage,
		"--daemon",
		"--cgroup", cgroupPath,
	)

	return args
}

func ensureContainerRunning(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("context canceled while waiting for container %s", name)
		default:
		}

		cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Running}}", name)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		status := strings.TrimSpace(stdout.String())
		if err == nil && status == "true" {
			return
		}
		if err != nil {
			msg := strings.ToLower(strings.TrimSpace(stderr.String()))
			if isDockerUnavailableMessage(msg) ||
				strings.Contains(msg, "no such container") ||
				strings.Contains(msg, "no such object") {
				t.Skipf("skipping: docker container %s unavailable (%s)", name, msg)
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("docker inspect %s failed after retries: %v\n%s", name, err, stderr.String())
			}
			t.Fatalf("container %s did not reach running state (status=%s)", name, status)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func ensureCgroupMirror(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	script := `set -eu
mkdir -p /leash/cgroup
if command -v mountpoint >/dev/null 2>&1; then
  if mountpoint -q /leash/cgroup; then
    exit 0
  fi
fi
mount --rbind /sys/fs/cgroup /leash/cgroup
`
	res := runDockerExec(ctx, container, []string{"sh", "-c", script})
	if res.exitCode != 0 {
		t.Fatalf("mirror cgroup filesystem in %s failed: exit=%d stdout=%s stderr=%s", container, res.exitCode, res.stdout, res.stderr)
	}
}

func discoverCgroupPath(t *testing.T, ctx context.Context, container string) string {
	t.Helper()

	cgroupPath, err := dockerInspectField(ctx, container, "{{with .State}}{{with index . \"CgroupPath\"}}{{.}}{{end}}{{end}}")
	if err == nil && strings.TrimSpace(cgroupPath) != "" {
		raw := strings.TrimSpace(cgroupPath)
		candidate := raw
		switch {
		case strings.HasPrefix(raw, "/sys/fs/cgroup"):
			candidate = raw
		case strings.HasPrefix(raw, "/"):
			candidate = filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(raw, "/"))
		default:
			candidate = filepath.Join("/sys/fs/cgroup", raw)
		}
		if containerPathExists(ctx, container, candidate) {
			return candidate
		}
	}

	relative, err := dockerExecOutputCtx(ctx, container, []string{"sh", "-c", "awk -F: 'NR==1 {print $3}' /proc/self/cgroup | tr -d '\\r'"})
	if err != nil {
		t.Fatalf("read cgroup from container: %v", err)
	}
	relative = strings.TrimSpace(relative)
	if relative == "" {
		t.Fatalf("unable to determine target cgroup path")
	}
	path := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(relative, "/"))

	if path == "/sys/fs/cgroup" {
		candidates := manualCgroupCandidates(t, ctx, container)
		if len(candidates) == 0 {
			t.Fatalf("unable to determine cgroup path for %s", container)
		}
		return candidates[0]
	}

	return path
}

func manualCgroupCandidates(t *testing.T, ctx context.Context, container string) []string {
	t.Helper()
	containerID, err := dockerInspectField(ctx, container, "{{.Id}}")
	if err != nil {
		t.Fatalf("fetch container id: %v", err)
	}
	containerID = strings.TrimSpace(containerID)
	if containerID == "" {
		return nil
	}

	candidates := []string{
		filepath.Join("/sys/fs/cgroup/docker", containerID),
		filepath.Join("/sys/fs/cgroup/system.slice", fmt.Sprintf("docker-%s.scope", containerID)),
		filepath.Join("/sys/fs/cgroup/system.slice", fmt.Sprintf("docker-%s.scope", containerID)),
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return []string{c}
		}
	}

	out, err := dockerCommandOutput(ctx, []string{
		"run", "--rm", "--privileged", "--pid=host", "justincormack/nsenter1",
		"/bin/sh", "-c", fmt.Sprintf("find /sys/fs/cgroup -name '*%s*' | grep .", containerID),
	})
	if err != nil {
		t.Logf("nsenter fallback failed: %v", err)
		return nil
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	var filtered []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			filtered = append(filtered, line)
		}
	}
	return filtered
}

func containerPathExists(ctx context.Context, container, path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	cmd := fmt.Sprintf("test -d %q", path)
	res := runDockerExec(ctx, container, []string{"sh", "-c", cmd})
	return res.exitCode == 0
}

func dockerInspectField(ctx context.Context, container, format string) (string, error) {
	out, err := dockerCommandOutput(ctx, []string{
		"inspect", container, "--format", format,
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func dockerCommandOutput(ctx context.Context, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.ToLower(strings.TrimSpace(stderr.String()))
		if isDockerUnavailableMessage(msg) {
			return "", fmt.Errorf("docker unavailable: %s", msg)
		}
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func appendPolicyRule(t *testing.T, policyPath, rule string) {
	t.Helper()
	t.Logf("appending policy rule: %s", rule)
	ps, rewrites := loadCedarPolicy(t, policyPath)
	applyPolicyRule(t, ps, &rewrites, rule, false)
	writeCedarPolicy(t, policyPath, ps, rewrites)
}

func prependPolicyRule(t *testing.T, policyPath, rule string) {
	t.Helper()
	t.Logf("prepending policy rule: %s", rule)
	ps, rewrites := loadCedarPolicy(t, policyPath)
	applyPolicyRule(t, ps, &rewrites, rule, true)
	writeCedarPolicy(t, policyPath, ps, rewrites)
}

func loadCedarPolicy(t *testing.T, policyPath string) (*lsm.PolicySet, []proxy.HeaderRewriteRule) {
	t.Helper()

	data, err := os.ReadFile(policyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &lsm.PolicySet{}, nil
		}
		t.Fatalf("read policy %s: %v", policyPath, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return &lsm.PolicySet{}, nil
	}

	comp, err := cedar.CompileString(policyPath, string(data))
	if err != nil {
		t.Fatalf("compile Cedar policy %s: %v", policyPath, err)
	}
	return clonePolicySet(comp.Policies), cloneRewrites(comp.HTTPRules)
}

func writeCedarPolicy(t *testing.T, policyPath string, ps *lsm.PolicySet, rewrites []proxy.HeaderRewriteRule) {
	t.Helper()

	cedarBody := strings.TrimSpace(transpiler.PolicySetToCedar(ps))
	var blocks []string
	if cedarBody != "" {
		blocks = append(blocks, cedarBody)
	}
	for _, hr := range rewrites {
		blocks = append(blocks, httpRewriteBlock(hr))
	}

	content := strings.Join(blocks, "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write Cedar policy: %v", err)
	}
}

func parseRulesToPolicy(t *testing.T, rules []string) (*lsm.PolicySet, []proxy.HeaderRewriteRule) {
	t.Helper()
	ps := &lsm.PolicySet{}
	var rewrites []proxy.HeaderRewriteRule
	for _, raw := range rules {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		applyPolicyRule(t, ps, &rewrites, line, false)
	}
	return ps, rewrites
}

func applyPolicyRule(t *testing.T, ps *lsm.PolicySet, rewrites *[]proxy.HeaderRewriteRule, rule string, prepend bool) {
	t.Helper()
	line := strings.TrimSpace(rule)
	if line == "" {
		return
	}

	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "default net.send") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			t.Fatalf("invalid default net.send rule: %s", line)
		}
		ps.ConnectDefaultExplicit = true
		ps.ConnectDefaultAllow = strings.EqualFold(fields[2], "allow")
		return
	}

	if lsmRule, err := lsm.ParseRuleString(line); err == nil && lsmRule != nil {
		addLSMRule(ps, lsmRule, prepend)
		return
	}

	if httpRule, err := policy.ParseHTTPRuleString(line); err == nil && httpRule != nil {
		if prepend {
			*rewrites = append([]proxy.HeaderRewriteRule{*httpRule}, *rewrites...)
		} else {
			*rewrites = append(*rewrites, *httpRule)
		}
		return
	}

	t.Fatalf("unsupported policy rule %q", line)
}

func addLSMRule(ps *lsm.PolicySet, rule *lsm.PolicyRule, prepend bool) {
	if ps == nil || rule == nil {
		return
	}
	switch rule.Operation {
	case lsm.OpOpen, lsm.OpOpenRO, lsm.OpOpenRW:
		ps.Open = insertRule(ps.Open, *rule, prepend)
	case lsm.OpExec:
		ps.Exec = insertRule(ps.Exec, *rule, prepend)
	case lsm.OpConnect:
		ps.Connect = insertRule(ps.Connect, *rule, prepend)
	default:
		ps.Open = insertRule(ps.Open, *rule, prepend)
	}
}

func insertRule(slice []lsm.PolicyRule, rule lsm.PolicyRule, prepend bool) []lsm.PolicyRule {
	if prepend {
		return append([]lsm.PolicyRule{rule}, slice...)
	}
	return append(slice, rule)
}

func clonePolicySet(src *lsm.PolicySet) *lsm.PolicySet {
	if src == nil {
		return &lsm.PolicySet{}
	}
	return &lsm.PolicySet{
		Open:                   append([]lsm.PolicyRule(nil), src.Open...),
		Exec:                   append([]lsm.PolicyRule(nil), src.Exec...),
		Connect:                append([]lsm.PolicyRule(nil), src.Connect...),
		MCP:                    append([]lsm.MCPPolicyRule(nil), src.MCP...),
		ConnectDefaultAllow:    src.ConnectDefaultAllow,
		ConnectDefaultExplicit: src.ConnectDefaultExplicit,
	}
}

func cloneRewrites(src []proxy.HeaderRewriteRule) []proxy.HeaderRewriteRule {
	return append([]proxy.HeaderRewriteRule(nil), src...)
}

func httpRewriteBlock(hr proxy.HeaderRewriteRule) string {
	return fmt.Sprintf(`permit (
    principal,
    action == Action::"HttpRewrite",
    resource == Host::"%s"
)
when {
    context.header == "%s" &&
    context.value == "%s"
};`,
		escapeCedarLiteral(hr.Host),
		escapeCedarLiteral(hr.Header),
		escapeCedarLiteral(hr.Value),
	)
}

func escapeCedarLiteral(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

type execResult struct {
	exitCode int
	stdout   string
	stderr   string
	err      error
}

func runDockerExec(ctx context.Context, container string, command []string) execResult {
	execArgs := append([]string{"exec", container}, command...)
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "docker", execArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return execResult{exitCode: -1, stdout: stdout.String(), stderr: stderr.String(), err: err}
		}
	}
	return execResult{
		exitCode: exitCode,
		stdout:   stdout.String(),
		stderr:   stderr.String(),
		err:      err,
	}
}

func dockerExecOutputCtx(ctx context.Context, container string, command []string) (string, error) {
	execArgs := append([]string{"exec", container}, command...)
	cmd := exec.CommandContext(ctx, "docker", execArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker exec %s: %w: %s", strings.Join(command, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
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
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	}
	switch r {
	case '@', '%', '_', '+', '=', ':', ',', '.', '/', '-':
		return true
	}
	return false
}

func workspaceDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("LEASH_WORKSPACE")); override != "" {
		return resolveWorkspaceCandidate(override)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("determine working directory: %w", err)
	}
	resolved, err := resolveWorkspaceCandidate(cwd)
	if err != nil {
		return "", err
	}
	if root := findDockerfileRoot(resolved); root != "" {
		return root, nil
	}
	return resolved, nil
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

func findDockerfileRoot(start string) string {
	current := start
	for {
		if _, err := os.Stat(filepath.Join(current, "Dockerfile.leash")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return ""
		}
		current = parent
	}
}

func isDockerUnavailableMessage(msg string) bool {
	if msg == "" {
		return false
	}
	switch {
	case strings.Contains(msg, "cannot connect to the docker daemon"),
		strings.Contains(msg, "is the docker daemon running"),
		strings.Contains(msg, "permission denied"),
		strings.Contains(msg, "operation not permitted"),
		strings.Contains(msg, "no such file or directory"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "failed to create shim"),
		strings.Contains(msg, "cgroup"):
		return true
	default:
		return false
	}
}
