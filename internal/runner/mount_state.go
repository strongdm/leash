package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/strongdm/leash/internal/configstore"
)

type mountState struct {
	command   string
	outcome   configstore.PromptOutcome
	mounts    []configstore.Mount
	tempFiles []string // paths to temporary files that need cleanup
}

var fetchClaudeCredentials = readClaudeKeychainCredentials

func (r *runner) initMountState(ctx context.Context, cwd string) error {
	cmd := strings.TrimSpace(r.opts.subcommand)
	if cmd == "" {
		return nil
	}

	if _, err := configstore.HostDirForCommand(cmd); err != nil {
		return nil
	}

	interactive := r.promptInteractive()
	cfgData, err := configstore.Load()
	if err != nil {
		return fmt.Errorf("load leash config: %w", err)
	}

	var prompter configstore.Prompter
	if interactive {
		if canUseBubbleTea(os.Stdin, os.Stderr) {
			prompter = newBubbleTeaPrompter(os.Stdin, os.Stderr, cwd)
		} else {
			prompter = newTerminalPrompter(os.Stdin, os.Stderr)
		}
	}

	controller := configstore.PromptController{
		Config:   &cfgData,
		SaveFunc: configstore.Save,
		Prompter: prompter,
	}

	outcome, err := controller.MaybePrompt(ctx, cmd, cwd, interactive)
	if err != nil {
		return fmt.Errorf("resolve %s mount decision: %w", cmd, err)
	}
	if outcome.SaveError != nil {
		r.logger.Printf("Warning: failed to persist %s mount preference: %v", cmd, outcome.SaveError)
	}

	decision, err := cfgData.GetEffectiveVolume(cmd, cwd)
	if err != nil {
		return fmt.Errorf("determine effective %s mount: %w", cmd, err)
	}
	if r.warnPersistedHostIssues(decision, outcome.HostDir, cmd) {
		return nil
	}
	if outcome.Mount {
		if cmd == "claude" {
			hostDir := strings.TrimSpace(outcome.HostDir)
			if hostDir != "" {
				if err := os.MkdirAll(hostDir, 0o700); err != nil {
					return fmt.Errorf("ensure Claude host dir: %w", err)
				}
			}
		}
		mounts, err := configstore.ComputeExtraMountsFor(cmd, outcome, nil)
		if err != nil {
			return fmt.Errorf("compute %s mounts: %w", cmd, err)
		}
		if len(mounts) > 0 {
			r.mountState = &mountState{
				command: cmd,
				outcome: outcome,
				mounts:  mounts,
			}
		}
	}

	customMounts, err := cfgData.ResolveCustomVolumes(cwd, cwd)
	if err != nil {
		return fmt.Errorf("resolve custom mounts: %w", err)
	}
	if len(customMounts) > 0 {
		if r.mountState == nil {
			r.mountState = &mountState{}
		}
		r.mountState.mounts = append(r.mountState.mounts, customMounts...)
	}

	if cmd == "claude" && r.mountState == nil && strings.TrimSpace(outcome.HostDir) != "" {
		r.mountState = &mountState{
			command: cmd,
			outcome: outcome,
			mounts:  nil,
		}
	}

	// For claude command on macOS, check for keychain credentials
	if runtime.GOOS == "darwin" && cmd == "claude" && r.mountState != nil {
		if err := r.maybeAddClaudeKeychainMount(); err != nil {
			// Log warning but don't fail - credentials might not be needed
			r.logger.Printf("Warning: failed to mount Claude keychain credentials: %v", err)
		}
	}

	return nil
}

func (r *runner) promptInteractive() bool {
	if r.opts.noInteractive {
		return false
	}
	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		return false
	}
	return true
}

func (r *runner) warnPersistedHostIssues(decision configstore.Decision, hostDir, cmd string) bool {
	if !decision.Enabled {
		return false
	}

	dir := strings.TrimSpace(hostDir)
	if dir == "" {
		resolved, err := configstore.HostDirForCommand(cmd)
		if err != nil {
			r.debugf("resolve host dir for %s: %v", cmd, err)
			return false
		}
		dir = resolved
	}

	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			r.logger.Printf("Warning: mount requested for %s but %s does not exist; skipping.", cmd, dir)
			return true
		}
		r.logger.Printf("Warning: failed to access %s: %v; skipping auto-mount.", dir, err)
		return true
	}

	if !info.IsDir() {
		r.logger.Printf("Warning: expected %s to be a directory; skipping auto-mount.", dir)
		return true
	}

	return false
}

// maybeAddClaudeKeychainMount checks if ~/.claude/.credentials.json exists on the host.
// If it doesn't exist, attempts to read credentials from macOS keychain and write them.
func (r *runner) maybeAddClaudeKeychainMount() error {
	if r.mountState == nil {
		return fmt.Errorf("mountState is nil")
	}

	hostClaudeDir := r.mountState.outcome.HostDir
	credentialsPath := filepath.Join(hostClaudeDir, ".credentials.json")

	info, err := os.Stat(credentialsPath)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("expected file at %s, found directory", credentialsPath)
		}
		if info.Size() > 0 {
			r.debugf(".credentials.json already exists at %s, skipping keychain mount", credentialsPath)
			return nil
		}
		r.debugf(".credentials.json exists at %s but is empty; attempting keychain refresh", credentialsPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check for existence of .credentials.json: %w", err)
	}

	credentials, err := fetchClaudeCredentials()
	if err != nil {
		r.debugf("no keychain credentials found: %v", err)
		return nil
	}

	if err := os.MkdirAll(hostClaudeDir, 0o700); err != nil {
		return fmt.Errorf("ensure Claude config dir %s: %w", hostClaudeDir, err)
	}

	if err := os.WriteFile(credentialsPath, []byte(credentials), 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}

	if err := os.Chmod(credentialsPath, 0o400); err != nil {
		os.Remove(credentialsPath)
		return fmt.Errorf("set credentials permissions: %w", err)
	}

	r.logger.Printf("Claude keychain credentials synced to %s (ephemeral)", credentialsPath)

	return nil
}
