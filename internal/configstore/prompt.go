package configstore

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// SaveFunc persists the provided configuration snapshot.
type SaveFunc func(Config) error

// Prompter drives interactive questions for mount decisions.
type Prompter interface {
	ConfirmMount(ctx context.Context, cmd, hostDir string) (bool, error)
	ChooseScope(ctx context.Context, cmd, cwd string) (ScopeChoice, error)
}

// ScopeChoice represents a persisted scope for a user's decision.
type ScopeChoice int

const (
	ScopeChoiceGlobal ScopeChoice = iota + 1
	ScopeChoiceProject
	ScopeChoiceOnce
)

// PromptOutcome captures the result of MaybePrompt.
type PromptOutcome struct {
	Mount     bool
	Scope     DecisionScope
	Persisted bool
	SaveError error
	HostDir   string
}

// PromptController orchestrates interactive prompting and persistence.
type PromptController struct {
	Config   *Config
	SaveFunc SaveFunc
	Prompter Prompter
	StatFunc func(string) (os.FileInfo, error)
}

// MaybePrompt evaluates existing decisions and optionally prompts the user.
func (pc *PromptController) MaybePrompt(ctx context.Context, cmd, cwd string, interactive bool) (PromptOutcome, error) {
	if pc == nil || pc.Config == nil {
		return PromptOutcome{}, errors.New("prompt controller misconfigured: config required")
	}
	if err := ensureSupportedCommand(cmd); err != nil {
		return PromptOutcome{}, err
	}

	hostDir, err := HostDirForCommand(cmd)
	if err != nil {
		return PromptOutcome{}, err
	}

	statFn := pc.StatFunc
	if statFn == nil {
		statFn = os.Stat
	}
	if _, err := statFn(hostDir); err != nil {
		if os.IsNotExist(err) {
			return PromptOutcome{HostDir: hostDir}, nil
		}
		return PromptOutcome{}, fmt.Errorf("check host dir: %w", err)
	}

	decision, err := pc.Config.GetEffectiveVolume(cmd, cwd)
	if err != nil {
		return PromptOutcome{}, err
	}
	if decision.Enabled {
		return PromptOutcome{
			Mount:     true,
			Scope:     decision.Scope,
			Persisted: decision.Scope != ScopeUnset,
			HostDir:   hostDir,
		}, nil
	}

	if !interactive {
		return PromptOutcome{Scope: decision.Scope, HostDir: hostDir}, nil
	}
	if pc.Prompter == nil {
		return PromptOutcome{}, errors.New("prompter required for interactive flow")
	}

	ok, err := pc.Prompter.ConfirmMount(ctx, cmd, hostDir)
	if err != nil {
		return PromptOutcome{}, err
	}
	if !ok {
		return PromptOutcome{Scope: ScopeUnset, HostDir: hostDir}, nil
	}

	choice, err := pc.Prompter.ChooseScope(ctx, cmd, cwd)
	if err != nil {
		return PromptOutcome{}, err
	}

	switch choice {
	case ScopeChoiceGlobal:
		return pc.persistDecision(cmd, func(cfg *Config) error {
			return cfg.SetGlobalVolume(cmd, true)
		}, ScopeGlobal, hostDir)
	case ScopeChoiceProject:
		return pc.persistDecision(cmd, func(cfg *Config) error {
			return cfg.SetProjectVolume(cwd, cmd, true)
		}, ScopeProject, hostDir)
	case ScopeChoiceOnce:
		return PromptOutcome{
			Mount:   true,
			Scope:   ScopeEphemeral,
			HostDir: hostDir,
		}, nil
	default:
		return PromptOutcome{}, fmt.Errorf("unsupported scope choice %d", choice)
	}
}

func (pc *PromptController) persistDecision(cmd string, mutate func(*Config) error, scope DecisionScope, hostDir string) (PromptOutcome, error) {
	prev := pc.Config.Clone()
	if err := mutate(pc.Config); err != nil {
		return PromptOutcome{}, err
	}

	saveFn := pc.SaveFunc
	if saveFn == nil {
		saveFn = Save
	}
	if err := saveFn(pc.Config.Clone()); err != nil {
		*pc.Config = prev
		return PromptOutcome{
			Mount:     true,
			Scope:     ScopeEphemeral,
			Persisted: false,
			SaveError: err,
			HostDir:   hostDir,
		}, nil
	}
	return PromptOutcome{
		Mount:     true,
		Scope:     scope,
		Persisted: true,
		HostDir:   hostDir,
	}, nil
}
