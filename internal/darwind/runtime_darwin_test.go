package darwind

import "testing"

func TestRunExecRequiresCommand(t *testing.T) {
	t.Parallel()

	if err := runExec(nil); err == nil {
		t.Fatalf("expected error when command missing")
	}
}

func TestParseExecCLIArgs_Default(t *testing.T) {
	t.Parallel()

	path, args, err := parseExecCLIArgs([]string{"--", "echo", "hello"})
	if err != nil {
		t.Fatalf("parseExecCLIArgs returned error: %v", err)
	}
	if path != defaultLeashCLIPath {
		t.Fatalf("expected default path %q, got %q", defaultLeashCLIPath, path)
	}
	if len(args) != 3 || args[0] != "--" {
		t.Fatalf("unexpected passthrough args: %#v", args)
	}
}

func TestParseExecCLIArgsOverride(t *testing.T) {
	t.Parallel()

	path, args, err := parseExecCLIArgs([]string{"--leash-cli-path", "/tmp/custom", "-v"})
	if err != nil {
		t.Fatalf("parseExecCLIArgs returned error: %v", err)
	}
	if path != "/tmp/custom" {
		t.Fatalf("expected override path /tmp/custom, got %q", path)
	}
	if len(args) != 1 || args[0] != "-v" {
		t.Fatalf("unexpected passthrough args: %#v", args)
	}
}

func TestParseExecCLIArgsOverrideEquals(t *testing.T) {
	t.Parallel()

	path, args, err := parseExecCLIArgs([]string{"--leash-cli-path=/usr/local/bin/leashcli", "status"})
	if err != nil {
		t.Fatalf("parseExecCLIArgs returned error: %v", err)
	}
	if path != "/usr/local/bin/leashcli" {
		t.Fatalf("expected override path, got %q", path)
	}
	if len(args) != 1 || args[0] != "status" {
		t.Fatalf("unexpected passthrough args: %#v", args)
	}
}

func TestParseExecCLIArgsMissingValue(t *testing.T) {
	t.Parallel()

	if _, _, err := parseExecCLIArgs([]string{"--leash-cli-path"}); err == nil {
		t.Fatalf("expected error for missing override value")
	}
	if _, _, err := parseExecCLIArgs([]string{"--leash-cli-path="}); err == nil {
		t.Fatalf("expected error for empty override value")
	}
}

func TestIsExecHelpRequest(t *testing.T) {
	t.Parallel()

	if !isExecHelpRequest([]string{"--help"}) {
		t.Fatalf("expected --help to be recognized")
	}
	if !isExecHelpRequest([]string{"-h"}) {
		t.Fatalf("expected -h to be recognized")
	}
	if !isExecHelpRequest([]string{"--", "help"}) {
		t.Fatalf("expected help after -- to be recognized")
	}
	if isExecHelpRequest([]string{"status"}) {
		t.Fatalf("unexpected help detection for normal command")
	}
}
