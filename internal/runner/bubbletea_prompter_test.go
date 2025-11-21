package runner

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWizardModelViewHasNoGapBeforeProposedMount(t *testing.T) {
	t.Parallel()

	makeModel := func(color bool) *wizardModel {
		return newWizardModel("claude", "/Users/example/.claude", "/Users/example/src/squash-config-5-0", "v0.0.0", newWizardTheme(color), "")
	}

	models := []*wizardModel{
		makeModel(false),
		makeModel(true),
	}

	for _, model := range models {
		view := model.View()
		lines := strings.Split(view, "\n")

		projectIdx := -1
		for i, line := range lines {
			if strings.Contains(line, "Project        :") {
				projectIdx = i
				break
			}
		}

		if projectIdx == -1 {
			t.Fatalf("project line not found.\nview:\n%s", view)
		}
		if projectIdx+1 >= len(lines) {
			t.Fatalf("no line found after project line.\nview:\n%s", view)
		}

		t.Logf("color=%v project line=%q after=%q", model.theme.color, lines[projectIdx], lines[projectIdx+1])

		nextLine := lines[projectIdx+1]
		if !strings.Contains(nextLine, "Proposed mount :") {
			t.Fatalf("expected proposed mount line immediately after project, got %q.\nview:\n%s", nextLine, view)
		}
	}
}

func TestShortenWorkingDirWithHome(t *testing.T) {
	t.Parallel()

	const home = "/Users/example"
	longDigits := "/" + strings.Repeat("0123456789", 6)
	longDigitsExpected := longDigits[:projectDisplayPrefixLen] + projectDisplayEllipsis + longDigits[len(longDigits)-projectDisplaySuffixLen:]
	longHomeRest := strings.Repeat("p", 60)
	longHomePath := home + "/" + longHomeRest
	replacedLongHome := "~/" + longHomeRest
	longHomeExpected := replacedLongHome[:projectDisplayPrefixLen] + projectDisplayEllipsis + replacedLongHome[len(replacedLongHome)-projectDisplaySuffixLen:]
	longHomePrefix := "/base/" + strings.Repeat("h", 60)
	longBeforeShortAfterPath := longHomePrefix + "/leaf"

	tests := []struct {
		name string
		path string
		home string
		want string
	}{
		{name: "shortNoHome", path: "/tmp/leash", home: "", want: "/tmp/leash"},
		{name: "shortWithHome", path: home + "/src/leash", home: home, want: "~/src/leash"},
		{name: "homeOnly", path: home, home: home, want: "~"},
		{name: "homeWithTrailingSlash", path: home + "/workspace", home: home + "/", want: "~/workspace"},
		{name: "maxLenExact", path: "/" + strings.Repeat("a", projectDisplayMaxLen-1), home: "", want: "/" + strings.Repeat("a", projectDisplayMaxLen-1)},
		{name: "maxLenAfterHome", path: home + "/" + strings.Repeat("b", projectDisplayMaxLen-2), home: home, want: "~/" + strings.Repeat("b", projectDisplayMaxLen-2)},
		{name: "longNoHome", path: longDigits, home: "", want: longDigitsExpected},
		{name: "longWithHome", path: longHomePath, home: home, want: longHomeExpected},
		{name: "longBeforeShortAfterHome", path: longBeforeShortAfterPath, home: longHomePrefix, want: "~/leaf"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := shortenWorkingDirWithHome(tt.path, tt.home)
			if got != tt.want {
				t.Fatalf("shortenWorkingDirWithHome(%q, %q) = %q want %q", tt.path, tt.home, got, tt.want)
			}
			if len(got) > projectDisplayMaxLen {
				t.Fatalf("result length %d exceeds max of %d", len(got), projectDisplayMaxLen)
			}
		})
	}
}

func TestWizardModelUsesFormattedWorkingDir(t *testing.T) {
	t.Parallel()

	home := currentHomeDir()
	if home == "" {
		t.Skip("home directory unavailable")
	}
	cwd := filepath.Join(home, strings.Repeat("z", 70))
	expected := shortenWorkingDirWithHome(cwd, home)
	model := newWizardModel("claude", "/Users/example/.claude", cwd, "v0.0.0", newWizardTheme(false), "")

	if model.project != expected {
		t.Fatalf("project display = %q want %q", model.project, expected)
	}

	if len(model.options) < 2 {
		t.Fatalf("unexpected options len %d", len(model.options))
	}

	const wantDesc = "Remember for this directory"
	if model.options[1].desc != wantDesc {
		t.Fatalf("option description = %q want %q", model.options[1].desc, wantDesc)
	}

	const wantLabel = "This project only"
	if model.options[1].label != wantLabel {
		t.Fatalf("option label = %q want %q", model.options[1].label, wantLabel)
	}
}
