package runner

import (
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
