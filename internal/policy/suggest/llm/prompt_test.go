package llm

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/policy/suggest/encoding"
	"github.com/strongdm/leash/internal/policy/suggest/pattern"
)

func TestBuildSuggestionPromptIncludesKeySections(t *testing.T) {
	cluster := encoding.Cluster{
		ID:          "cluster-1",
		Members:     []string{"session-1", "session-2"},
		Explanation: "workflow from filesystem:open:unix.file:/etc to network:connect:net.host:api; principal user1",
	}
	patterns := []pattern.Pattern{
		{Tokens: []string{"filesystem:open:unix.file:/etc", "network:connect:net.host:api"}, Support: 2},
	}
	prompt := BuildSuggestionPrompt(ClusterSummary{
		Cluster:  cluster,
		Patterns: patterns,
		Support:  3,
		RiskTags: []string{"new_resource"},
	}, PromptOptions{})

	for _, section := range []string{"## Observed Workflow Cluster", "## Frequent Sequences", "## Tasks"} {
		if !strings.Contains(prompt, section) {
			t.Fatalf("prompt missing section %s", section)
		}
	}
	if !strings.Contains(prompt, "Summarize the workflow") {
		t.Fatalf("prompt missing task instructions")
	}
}
