package llm

import (
	"fmt"
	"strings"

	"github.com/strongdm/leash/internal/policy/suggest/encoding"
	"github.com/strongdm/leash/internal/policy/suggest/pattern"
)

// ClusterSummary captures the minimum information required for an LLM to label
// a compressed policy cluster.
type ClusterSummary struct {
	Cluster  encoding.Cluster
	Patterns []pattern.Pattern
	Support  int
	RiskTags []string
}

// PromptOptions controls prompt generation.
type PromptOptions struct {
	TargetVoice string
	MaxPolicies int
}

// BuildSuggestionPrompt creates a natural-language brief instructing an LLM to
// produce a policy explanation and candidate Cedar snippet.
func BuildSuggestionPrompt(summary ClusterSummary, opts PromptOptions) string {
	if opts.TargetVoice == "" {
		opts.TargetVoice = "security engineer"
	}
	if opts.MaxPolicies <= 0 {
		opts.MaxPolicies = 3
	}

	var sb strings.Builder
	sb.WriteString("You are an expert Cedar policy author assisting a ")
	sb.WriteString(opts.TargetVoice)
	sb.WriteString(".\n\n")
	sb.WriteString("## Observed Workflow Cluster\n")
	sb.WriteString(fmt.Sprintf("- Cluster ID: %s\n", summary.Cluster.ID))
	sb.WriteString(fmt.Sprintf("- Sessions: %s\n", strings.Join(summary.Cluster.Members, ", ")))
	sb.WriteString(fmt.Sprintf("- Representative workflow: %s\n", summary.Cluster.Explanation))
	sb.WriteString(fmt.Sprintf("- Aggregate support: %d\n", summary.Support))

	if len(summary.RiskTags) > 0 {
		sb.WriteString(fmt.Sprintf("- Risk signals: %s\n", strings.Join(summary.RiskTags, ", ")))
	}

	if len(summary.Patterns) > 0 {
		sb.WriteString("\n## Frequent Sequences\n")
		for i, p := range summary.Patterns {
			if i >= opts.MaxPolicies {
				break
			}
			sb.WriteString(fmt.Sprintf("%d. %s (support: %d sessions)\n", i+1, strings.Join(p.Tokens, " -> "), p.Support))
		}
	}

	sb.WriteString("\n## Tasks\n")
	sb.WriteString("1. Summarize the workflow in plain language, explaining the goal and involved resources.\n")
	sb.WriteString("2. Highlight safety considerations and residual risks.\n")
	sb.WriteString("3. Draft up to two Cedar policy statements that allow the workflow while minimizing over-broad access.\n")
	sb.WriteString("4. Provide a short validation checklist for the operator (e.g., logs, environment constraints).\n")

	return sb.String()
}
