package autocomplete

import (
	"strings"
	"testing"
)

func TestCompleteStartOfDocument(t *testing.T) {
	t.Parallel()

	items, rng, err := Complete("", 1, 1, 0, Hints{})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected suggestions, got none")
	}
	if items[0].Label != "permit" {
		t.Fatalf("expected first suggestion to be permit, got %q", items[0].Label)
	}
	if rng.Start.Line != 1 || rng.Start.Column != 1 {
		t.Fatalf("expected start range at 1:1, got %+v", rng.Start)
	}
	if rng.End.Line != 1 || rng.End.Column != 1 {
		t.Fatalf("expected end range at 1:1, got %+v", rng.End)
	}
}

func TestCompleteAfterActionComparator(t *testing.T) {
	t.Parallel()

	src := `permit (principal, action == <caret>, resource);`
	code, line, col := extractCaret(t, src)

	items, _, err := Complete(code, line, col, 0, Hints{})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if !containsLabel(items, `Action::"FileOpen"`) {
		t.Fatalf("expected Action::\"FileOpen\" in suggestions, got %+v", labels(items))
	}
	if got := items[0].Kind; got != KindAction {
		t.Fatalf("expected first item kind action, got %s", got)
	}
}

func TestCompleteResourceSuggestions(t *testing.T) {
	t.Parallel()

	src := `
permit (principal, action == Action::"FileOpen", resource)
    when { resource in [ <caret> ] };`
	code, line, col := extractCaret(t, src)

	hints := Hints{
		Dirs:  []string{"/var/lib"},
		Files: []string{"/etc/hosts"},
		Hosts: []string{"example.com:443"},
	}

	items, _, err := Complete(code, line, col, 0, hints)
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	want := []string{`Dir::"/var/lib/"`, `File::"/etc/hosts"`, `Host::"example.com:443"`}
	for _, label := range want {
		if !containsLabel(items, label) {
			t.Fatalf("expected %s in suggestions, got %+v", label, labels(items))
		}
	}
}

func TestCompleteMCPHintsPriority(t *testing.T) {
	t.Parallel()

	src := `
forbid (principal, action == Action::"McpCall", resource)
    when { resource in [ MCP::Server::"<caret>" ] };`
	code, line, col := extractCaret(t, src)

	hints := Hints{
		Servers: []string{"mcp.example.com"},
		Tools:   []string{"resolve-library-id"},
	}

	items, _, err := Complete(code, line, col, 0, hints)
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected results")
	}
	if items[0].Label != `MCP::Server::"mcp.example.com"` {
		t.Fatalf("expected first suggestion to be server hint, got %q", items[0].Label)
	}
	if !containsLabel(items, `MCP::Tool::"resolve-library-id"`) {
		t.Fatalf("expected tool hint to be included, got %+v", labels(items))
	}
}

func TestCompleteSkipsComments(t *testing.T) {
	t.Parallel()

	src := `// comment <caret>`
	code, line, col := extractCaret(t, src)

	items, _, err := Complete(code, line, col, 0, Hints{})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected no suggestions inside comments, got %+v", labels(items))
	}
}

func TestCompleteSuggestsActionsWhenMissing(t *testing.T) {
	t.Parallel()

	src := `
permit (principal, action<caret>, resource)
    when { resource in [ Dir::"/tmp/" ] };`
	code, line, col := extractCaret(t, src)

	items, _, err := Complete(code, line, col, 0, Hints{})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected suggestions")
	}
	if items[0].Kind != KindAction {
		t.Fatalf("expected action suggestions first, got %s", items[0].Kind)
	}
	if !containsLabel(items, `Action::"FileOpen"`) {
		t.Fatalf("expected Action::\"FileOpen\", got %+v", labels(items))
	}
}

func TestCompleteHttpRewriteContextKeys(t *testing.T) {
	t.Parallel()

	src := `
permit (principal, action == Action::"HttpRewrite", resource)
    when { context.<caret> }`
	code, line, col := extractCaret(t, src)

	items, _, err := Complete(code, line, col, 0, Hints{})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if !containsLabel(items, "context.header") {
		t.Fatalf("expected context.header in suggestions, got %+v", labels(items))
	}
}

func TestCompletePermitParametersSuggestPrincipal(t *testing.T) {
	t.Parallel()

	src := `permit (<caret>`
	code, line, col := extractCaret(t, src)

	items, _, err := Complete(code, line, col, 0, Hints{})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if !containsLabel(items, "principal") {
		t.Fatalf("expected principal suggestion, got %+v", labels(items))
	}
}

func TestCompletePermitParametersSuggestActionComparator(t *testing.T) {
	t.Parallel()

	src := `permit (principal, <caret>`
	code, line, col := extractCaret(t, src)

	items, _, err := Complete(code, line, col, 0, Hints{})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if !containsLabel(items, `action == Action::"NetworkConnect"`) {
		t.Fatalf("expected action comparator suggestion, got %+v", labels(items))
	}
}

func TestCompleteInlinePermitStatementSnippet(t *testing.T) {
	t.Parallel()

	src := `policy Example = permit (<caret>`
	code, line, col := extractCaret(t, src)

	items, _, err := Complete(code, line, col, 0, Hints{})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected suggestions")
	}
	if items[0].Label != "permit statement" {
		t.Fatalf("expected permit statement first, got %q", items[0].Label)
	}
	if !containsLabel(items, "permit statement") {
		t.Fatalf("expected permit statement snippet, got %+v", labels(items))
	}
	if !containsLabel(items, "Policy skeleton") {
		t.Fatalf("expected policy skeleton snippet to remain available, got %+v", labels(items))
	}
}

func TestCompletePermitSuggestsActionNotEquals(t *testing.T) {
	t.Parallel()

	src := `permit (principal, action != <caret>, resource);`
	code, line, col := extractCaret(t, src)

	items, _, err := Complete(code, line, col, 0, Hints{})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if !containsLabel(items, `action != Action::"NetworkConnect"`) {
		t.Fatalf("expected action != comparator suggestion, got %+v", labels(items))
	}
}

func extractCaret(t *testing.T, src string) (string, int, int) {
	t.Helper()
	const marker = "<caret>"
	idx := strings.Index(src, marker)
	if idx == -1 {
		t.Fatalf("caret marker not found in %q", src)
	}
	before := src[:idx]
	after := src[idx+len(marker):]
	line := strings.Count(before, "\n") + 1
	lastNL := strings.LastIndex(before, "\n")
	col := len(before) + 1
	if lastNL != -1 {
		col = len(before[lastNL+1:]) + 1
	}
	return before + after, line, col
}

func containsLabel(items []Item, label string) bool {
	for _, item := range items {
		if item.Label == label {
			return true
		}
	}
	return false
}

func labels(items []Item) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Label)
	}
	return out
}
