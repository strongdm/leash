package cedar

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileFileMissingPath(t *testing.T) {
	t.Parallel()

	comp, err := CompileFile("  ")
	if comp != nil {
		t.Fatalf("expected nil compilation, got %+v", comp)
	}
	var detail *ErrorDetail
	if !errors.As(err, &detail) {
		t.Fatalf("expected *ErrorDetail, got %T", err)
	}
	if detail.Code != "CEDAR_CONFIG" {
		t.Fatalf("expected error code CEDAR_CONFIG, got %s", detail.Code)
	}
	if !strings.Contains(detail.Suggestion, "Cedar policy file path") {
		t.Fatalf("expected suggestion to mention Cedar policy path, got %q", detail.Suggestion)
	}
}

func TestCompileFileReadError(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.cedar")
	comp, err := CompileFile(path)
	if comp != nil {
		t.Fatalf("expected nil compilation, got %+v", comp)
	}
	var detail *ErrorDetail
	if !errors.As(err, &detail) {
		t.Fatalf("expected *ErrorDetail, got %T", err)
	}
	if detail.Code != "CEDAR_IO" {
		t.Fatalf("expected CEDAR_IO, got %s", detail.Code)
	}
	if detail.File != path {
		t.Fatalf("expected file %s, got %s", path, detail.File)
	}
}

func TestCompileFileSuccess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.cedar")
	content := `
permit (principal, action == Action::"ProcessExec", resource)
when { resource in [ Dir::"/" ] };

permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"example.com" ] };
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	comp, err := CompileFile(path)
	if err != nil {
		t.Fatalf("CompileFile returned error: %v", err)
	}
	if comp == nil || comp.Policies == nil {
		t.Fatalf("expected compilation with policies")
	}
	if len(comp.Policies.Exec) != 1 || len(comp.Policies.Connect) != 1 {
		t.Fatalf("expected exec and connect policies, got %+v", comp.Policies)
	}
}

func TestCompileStringErrorDetail(t *testing.T) {
	t.Parallel()

	const cedar = `permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"www.facebook.com" ] }`

	comp, err := CompileString("policy.cedar", cedar)
	if comp != nil {
		t.Fatalf("expected nil compilation, got %+v", comp)
	}
	var detail *ErrorDetail
	if !errors.As(err, &detail) {
		t.Fatalf("expected *ErrorDetail, got %T", err)
	}
	if detail.File == "" || detail.File != "policy.cedar" {
		t.Fatalf("expected file policy.cedar, got %q", detail.File)
	}
	if detail.Line != 2 {
		t.Fatalf("expected error line 2, got %d", detail.Line)
	}
	if detail.Code != "CEDAR_PARSE" {
		t.Fatalf("expected parse code, got %s", detail.Code)
	}
	if !strings.Contains(strings.ToLower(detail.Suggestion), "cedar") {
		t.Fatalf("unexpected suggestion: %q", detail.Suggestion)
	}
	if detail.Snippet == "" {
		t.Fatalf("expected snippet to be populated")
	}
}

func TestFormatCedarErrorLocationFallback(t *testing.T) {
	t.Parallel()

	inner := errors.New("parse error at <input>:3:7 unexpected token")
	err := formatCedarError(inner, "my.cedar", "line1\nline2\nline3\n")
	if err.File != "<input>" && err.File != "my.cedar" {
		t.Fatalf("unexpected file %q", err.File)
	}
	if err.Line != 3 || err.Column != 7 {
		t.Fatalf("expected line 3 column 7, got (%d,%d)", err.Line, err.Column)
	}
	if err.CaretStart != err.CaretEnd {
		t.Fatalf("expected single caret position, got %d-%d", err.CaretStart, err.CaretEnd)
	}
	if err.Snippet != "line3" {
		t.Fatalf("expected snippet line3, got %q", err.Snippet)
	}
}

func TestRootError(t *testing.T) {
	t.Parallel()

	base := errors.New("root cause")
	wrapped := fmt.Errorf("wrapper: %w", base)
	final := fmt.Errorf("top: %w", wrapped)

	if got := rootError(final); got == nil || got.Error() != base.Error() {
		t.Fatalf("expected root error %q, got %v", base, got)
	}
}

func TestExtractLine(t *testing.T) {
	t.Parallel()

	const src = "first\nsecond\nthird"
	if got := extractLine(src, 2); got != "second" {
		t.Fatalf("expected second, got %q", got)
	}
	if got := extractLine(src, 5); got != "" {
		t.Fatalf("expected empty for missing line, got %q", got)
	}
	if got := extractLine("single", 1); got != "single" {
		t.Fatalf("expected single, got %q", got)
	}
}

func TestCaretRange(t *testing.T) {
	t.Parallel()

	start, end := caretRange("abcdef", 3)
	if start != 3 || end != 3 {
		t.Fatalf("expected caret at 3, got %d-%d", start, end)
	}
	start, end = caretRange("abc", 10)
	if start != 4 || end != 4 {
		t.Fatalf("expected caret at end+1 (4), got %d-%d", start, end)
	}
	start, end = caretRange("", 0)
	if start != 1 || end != 1 {
		t.Fatalf("expected caret at 1 when column is 0, got %d-%d", start, end)
	}
}

func TestAtoiSafe(t *testing.T) {
	t.Parallel()

	if atoiSafe("42") != 42 {
		t.Fatalf("expected 42")
	}
	if atoiSafe("bad") != 0 {
		t.Fatalf("expected 0 on parse failure")
	}
}

func TestBuildSummary(t *testing.T) {
	t.Parallel()

	if got := buildSummary(""); got != "invalid Cedar policy" {
		t.Fatalf("unexpected summary %q", got)
	}
	msg := "ParseError: unexpected token"
	if got := buildSummary(msg); got != msg {
		t.Fatalf("expected original message, got %q", got)
	}
	long := strings.Repeat("a", 200)
	if len(buildSummary(long)) != 160 {
		t.Fatalf("expected summary to be truncated to 160 chars")
	}
}

func TestSuggestFix(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"expected ',' before":            "Add a comma",
		"unexpected token permit":        "Review the permit statement syntax",
		"unknown entity type Foo":        "Verify the entity type name",
		"unknown action Action::\"Foo\"": "Confirm the action name",
		"undeclared identifier resource": "Declare the identifier",
		"generic failure":                "Review the Cedar syntax",
	}
	for input, expect := range cases {
		input, expect := input, expect
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			out := suggestFix(input)
			if !strings.Contains(out, expect) {
				t.Fatalf("suggestion %q does not contain %q", out, expect)
			}
		})
	}
}

func TestClassifyCode(t *testing.T) {
	t.Parallel()

	if classifyCode("lint warning") != "CEDAR_LINT" {
		t.Fatalf("expected lint classification")
	}
	if classifyCode("parse failure") != "CEDAR_PARSE" {
		t.Fatalf("expected parse classification fallback")
	}
}

func TestBuildErrorResponse(t *testing.T) {
	t.Parallel()

	detail := &ErrorDetail{
		Summary:    "oops",
		File:       "policy.cedar",
		Line:       3,
		Column:     12,
		Snippet:    "permit ...",
		CaretStart: 5,
		CaretEnd:   6,
		Suggestion: "fix it",
		Code:       "CEDAR_PARSE",
	}
	resp := BuildErrorResponse(detail)
	if resp["message"] != detail.Summary {
		t.Fatalf("expected message %q, got %v", detail.Summary, resp["message"])
	}
	if resp["line"] != detail.Line || resp["column"] != detail.Column {
		t.Fatalf("expected line/column to be copied")
	}
	if resp["code"] != detail.Code {
		t.Fatalf("expected code %s, got %v", detail.Code, resp["code"])
	}
	if resp["suggestion"] != detail.Suggestion {
		t.Fatalf("expected suggestion %q", detail.Suggestion)
	}
}
