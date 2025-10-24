package autocomplete

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/strongdm/leash/internal/transpiler"
)

const (
	defaultMaxItems = 75
)

type contextKind int

const (
	contextUnknown contextKind = iota
	contextKeyword
	contextAction
	contextResource
	contextMCP
	contextContextKey
	contextHeader
	contextSnippet
)

// Complete produces context-aware completion items for the provided Cedar buffer and cursor location.
func Complete(input string, line, column, maxItems int, hints Hints) ([]Item, ReplaceRange, error) {
	if maxItems <= 0 {
		maxItems = defaultMaxItems
	}
	if line < 1 {
		line = 1
	}
	if column < 1 {
		column = 1
	}

	runes := []rune(input)
	offset := positionToOffset(runes, line, column)
	if offset < 0 {
		offset = 0
	}
	if offset > len(runes) {
		offset = len(runes)
	}
	byteOffset := runeOffsetToByteOffset(runes, offset)
	if byteOffset < 0 {
		byteOffset = 0
	}
	if byteOffset > len(input) {
		byteOffset = len(input)
	}

	if inComment(input, byteOffset) {
		empty := ReplaceRange{
			Start: Position{Line: line, Column: column},
			End:   Position{Line: line, Column: column},
		}
		return nil, empty, nil
	}

	start, end := tokenBounds(runes, offset)
	if start < 0 {
		start = offset
	}
	if end < start {
		end = start
	}

	prefix := string(runes[start:offset])
	normalizedPrefix, segmentPrefix := normalizePrefix(prefix)

	context := detectContexts(input, runes, offset, byteOffset)

	candidates := gatherCandidates(context, hints)

	items := selectAndRank(candidates, normalizedPrefix, segmentPrefix, maxItems)

	replaceRange := ReplaceRange{
		Start: offsetToPosition(runes, start),
		End:   offsetToPosition(runes, end),
	}

	return items, replaceRange, nil
}

type candidate struct {
	item      Item
	priority  int
	uniqueKey string
}

func gatherCandidates(ctx detectedContext, hints Hints) []candidate {
	var out []candidate

	if ctx.startOfDocument {
		out = append(out, wrapCandidates(keywordItems(), 0)...)
		out = append(out, wrapCandidates(snippetItems(), 1)...)
	}

	if ctx.afterPermitForbid && !ctx.afterContextDot {
		if ctx.permitArgsEmpty {
			out = append(out, wrapCandidates(statementSnippetItems(), -2)...)
			out = append(out, wrapCandidates(snippetItems(), -1)...)
		} else if !ctx.actionComparator && !ctx.resourceList {
			out = append(out, wrapCandidates(statementSnippetItems(), 1)...)
			out = append(out, wrapCandidates(snippetItems(), 2)...)
		}

		if ctx.insidePermitArgs && !ctx.actionComparator {
			paramPriority := 0
			if ctx.needsResource && !ctx.needsAction {
				paramPriority = -1
			}
			out = append(out, wrapCandidates(permitParameterItems(), paramPriority)...)
		}

		if !ctx.actionComparator && !ctx.resourceList {
			out = append(out, wrapCandidates(keywordItems(), 3)...)
		}
	}

	if ctx.actionComparator || ctx.needsAction {
		priority := 0
		if ctx.needsAction && !ctx.actionComparator {
			priority = -1
		}
		out = append(out, wrapCandidates(actionItems(), priority)...)
	}

	if ctx.resourceList || ctx.needsResource {
		resourcePriority := 0
		if ctx.needsResource && !ctx.resourceList {
			resourcePriority = -1
		}
		if ctx.mcpPolicy {
			out = append(out, wrapCandidates(mcpResourceItems(hints), resourcePriority)...)
			resourcePriority++
		}
		out = append(out, wrapCandidates(resourceItems(hints), resourcePriority)...)
		if ctx.httpRewritePolicy {
			out = append(out, wrapCandidates(httpRewriteSnippetItems(), resourcePriority+1)...)
		}
	}

	if ctx.afterContextDot {
		out = append(out, wrapCandidates(contextKeyItems(), 0)...)
		if ctx.httpRewritePolicy {
			out = append(out, wrapCandidates(httpRewriteContextItems(hints), 1)...)
		}
	}

	if len(out) == 0 {
		out = append(out, wrapCandidates(keywordItems(), 1)...)
		out = append(out, wrapCandidates(snippetItems(), 2)...)
	}

	return dedupeCandidates(out)
}

func wrapCandidates(items []Item, priority int) []candidate {
	out := make([]candidate, 0, len(items))
	for _, it := range items {
		item := it // copy
		out = append(out, candidate{
			item:      item,
			priority:  priority,
			uniqueKey: strings.ToLower(item.Label),
		})
	}
	return out
}

func dedupeCandidates(in []candidate) []candidate {
	seen := make(map[string]struct{}, len(in))
	out := make([]candidate, 0, len(in))
	for _, c := range in {
		key := c.uniqueKey
		if key == "" {
			key = strings.ToLower(c.item.InsertText)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

func selectAndRank(candidates []candidate, prefix, segment string, maxItems int) []Item {
	type rankedItem struct {
		item Item
		key  string
		rank int
	}

	ranked := make([]rankedItem, 0, len(candidates))
	for idx, cand := range candidates {
		score := cand.priority * 100
		lowerLabel := strings.ToLower(cand.item.Label)
		lowerInsert := strings.ToLower(cand.item.InsertText)

		if prefix != "" {
			switch {
			case strings.HasPrefix(lowerLabel, prefix), strings.HasPrefix(lowerInsert, prefix):
				score += 0
			case segment != "" && (strings.HasPrefix(lowerLabel, segment) || strings.HasPrefix(lowerInsert, segment)):
				score += 1
			case strings.Contains(lowerLabel, segment) || strings.Contains(lowerInsert, segment):
				score += 5
			default:
				score += 15
			}
		}

		ranked = append(ranked, rankedItem{
			item: cand.item,
			key:  cand.uniqueKey,
			rank: score*100 + idx,
		})
	}

	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].rank < ranked[j].rank
	})

	max := maxItems
	if max > len(ranked) {
		max = len(ranked)
	}

	items := make([]Item, 0, max)
	for i := 0; i < max; i++ {
		item := ranked[i].item
		item.SortText = sortKey(i)
		items = append(items, item)
	}
	return items
}

func sortKey(idx int) string {
	if idx < 0 {
		idx = 0
	}
	return fmt.Sprintf("%03d", idx)
}

type detectedContext struct {
	startOfDocument   bool
	afterPermitForbid bool
	actionComparator  bool
	resourceList      bool
	mcpPolicy         bool
	httpRewritePolicy bool
	afterContextDot   bool
	needsAction       bool
	needsResource     bool
	insidePermitArgs  bool
	permitArgsEmpty   bool
}

func detectContexts(input string, runes []rune, runeOffset, byteOffset int) detectedContext {
	before := input[:byteOffset]
	beforeLower := strings.ToLower(before)

	ctx := detectedContext{}

	if strings.TrimSpace(before) == "" {
		ctx.startOfDocument = true
	}

	ctx.afterPermitForbid = afterPermitOrForbid(beforeLower)
	ctx.actionComparator = isActionComparator(beforeLower)
	ctx.resourceList = isResourceListContext(input, byteOffset)

	ctx.afterContextDot = strings.HasSuffix(strings.TrimSpace(beforeLower), "context.")
	if !ctx.afterContextDot {
		ctx.afterContextDot = hasContextDot(beforeLower)
	}

	hasPermit, insidePermit, permitEmpty := permitInvocationState(beforeLower)
	if hasPermit {
		ctx.afterPermitForbid = true
	}
	ctx.insidePermitArgs = insidePermit
	ctx.permitArgsEmpty = permitEmpty

	var snippet string
	if astInfo, snip, ok := analyzeContextWithAST(input, byteOffset); ok {
		snippet = snip
		ctx.mcpPolicy = astInfo.hasMCP
		ctx.httpRewritePolicy = astInfo.hasHttpRewrite
		ctx.needsAction = astInfo.missingAction
		ctx.needsResource = astInfo.missingResource
	} else {
		if snip, ok := heuristicPolicySnippet(input, byteOffset); ok {
			snippet = snip
		}
		if snippet != "" {
			if lintInfo := analyzeContextWithLint(snippet); lintInfo.valid {
				ctx.needsAction = ctx.needsAction || lintInfo.missingAction
				ctx.needsResource = ctx.needsResource || lintInfo.missingResource
				ctx.mcpPolicy = ctx.mcpPolicy || lintInfo.hasMCP
				ctx.httpRewritePolicy = ctx.httpRewritePolicy || lintInfo.hasHttpRewrite
			}
		}
	}

	if !ctx.mcpPolicy {
		ctx.mcpPolicy = withinPolicyContaining(beforeLower, `action::"mcpcall"`)
	}
	if !ctx.httpRewritePolicy {
		ctx.httpRewritePolicy = withinPolicyContaining(beforeLower, `action::"httprewrite"`)
	}

	// Token-level fallback for incomplete input.
	if !ctx.mcpPolicy {
		ctx.mcpPolicy = strings.Contains(strings.ToLower(snippet), `action::"mcpcall"`)
	}
	if !ctx.httpRewritePolicy {
		ctx.httpRewritePolicy = strings.Contains(strings.ToLower(snippet), `action::"httprewrite"`)
	}

	return ctx
}

func afterPermitOrForbid(before string) bool {
	lastPermit := strings.LastIndex(before, "permit")
	lastForbid := strings.LastIndex(before, "forbid")
	last := max(lastPermit, lastForbid)
	if last == -1 {
		return false
	}
	chunk := before[last:]
	lines := strings.Split(chunk, "\n")
	if len(lines) == 0 {
		return false
	}
	lastLine := strings.TrimSpace(lines[len(lines)-1])
	if lastLine == "permit" || lastLine == "forbid" {
		return true
	}
	normalized := removeWhitespace(lastLine)
	if strings.HasPrefix(normalized, "permit(") || strings.HasPrefix(normalized, "forbid(") {
		return true
	}
	return strings.HasSuffix(normalized, "permit") || strings.HasSuffix(normalized, "forbid")
}

func permitInvocationState(before string) (hasKeyword bool, insideArgs bool, argsEmpty bool) {
	idxPermit := strings.LastIndex(before, "permit")
	idxForbid := strings.LastIndex(before, "forbid")
	last := max(idxPermit, idxForbid)
	if last == -1 {
		return false, false, false
	}
	keyword := "permit"
	if last == idxForbid {
		keyword = "forbid"
	}

	if last > 0 {
		if r := rune(before[last-1]); isIdentifierRune(r) {
			return false, false, false
		}
	}

	remainder := before[last+len(keyword):]
	remainder = strings.TrimLeftFunc(remainder, unicode.IsSpace)
	if remainder == "" {
		return true, false, true
	}
	if remainder[0] != '(' {
		return true, false, false
	}
	content := []rune(remainder[1:])
	depth := 1
	for idx, r := range content {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				beforeClose := strings.TrimSpace(string(content[:idx]))
				return true, false, beforeClose == ""
			}
		}
	}
	insideArgs = true
	if strings.TrimSpace(string(content)) == "" {
		return true, true, true
	}
	return true, true, false
}

func isIdentifierRune(r rune) bool {
	if r == '_' || r == ':' {
		return true
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isActionComparator(before string) bool {
	idx := strings.LastIndex(before, "action")
	if idx == -1 {
		return false
	}
	chunk := strings.TrimSpace(before[idx:])
	chunk = removeWhitespace(chunk)
	if !strings.HasPrefix(chunk, "action==") {
		return false
	}
	return true
}

func isResourceListContext(input string, byteOffset int) bool {
	if byteOffset <= 0 {
		return false
	}
	if byteOffset > len(input) {
		byteOffset = len(input)
	}
	lower := strings.ToLower(input[:byteOffset])
	before := lower
	idx := strings.LastIndex(before, "resource")
	if idx == -1 {
		return false
	}
	chunk := removeWhitespace(before[idx:])
	if !strings.Contains(chunk, "resourcein[") {
		return false
	}
	closing := strings.LastIndex(chunk, "]")
	if closing >= 0 && closing < len(chunk)-1 {
		return false
	}
	return true
}

func withinPolicyContaining(before string, needle string) bool {
	lastPermit := strings.LastIndex(before, "permit")
	lastForbid := strings.LastIndex(before, "forbid")
	start := max(lastPermit, lastForbid)
	if start == -1 {
		start = 0
	}
	chunk := before[start:]
	return strings.Contains(chunk, needle)
}

func hasContextDot(before string) bool {
	idx := strings.LastIndex(before, "context.")
	if idx == -1 {
		return false
	}
	after := before[idx+len("context."):]
	after = strings.TrimSpace(after)
	return after == "" || strings.LastIndex(after, "\n") == len(after)-1
}

func removeWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func runeOffsetToByteOffset(runes []rune, runeOffset int) int {
	if runeOffset <= 0 || len(runes) == 0 {
		return 0
	}
	if runeOffset > len(runes) {
		runeOffset = len(runes)
	}
	total := 0
	for i := 0; i < runeOffset; i++ {
		total += utf8.RuneLen(runes[i])
	}
	return total
}

type astAnalysis struct {
	hasMCP          bool
	hasHttpRewrite  bool
	missingAction   bool
	missingResource bool
}

type policySegment struct {
	policy transpiler.CedarPolicy
	start  int
	end    int
}

func analyzeContextWithAST(input string, byteOffset int) (astAnalysis, string, bool) {
	parser := transpiler.NewCedarParser()
	if parser == nil {
		return astAnalysis{}, "", false
	}
	policySet, err := parser.ParseFromNamedString("completion.cedar", input)
	if err != nil || policySet == nil {
		return astAnalysis{}, "", false
	}

	segments := buildPolicySegments(input, policySet.Policies)
	for _, seg := range segments {
		if byteOffset < seg.start || byteOffset > seg.end {
			continue
		}
		analysis := astAnalysis{
			hasMCP:          policyHasAction(seg.policy, "McpCall"),
			hasHttpRewrite:  policyHasAction(seg.policy, "HttpRewrite"),
			missingAction:   policyMissingAction(seg.policy),
			missingResource: policyMissingResource(seg.policy),
		}
		start := seg.start
		end := seg.end
		if start < 0 {
			start = 0
		}
		if end > len(input) {
			end = len(input)
		}
		return analysis, input[start:end], true
	}

	return astAnalysis{}, "", false
}

func buildPolicySegments(input string, policies []transpiler.CedarPolicy) []policySegment {
	segments := make([]policySegment, 0, len(policies))
	for _, pol := range policies {
		if pol.NativePolicy == nil {
			continue
		}
		pos := pol.NativePolicy.Position()
		start := int(pos.Offset)
		if start < 0 {
			start = 0
		}
		if start > len(input) {
			start = len(input)
		}
		end := findPolicyEndBytes(input, start)
		if end < start {
			end = start
		}
		if end > len(input) {
			end = len(input)
		}
		segments = append(segments, policySegment{
			policy: pol,
			start:  start,
			end:    end,
		})
	}

	sort.Slice(segments, func(i, j int) bool {
		return segments[i].start < segments[j].start
	})

	for i := range segments {
		if i+1 < len(segments) && segments[i].end > segments[i+1].start {
			segments[i].end = segments[i+1].start
		}
		if segments[i].end > len(input) {
			segments[i].end = len(input)
		}
	}

	return segments
}

func findPolicyEndBytes(input string, start int) int {
	if start < 0 {
		start = 0
	}
	if start >= len(input) {
		return len(input)
	}
	inString := false
	escape := false
	lineComment := false
	blockComment := false
	depth := 0
	for i := start; i < len(input); i++ {
		ch := input[i]
		if lineComment {
			if ch == '\n' {
				lineComment = false
			}
			continue
		}
		if blockComment {
			if ch == '*' && i+1 < len(input) && input[i+1] == '/' {
				blockComment = false
				i++
			}
			continue
		}
		if inString {
			if escape {
				escape = false
				continue
			}
			if ch == '\\' {
				escape = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			escape = false
			continue
		}
		if ch == '/' && i+1 < len(input) {
			switch input[i+1] {
			case '/':
				lineComment = true
				i++
				continue
			case '*':
				blockComment = true
				i++
				continue
			}
		}
		switch ch {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(input)
}

func policyHasAction(policy transpiler.CedarPolicy, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range gatherActionValues(policy.Action) {
		if actionMatchesTarget(value, target) {
			return true
		}
	}
	return false
}

func gatherActionValues(action transpiler.ActionConstraint) []string {
	values := make([]string, 0, len(action.Actions)+len(action.InSet))
	values = append(values, action.Actions...)
	values = append(values, action.InSet...)
	return values
}

func actionMatchesTarget(value string, target string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		return false
	}
	if !strings.Contains(v, "::") {
		return v == strings.ToLower(target)
	}
	parts := strings.Split(v, "::")
	last := strings.TrimSpace(parts[len(parts)-1])
	last = strings.Trim(last, `"`)
	return last == strings.ToLower(target)
}

func policyMissingAction(policy transpiler.CedarPolicy) bool {
	values := gatherActionValues(policy.Action)
	if len(values) > 0 {
		return false
	}
	return policy.Action.IsAny
}

func policyMissingResource(policy transpiler.CedarPolicy) bool {
	res := policy.Resource
	if len(res.InSet) > 0 {
		return false
	}
	if strings.TrimSpace(res.Type) != "" || strings.TrimSpace(res.ID) != "" {
		return false
	}
	if res.IsAny {
		return true
	}
	return true
}

type lintAnalysis struct {
	valid           bool
	missingAction   bool
	missingResource bool
	hasMCP          bool
	hasHttpRewrite  bool
}

func analyzeContextWithLint(snippet string) lintAnalysis {
	report, err := transpiler.LintFromString(snippet)
	if err != nil || report == nil {
		return lintAnalysis{}
	}
	info := lintAnalysis{valid: true}
	lowerSnippet := strings.ToLower(snippet)
	if strings.Contains(lowerSnippet, `action::"mcpcall"`) {
		info.hasMCP = true
	}
	if strings.Contains(lowerSnippet, `action::"httprewrite"`) {
		info.hasHttpRewrite = true
	}
	for _, issue := range report.Issues {
		switch issue.Code {
		case "missing_action":
			info.missingAction = true
		case "no_resources", "mcp_no_resources":
			info.missingResource = true
		}
		msg := strings.ToLower(issue.Message)
		if strings.Contains(msg, "mcp") {
			info.hasMCP = true
		}
		if strings.Contains(msg, "httprewrite") {
			info.hasHttpRewrite = true
		}
	}
	return info
}

func heuristicPolicySnippet(input string, byteOffset int) (string, bool) {
	start, ok := findPolicyStartHeuristic(input, byteOffset)
	if !ok {
		return "", false
	}
	end := findPolicyEndBytes(input, start)
	if end <= start {
		return "", false
	}
	if end > len(input) {
		end = len(input)
	}
	return input[start:end], true
}

func findPolicyStartHeuristic(input string, byteOffset int) (int, bool) {
	if byteOffset > len(input) {
		byteOffset = len(input)
	}
	lower := strings.ToLower(input[:byteOffset])
	search := lower
	for len(search) > 0 {
		permitIdx := strings.LastIndex(search, "permit")
		forbidIdx := strings.LastIndex(search, "forbid")
		keyword := "permit"
		candidate := permitIdx
		length := len(keyword)
		if forbidIdx > candidate {
			keyword = "forbid"
			candidate = forbidIdx
			length = len(keyword)
		}
		if candidate == -1 {
			break
		}
		if !isIdentifierBoundary(search, candidate, candidate+length) {
			search = search[:candidate]
			continue
		}
		if inComment(input, candidate) {
			search = search[:candidate]
			continue
		}
		return candidate, true
	}

	if strings.TrimSpace(lower) == "" {
		return 0, true
	}
	return 0, false
}

func isIdentifierBoundary(s string, start, end int) bool {
	if start > 0 {
		if isWordRune(rune(s[start-1])) {
			return false
		}
	}
	if end < len(s) {
		if isWordRune(rune(s[end])) {
			return false
		}
	}
	return true
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == ':'
}

func positionToOffset(runes []rune, line, column int) int {
	if len(runes) == 0 {
		return 0
	}
	curLine := 1
	curCol := 1
	for idx, r := range runes {
		if curLine == line && curCol >= column {
			return idx
		}
		if r == '\n' {
			curLine++
			curCol = 1
			if curLine > line {
				return idx + 1
			}
			continue
		}
		curCol++
	}
	return len(runes)
}

func offsetToPosition(runes []rune, offset int) Position {
	if offset < 0 {
		offset = 0
	}
	if offset > len(runes) {
		offset = len(runes)
	}
	line := 1
	col := 1
	for i := 0; i < offset; i++ {
		if runes[i] == '\n' {
			line++
			col = 1
			continue
		}
		col++
	}
	return Position{Line: line, Column: col}
}

func tokenBounds(runes []rune, offset int) (int, int) {
	if offset < 0 {
		return 0, 0
	}
	if offset > len(runes) {
		offset = len(runes)
	}
	start := offset
	for start > 0 {
		r := runes[start-1]
		if !isTokenRune(r) {
			break
		}
		start--
	}
	end := offset
	for end < len(runes) {
		r := runes[end]
		if !isTokenRune(r) {
			break
		}
		end++
	}
	return start, end
}

func isTokenRune(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	switch r {
	case ':', '_', '"', '.', '-', '/', '*':
		return true
	}
	return false
}

func inComment(input string, offset int) bool {
	if offset < 0 {
		offset = 0
	}
	if offset > len(input) {
		offset = len(input)
	}
	// Single-line comment
	lineStart := strings.LastIndex(input[:offset], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}
	singleIdx := strings.Index(input[lineStart:offset], "//")
	if singleIdx >= 0 {
		return true
	}
	// Block comment
	before := input[:offset]
	openIdx := strings.LastIndex(before, "/*")
	if openIdx == -1 {
		return false
	}
	closeIdx := strings.LastIndex(before, "*/")
	return closeIdx < openIdx
}

func normalizePrefix(prefix string) (string, string) {
	trimmed := strings.ToLower(strings.TrimSpace(prefix))
	if trimmed == "" {
		return "", ""
	}
	segment := trimmed
	for _, sep := range []string{`"`, "::", ":", "."} {
		if idx := strings.LastIndex(segment, sep); idx >= 0 {
			segment = segment[idx+len(sep):]
		}
	}
	segment = strings.Trim(segment, `"`)
	return trimmed, segment
}

func keywordItems() []Item {
	items := []Item{
		{Label: "permit", Kind: KindKeyword, InsertText: "permit", Detail: "Allow request when conditions match", Documentation: "Starts a Cedar allow policy."},
		{Label: "forbid", Kind: KindKeyword, InsertText: "forbid", Detail: "Deny request when conditions match", Documentation: "Starts a Cedar deny policy."},
		{Label: "when", Kind: KindKeyword, InsertText: "when", Detail: "Conditional block (positive)", Documentation: "Adds a positive condition block to a policy."},
		{Label: "unless", Kind: KindKeyword, InsertText: "unless", Detail: "Conditional block (negative)", Documentation: "Adds a negative condition block to a policy."},
		{Label: "in", Kind: KindKeyword, InsertText: "in", Detail: "Membership operator", Documentation: "Checks whether a value is a member of a set."},
		{Label: "and", Kind: KindKeyword, InsertText: "and", Detail: "Logical AND", Documentation: "Combine conditions that must all match."},
		{Label: "or", Kind: KindKeyword, InsertText: "or", Detail: "Logical OR", Documentation: "Combine conditions where any may match."},
	}
	return items
}

func snippetItems() []Item {
	return []Item{
		{
			Label:         "Policy skeleton",
			Kind:          KindSnippet,
			InsertText:    "policy ${1:RuleName} = permit (principal, action, resource) when {\n    ${2:// conditions}\n};",
			Detail:        "Insert policy skeleton",
			Documentation: "Creates a permit policy with placeholders for name and conditions.",
		},
		{
			Label:         "forbid skeleton",
			Kind:          KindSnippet,
			InsertText:    "policy ${1:RuleName} = forbid (principal, action, resource) when {\n    ${2:// conditions}\n};",
			Detail:        "Insert forbid policy skeleton",
			Documentation: "Creates a forbid policy template.",
		},
	}
}

func statementSnippetItems() []Item {
	return []Item{
		{
			Label:         "permit statement",
			Kind:          KindSnippet,
			InsertText:    "permit (principal, action == ${1:Action::\"NetworkConnect\"}, resource) when {\n    ${2:// conditions}\n};",
			Detail:        "Insert permit statement",
			Documentation: "Creates a permit statement with placeholders for the action comparator and conditions.",
		},
		{
			Label:         "forbid statement",
			Kind:          KindSnippet,
			InsertText:    "forbid (principal, action == ${1:Action::\"ProcessExec\"}, resource) when {\n    ${2:// conditions}\n};",
			Detail:        "Insert forbid statement",
			Documentation: "Creates a forbid statement with placeholders for the action comparator and conditions.",
		},
	}
}

func permitParameterItems() []Item {
	commit := []string{",", ")", ";"}
	return []Item{
		{
			Label:            "principal",
			Kind:             KindKeyword,
			InsertText:       "principal",
			Detail:           "Subject placeholder",
			Documentation:    "Represents the requesting principal in a policy parameter list.",
			CommitCharacters: commit,
		},
		{
			Label:         "action == Action::\"NetworkConnect\"",
			Kind:          KindSnippet,
			InsertText:    "action == ${1:Action::\"NetworkConnect\"}",
			Detail:        "Compare action",
			Documentation: "Adds an action comparator with a placeholder action identifier.",
			CommitCharacters: []string{
				",", ")", ";",
			},
		},
		{
			Label:         "action != Action::\"NetworkConnect\"",
			Kind:          KindSnippet,
			InsertText:    "action != ${1:Action::\"NetworkConnect\"}",
			Detail:        "Compare action (not equals)",
			Documentation: "Adds an inequality comparator for the action identifier.",
			CommitCharacters: []string{
				",", ")", ";",
			},
		},
		{
			Label:            "action",
			Kind:             KindKeyword,
			InsertText:       "action",
			Detail:           "Action placeholder",
			Documentation:    "Represents the action being authorized.",
			CommitCharacters: commit,
		},
		{
			Label:         "resource == Host::\"api.example.com\"",
			Kind:          KindSnippet,
			InsertText:    "resource == ${1:Host::\"api.example.com\"}",
			Detail:        "Compare resource",
			Documentation: "Adds a resource comparator with a placeholder host identifier.",
			CommitCharacters: []string{
				",", ")", ";",
			},
		},
		{
			Label:         "resource != Host::\"api.example.com\"",
			Kind:          KindSnippet,
			InsertText:    "resource != ${1:Host::\"api.example.com\"}",
			Detail:        "Compare resource (not equals)",
			Documentation: "Adds an inequality comparator for the resource identifier.",
			CommitCharacters: []string{
				",", ")", ";",
			},
		},
		{
			Label:            "resource",
			Kind:             KindKeyword,
			InsertText:       "resource",
			Detail:           "Resource placeholder",
			Documentation:    "Represents the resource being accessed.",
			CommitCharacters: commit,
		},
	}
}

func actionItems() []Item {
	commit := []string{",", ")", ";", "]"}
	return []Item{
		{Label: `Action::"FileOpen"`, Kind: KindAction, InsertText: `Action::"FileOpen"`, Detail: "Allow reading or writing files", Documentation: "Applies to file open operations.", CommitCharacters: commit},
		{Label: `Action::"FileOpenReadOnly"`, Kind: KindAction, InsertText: `Action::"FileOpenReadOnly"`, Detail: "Allow read-only file access", Documentation: "Restricts allow to read-only opens.", CommitCharacters: commit},
		{Label: `Action::"FileOpenReadWrite"`, Kind: KindAction, InsertText: `Action::"FileOpenReadWrite"`, Detail: "Allow read-write file access", Documentation: "Enables read/write operations on files.", CommitCharacters: commit},
		{Label: `Action::"ProcessExec"`, Kind: KindAction, InsertText: `Action::"ProcessExec"`, Detail: "Allow process execution", Documentation: "Controls process execution events.", CommitCharacters: commit},
		{Label: `Action::"NetworkConnect"`, Kind: KindAction, InsertText: `Action::"NetworkConnect"`, Detail: "Allow network connections", Documentation: "Applies to outbound connect operations.", CommitCharacters: commit},
		{Label: `Action::"HttpRewrite"`, Kind: KindAction, InsertText: `Action::"HttpRewrite"`, Detail: "Allow HTTP header rewrite", Documentation: "Applies to HTTP header rewrite rules.", CommitCharacters: commit},
		{Label: `Action::"McpCall"`, Kind: KindAction, InsertText: `Action::"McpCall"`, Detail: "Allow or deny MCP call", Documentation: "Controls MCP tool invocations.", CommitCharacters: commit},
	}
}

func resourceItems(hints Hints) []Item {
	commit := []string{",", "]", ")"}
	var items []Item

	for _, file := range hints.Files {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		items = append(items, Item{
			Label:            `File::"` + file + `"`,
			Kind:             KindResource,
			InsertText:       `File::"` + file + `"`,
			Detail:           "Observed file path",
			Documentation:    "Runtime-observed file from active policies or recent events.",
			CommitCharacters: commit,
		})
	}

	for _, dir := range appendTrailingSlash(hints.Dirs) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		items = append(items, Item{
			Label:            `Dir::"` + dir + `"`,
			Kind:             KindResource,
			InsertText:       `Dir::"` + dir + `"`,
			Detail:           "Observed directory",
			Documentation:    "Runtime-observed directory with trailing slash.",
			CommitCharacters: commit,
		})
	}

	for _, host := range hints.Hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		items = append(items, Item{
			Label:            `Host::"` + host + `"`,
			Kind:             KindResource,
			InsertText:       `Host::"` + host + `"`,
			Detail:           "Observed host",
			Documentation:    "Runtime-observed host name or host:port.",
			CommitCharacters: commit,
		})
	}

	items = append(items,
		Item{Label: `File::"/path"`, Kind: KindResource, InsertText: `File::"/path"`, Detail: "Specific file path", Documentation: "Targets a single file path.", CommitCharacters: commit},
		Item{Label: `Dir::"/path/"`, Kind: KindResource, InsertText: `Dir::"/path/"`, Detail: "Directory path (recursive)", Documentation: "Targets a directory with trailing slash.", CommitCharacters: commit},
		Item{Label: `Host::"example.com"`, Kind: KindResource, InsertText: `Host::"example.com"`, Detail: "Hostname or host:port", Documentation: "Targets network connections to a host.", CommitCharacters: commit},
		Item{Label: `Net::DnsZone::"example.com"`, Kind: KindResource, InsertText: `Net::DnsZone::"example.com"`, Detail: "DNS zone wildcard", Documentation: "Matches all hosts within the zone; apex excluded.", CommitCharacters: commit},
	)

	return items
}

func appendTrailingSlash(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if strings.HasSuffix(v, "/") {
			out = append(out, v)
		} else {
			out = append(out, v+"/")
		}
	}
	return out
}

func mcpResourceItems(hints Hints) []Item {
	var items []Item
	commit := []string{",", "]", ")"}

	for _, server := range hints.Servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		items = append(items, Item{
			Label:            `MCP::Server::"` + server + `"`,
			Kind:             KindServer,
			InsertText:       `MCP::Server::"` + server + `"`,
			Detail:           "Observed MCP server",
			Documentation:    "Runtime observed MCP server identifier.",
			CommitCharacters: commit,
		})
	}

	for _, tool := range hints.Tools {
		tool = strings.TrimSpace(tool)
		if tool == "" {
			continue
		}
		items = append(items, Item{
			Label:            `MCP::Tool::"` + tool + `"`,
			Kind:             KindTool,
			InsertText:       `MCP::Tool::"` + tool + `"`,
			Detail:           "Observed MCP tool",
			Documentation:    "Runtime observed MCP tool identifier.",
			CommitCharacters: commit,
		})
	}

	items = append(items, Item{
		Label:            `MCP::Server::"server"`,
		Kind:             KindServer,
		InsertText:       `MCP::Server::"$1"`,
		Detail:           "Specific MCP server",
		Documentation:    "Targets MCP server identifiers observed in runtime.",
		CommitCharacters: commit,
	})
	items = append(items, Item{
		Label:            `MCP::Tool::"tool"`,
		Kind:             KindTool,
		InsertText:       `MCP::Tool::"$1"`,
		Detail:           "Specific MCP tool",
		Documentation:    "Targets MCP tools invoked via MCP::Tool::\"...\".",
		CommitCharacters: commit,
	})
	return items
}

func httpRewriteSnippetItems() []Item {
	return []Item{
		{
			Label:         "HttpRewrite snippet",
			Kind:          KindSnippet,
			InsertText:    `context.header == "${1:X-Header}"\n    context.value == "${2:value}"`,
			Detail:        "Insert HttpRewrite header/value conditions",
			Documentation: "Adds context.header and context.value comparisons for HttpRewrite policies.",
		},
	}
}

func contextKeyItems() []Item {
	return []Item{
		{Label: "context.hostname", Kind: KindConditionKey, InsertText: "context.hostname", Detail: "Hostname from the request context", Documentation: "Matches against the request hostname."},
		{Label: "context.header", Kind: KindConditionKey, InsertText: "context.header", Detail: "HTTP header key in rewrite context", Documentation: "References the header name during HttpRewrite evaluation."},
		{Label: "context.value", Kind: KindConditionKey, InsertText: "context.value", Detail: "HTTP header value in rewrite context", Documentation: "References the header value during HttpRewrite evaluation."},
	}
}

func httpRewriteContextItems(hints Hints) []Item {
	commit := []string{",", "]", ")"}
	var items []Item
	for _, header := range hints.Headers {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		items = append(items, Item{
			Label:            `"` + header + `"`,
			Kind:             KindHeader,
			InsertText:       `"` + header + `"`,
			Detail:           "Observed header",
			Documentation:    "Header observed in runtime events.",
			CommitCharacters: commit,
		})
	}
	items = append(items, Item{
		Label:            `"X-Header"`,
		Kind:             KindHeader,
		InsertText:       `"${1:X-Header}"`,
		Detail:           "Header placeholder",
		Documentation:    "Specify the header name being rewritten.",
		CommitCharacters: commit,
	})
	return items
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
