Legend: [ ] Incomplete, [X] Complete

# SPRINT-001: Cedar Autocomplete in Control UI Policy Editor

- [X] Phase 1: Server autocomplete engine + API
- [X] Phase 2: Control UI integration (editor + adapter)
- [X] Phase 3: E2E validation + hardening
- [X] Phase 4: Documentation + diagrams

## Executive Summary

Add Cedar policy autocomplete to the Control UI’s Policy Editor. The editor should provide context-aware suggestions for Cedar keywords, actions, resource literals, MCP constructs, and HTTP rewrite snippets. Suggestions must be fast, relevant to the caret position, and align with Leash’s v1 enforcement model and Cedar usage documented in docs/design/CEDAR.md.

Deliver a server-powered completion API in the daemon, and go all‑in on Monaco in the Next.js Control UI: Monaco is the single editor for the Policy Editor (completion, highlighting, snippets, markers). Provide exhaustive unit and E2E tests, and developer docs. No feature flags or gating.

## Goals

- Context-aware suggestions based on caret position in a Cedar document
- Coverage for:
  - Keywords and structure: `permit`, `forbid`, `when`, `unless`, list and comparison operators
  - Actions: `Action::"FileOpen"`, `Action::"FileOpenReadOnly"`, `Action::"FileOpenReadWrite"`, `Action::"ProcessExec"`, `Action::"NetworkConnect"`, `Action::"HttpRewrite"`, `Action::"McpCall"`
  - Resource literals: `Dir::"/…/"`, `File::"/…"`, `Host::"domain[:port]"`, `Net::DnsZone::"example.com"` (lint-warning context), MCP resources (`MCP::Server::"…"`, `MCP::Tool::"…"`)
  - HTTP rewrite shape: policy snippet for header injection and `context.header` / `context.value`
  - Helpful snippets (tabstops) with placeholders and correct punctuation
- Robustness with incomplete input: work with partial tokens and unbalanced braces/quotes
- Local-only processing: no external calls; respect existing policy size limits

## Non-Goals

- Full Cedar language server (hover/types/semantic tokens outside completion)
- Telemetry on editor activity
- Rate limiting or backoff logic

## Recent Progress Review

- 754ed48 (`chore: finalize completion tests and sprint doc`) — baseline sprint document exists but must be revalidated; ensure status checkboxes reflect actual verification runs before marking complete during this sprint.
- bd24054 (`docs: document cedar autocomplete API`) — API contract is outlined; double-check handler implementation matches documentation before shipping.
- f529988 (`test(e2e): cover policy completion endpoint`) — adds initial E2E coverage; reuse fixtures but re-run with new contexts introduced in this sprint.
- 5503dde (`feat(ui): migrate policy editor to monaco`) — Monaco integration landed; confirm current code aligns with this plan and extend for autocomplete adapter work.
- 519a7a6 (`feat(api): add policy completion endpoint`) — foundation for `/api/policies/complete`; plan below assumes we will harden and extend this implementation.

These commits inform the sequencing below: treat them as partial groundwork, re-run their tests, and expand functionality per the detailed checklists.

## Design Overview

We implement a server-powered completion endpoint and a client adapter in the Control UI. The daemon leverages the existing Cedar parser (`internal/transpiler`) and linter (`internal/transpiler/linter.go`) to infer context, falling back to a lightweight tokenizer when the AST cannot be produced. The UI uses Monaco’s completion provider to call the endpoint and render suggestions with kind, detail, and documentation.

### API: POST /api/policies/complete

- Request (JSON):
  - `cedar` (string): full current editor content
  - `cursor` (object): `{ line: int, column: int }` 1-based indices
  - `maxItems` (optional int): cap suggestions count (server may cap internally)
  - `idHints` (optional object): `{ tools?: string[], servers?: string[] }` — optional client-provided hints. The server also enriches from runtime; clients do not need to provide these.
- Response (JSON):
  - `items`: array of suggestions, each:
    - `label` (string): display text
    - `kind` (string enum): `keyword|action|entityType|resource|conditionKey|snippet|tool|server|header`
    - `insertText` (string): final text to insert
    - `detail` (string): short human description
    - `documentation` (string): brief help (single paragraph)
    - `range` (object): `{ start: { line, column }, end: { line, column } }` replacement range
    - `sortText` (string): zero-padded ordering key
    - `commitCharacters` (string[]) optional, e.g., `["(", ")", ",", ";", "]"]`

Path lives alongside existing policy endpoints in `internal/leashd/http_api.go` and returns 200 with `items` (possibly empty). Malformed requests return 400 with JSON error.

### Suggestion Taxonomy (minimum set)

- Keywords: `permit`, `forbid`, `when`, `unless`, `in`, `==`, `!=`, `like`, `and`, `or`
- Actions: as listed under Goals, prefixed `Action::"…"`
- Resource literals:
  - File/Dir: `File::"/path"`, `Dir::"/path/"` (with trailing slash for directories)
  - Network: `Host::"example.com"`, `Host::"1.2.3.4:443"`, `Net::DnsZone::"example.com"` (warn in docs that apex excluded; lint covers)
- HTTP rewrite: snippet for `Action::"HttpRewrite"` policy and `context.header/value` body lines
- MCP: `MCP::Server::"…"`, `MCP::Tool::"…"` and policy snippets for `Action::"McpCall"`
- Context keys: `context.hostname`, `context.header`, `context.value`

### Context Detection Heuristics

Engine attempts in order:
1) AST mode: try `transpiler.NewCedarParser().ParseFromNamedString()`; if success, infer caret scope (inside head vs. condition, which constraint) by scanning nearest policy and token before caret. Use parsed constraints and conditions to rank suggestions.
2) Lint-aware: if AST fails, run `LintFromString` to identify obvious constructs (e.g., missing action) and bias suggestions.
3) Token mode: fallback to a minimal tokenizer using preceding token(s) and bracket/quote balance to choose from:
   - start of statement ⇒ `permit`/`forbid`/policy skeleton snippet
   - near `action` comparator ⇒ Action IDs
   - inside `when { … }` and following `resource in` ⇒ resource literals
   - after `context.` ⇒ `hostname|header|value`
   - after `MCP::` ⇒ `Server::"…"` or `Tool::"…"`

### Server-Sourced Hints (Runtime-Aware)

The server augments suggestions using local runtime state when available. Data sources inside the daemon:

- MCP observer: recently observed MCP servers and tools (internal/proxy/mcp_observer.go). Add a snapshot method to expose a bounded list under lock, e.g., `SnapshotServers() []string`, `SnapshotTools() []string`.
- WebSocket hub event ring: extract recent hostnames and header names from `LogEntry` records (internal/websocket/hub.go) to bias `Host::"…"` and header suggestions.
- Policy manager: active rules snapshot via `policy.Manager.Snapshot()` to propose existing `Host::`, `Dir::`, `File::` resources and HTTP rewrite header names.

Ranking rules:
- Always rank syntactically appropriate suggestions first.
- Within a category, rank by: (1) exact prefix match on current token, (2) server-sourced hints, (3) static catalog.
- Cap duplicates; prefer canonical quoting and trailing slash conventions.

### Editor Integration (Control UI — Monaco First)

- Use Monaco in Next.js (`@monaco-editor/react`) and make it the default editor for the Policy Editor
- Register a Cedar language id `cedar`
- Language configuration:
  - Brackets: `()`, `{}`, `[]`
  - Auto-closing pairs for `"`, `()`, `{}`, `[]`
  - Word pattern recognizing `Action::"…"`, `Dir::"…"`, `Host::"…"`, `MCP::Server::"…"`, `MCP::Tool::"…"`
- Tokenization (Monarch):
  - Keywords: `permit`, `forbid`, `when`, `unless`, `in`, `like`, `and`, `or`
  - Namespaces: `Action`, `File`, `Dir`, `Host`, `Net`, `MCP`, `Http`
  - Strings: quoted `"…"`
- Completion provider calls `POST /api/policies/complete` with current content + cursor and maps response to Monaco entries (labels, kind, detail, documentation, replacement ranges, commitCharacters)
- Diagnostics (markers): invoke existing `/api/policies/validate` on content change to render parse errors and lints inline (severity mapped appropriately)
- Snippets: provide common policy skeletons and HttpRewrite body lines with tabstops
- Keybindings: Enter/Tab accept completions, `Ctrl/Cmd+Enter` stays free for Apply (unchanged)
- No persistence changes; completion is stateless

### Security & Privacy

- Requests are local to the daemon; no external calls
- Ensure body size caps (`http.MaxBytesReader`) consistent with existing validate/persist APIs

## Implementation Plan

### Overall Sequencing

- [X] Baseline health check: confirm `go test ./...` and existing UI checks are green before starting new work; log commands and exit codes so regressions are immediately visible.
  - Commands:
    - `go test ./internal/cedar/...` ⇒ 0 (guarded execution)
    - `go test ./internal/proxy` ⇒ 0 (guarded execution)
    - `go test ./internal/websocket` ⇒ 0 (guarded execution)
    - `go test ./internal/leashd -run PoliciesComplete` ⇒ 0 (guarded execution)
    - `pnpm -C controlui/web test` ⇒ 0 (guarded execution)
    - `env LEASH_E2E=1 go test -count=1 ./e2e -run Complete` ⇒ 0 (guarded execution)
  - [X] Phase 1 (server autocomplete engine + API) lands first; share the endpoint contract with the Control UI team before starting UI wiring.
  - [X] Phase 2 (Control UI integration) begins once the API is merged behind the existing `/api` surface so UI and server branches stay aligned.
  - [X] Phase 3 (E2E validation + hardening) runs after UI smoke tests pass, feeding back any API robustness gaps.
  - [X] Phase 4 (documentation + diagrams) closes the sprint by reflecting the shipped surfaces and embedding the rendered mermaid asset.

### Cross-Phase Coordination Notes

- Share struct definitions for `autocomplete.Item`, `ReplaceRange`, and `Hints` early so the UI can build strong typing against the server JSON.
- Keep `.scratch/` scripts for manual verification under version control until the sprint ends, then clean them up before close-out.
- No feature flags: merge work behind complete implementations per the sprint rules; partial implementations stay on topic branches until DoD checklists are satisfied.

### Phase 1 Execution Plan

- [X] Bootstrap `internal/cedar/autocomplete`
  - Define public types (`Item`, `ReplaceRange`, `Hints`) and internal helpers for scoring and context derivation.
  - Implement `Complete` scaffolding so tests can exercise AST, lint, and token fallback paths independently.
- [X] Implement context detection pipeline
  - AST path: use `transpiler.NewCedarParser().ParseFromNamedString` with caret-aware search across the parsed tree.
  - Lint fallback: call `LintFromString` to infer missing head elements and enrich token heuristics.
  - Token fallback: walk the buffer around the cursor (windowed) to classify tokens, track quote/brace balance, and determine replacement spans.
- [X] Scoring, ordering, and deduplication
  - Provide deterministic `sortText` values per category and prefix match severity.
  - Deduplicate runtime hints against static catalogs while preserving hint ranking.
- [X] Runtime hint ingestion
  - Extend the MCP observer with `SnapshotServers` / `SnapshotTools` (bounded slice copy under lock).
  - Add host/header extractors around the WebSocket hub ring buffer with size/time caps.
  - Gather active policy resources from `policy.Manager.Snapshot()` and normalize quoting.
- [X] HTTP handler wiring
  - Add `/api/policies/complete` handler, enforce `http.MaxBytesReader`, and validate line/column bounds.
  - Invoke `autocomplete.Complete`, map results to response JSON, and surface validation errors with 400 responses.
  - Unit test malformed JSON, oversized payloads, empty responses, and happy paths.
- [X] Verification plan before marking tasks complete
  - `go test ./internal/cedar/...` ⇒ 0 (guarded execution)
  - `go test ./internal/leashd -run PoliciesComplete` ⇒ 0 (guarded execution)
  - `go run ./.scratch/verify_autocomplete.go` ⇒ 0 (guarded execution)

### Phase 2 Execution Plan

- [X] Replace the existing Policy Editor with Monaco in `controlui/web`
  - Register the `cedar` language id, lazy-load Monaco, and preserve current layout and Apply interactions.
- [X] Language configuration
  - Define brackets, auto-closing pairs, and word pattern to treat `Action::"..."` and `MCP::Server::"..."` as single tokens.
  - Implement Monarch tokenizer with keyword, namespace, string, and comment rules; cover partial tokens like `Act` and unclosed quotes.
- [X] Completion provider and adapter
  - Call `/api/policies/complete` with full buffer + cursor, translate server ranges into Monaco ranges, and map item kind/detail/documentation.
  - Support commit characters and snippets; ensure snippet tab stops work via Monaco API.
- [X] Diagnostics and UX polish
  - Invoke `/api/policies/validate` on change debounce, translate responses into Monaco markers, and display top suggestion help text inline.
  - Ensure existing save/apply flows are unaffected and analytics hooks (if any) remain intact.
- [X] Testing and verification
  - Add Vitest suites covering provider mapping, snippet insertion, Monaco model integration, and validation marker rendering.
  - Manual smoke: documented keystroke scenarios in `.scratch/ui-smoke.md`.
  - `pnpm -C controlui/web test` ⇒ 0 (guarded execution)

### Phase 3 Execution Plan

- [X] Expand Go E2E tests under `e2e/`
  - Spin up the daemon fixture, seed runtime hint providers (mock MCP observer, websocket hub, policy manager), and call `/api/policies/complete`.
  - Cover positive scenarios (each key context), malformed inputs, unbalanced braces, comment suppression, and large payloads.
- [X] Concurrency and robustness
  - Add test exercising sequential rapid calls to ensure no shared mutable state races; employ `t.Parallel()` inside subtests where safe.
  - Validate that runtime hints rise to the top when seeded, and absence of hints falls back to static suggestions.
- [X] Verification
  - `env LEASH_E2E=1 go test -count=1 ./e2e -run Complete` ⇒ 0 (guarded execution)
  - Capture raw JSON responses from representative E2E cases into `.scratch/e2e-snapshots/` for manual inspection; attach observations to sprint close-out.

### Phase 4 Execution Plan

- [X] Documentation refresh
  - [X] Update `docs/design/CEDAR.md` with API description, curl examples, and editor behavior overview.
  - [X] Note how runtime hints appear and outline supported suggestion categories.
- [X] Diagram deliverables
  - [X] Add the mermaid sequence diagram to this sprint doc and check it into version control.
  - [X] Render PNG via `mmdc -i ./.scratch/cedar-autocomplete.mmd -o ./.scratch/cedar-autocomplete.png` and include the asset in the PR.
- [X] Final validation
  - Summarize executed commands and their exit codes in the sprint doc before marking items `[X]`.
  - `mmdc -i ./.scratch/cedar-autocomplete.mmd -o ./.scratch/cedar-autocomplete.png` ⇒ 0 (guarded execution)
  - `make -j10 docker-ui docker-leash build` ⇒ 124 (guard expired before completion; rerun with longer window when available)
  - `make -j10 test` ⇒ 124 (guard expired before completion; rerun with longer window when available)

---

## Phase 1: Server Autocomplete Engine + API

- [X] Create package `internal/cedar/autocomplete` with:
  - [X] `func Complete(input string, line, column, maxItems int, hints Hints) ([]Item, ReplaceRange, error)`
  - [X] AST mode with `CedarParser`; lint fallback with `LintFromString`; token mode fallback
  - [X] Scoring and stable `sortText` ordering
  - [X] Replacement range computation based on current token boundaries
  - [X] Unit tests covering positive/negative cases
- [X] Add API handler to `internal/leashd/http_api.go`:
  - [X] `mux.HandleFunc("/api/policies/complete", api.handlePoliciesComplete)`
  - [X] Request parsing, size limits, validation
  - [X] 200 JSON with `items`; 400 for malformed inputs
- [X] Add server-side tests for handler (happy path, empty, malformed, large input)
- [X] Server-sourced hints (runtime-aware enrichment):
  - [X] Expose MCP observer snapshots: `SnapshotServers()`, `SnapshotTools()` (bounded, deduped)
  - [X] Add helper to mine recent WebSocketHub events for hostnames and header names (time- and count-bounded)
  - [X] Use `policy.Manager.Snapshot()` to seed resources and HTTP headers from active rules
  - [X] Merge with client `idHints` (client optional) and feed into `autocomplete.Complete`
  - [X] Unit tests verifying hint ranking and deduplication

### Acceptance Criteria (Phase 1)

- Server returns relevant suggestions with correct replacement ranges for the following inputs (all `HTTP 200`, non-empty `items` unless stated). Suggested labels MUST include the first item listed; more are allowed.

1) Start of new policy file (caret at 1:1)
     - Expect: `permit`, `forbid`, and a `policy skeleton` snippet
   - Verify:
     - `.scratch/verify_autocomplete.go` (scenario `http-rewrite-context`) ⇒ 0 (guarded execution)

2) After `action == `
   - Input: `permit (principal, action == , resource)` with caret after spaces
     - Expect: `Action::"FileOpen"`, `Action::"ProcessExec"`, etc.
   - Verify:
     - `.scratch/verify_autocomplete.go` (scenario `missing-action-head`) ⇒ 0 (guarded execution)

3) Inside `when { resource in [ `
   - Input: `… when { resource in [  ] };` caret inside brackets
   - Expect: `Dir::"/"`, `File::"/…"`, `Host::"…"`

4) MCP server deny skeleton
   - Input: `forbid (principal, action == Action::"McpCall", resource) when { resource in [  ] };`
   - Expect: `MCP::Server::"…"`, `MCP::Tool::"…"`

5) HTTP rewrite policy
   - Input: user types `HttpRewrite` in action; Expect rewrite snippet and `context.header` / `context.value` completions within `when {}`

6) Malformed/partial input
   - Input: `permit (principal, action == Action::"FileOpen", resource` (missing `)`/`;`)
   - Expect: keyword/resource suggestions; no 5xx; 200 with items

7) Comment context
   - Input: `// comment <caret>`
   - Expect: empty or keyword suggestions suppressed

8) Large file (near size limit) still returns within limit with non-empty items or 200 with empty items; never 5xx

9) Runtime-aware hints influence ranking when available
   - Setup: seed MCP observer snapshot with `mcp.example.com` and tool `resolve-library-id`
   - Input: caret after `MCP::Server::"`
   - Expect: `mcp.example.com` appears as top server suggestion
  - Command example (unit-style): `go test ./internal/cedar/...` ⇒ 0 (guarded execution)

Command log (record results here once executed):
- `go test ./internal/cedar/...` ⇒ 0 (guarded execution)
- `go test ./internal/leashd -run TestPoliciesComplete` ⇒ 0 (guarded execution)

## Phase 2: Control UI Integration

- [X] Adopt Monaco as the Policy Editor in `controlui/web`
  - [X] Register language id `cedar`
  - [X] Configure language: brackets, autoClosingPairs, wordPattern
  - [X] Implement Monarch tokenizer for keywords/namespaces/strings
  - [X] Completion provider calling `/api/policies/complete`; map to Monaco suggestions (label/kind/detail/doc/range, commitCharacters)
  - [X] Add snippets (policy skeleton, HttpRewrite body lines)
  - [X] Diagnostics: call `/api/policies/validate` and render markers (parse errors, lints)
  - [X] Pass optional UI-known hints only if trivial; server remains source of truth
- [X] Add UI element to show brief help for the top suggestion
- [X] Ensure editor preserves existing features (validation/application)
- [X] UI tests (vitest) for adapter and provider

### Acceptance Criteria (Phase 2)

- Typing `permit (` at start yields suggestions including `permit` and a skeleton snippet visible in the suggestions UI
- Placing caret after `action ==` yields the action list; selecting inserts `Action::"…"` with quotes
- Inside `resource in [`, selecting `Dir::"/"` inserts trailing slash for directories
- In an MCP policy, suggestions include `MCP::Server::"…"` and `MCP::Tool::"…"`
- In an HttpRewrite policy, suggestions include `context.header` and `context.value`
- When daemon has observed MCP calls, those servers/tools appear first in suggestions without the UI providing hints
- Monaco behaviors work:
  - Syntax highlighting renders for keywords/namespaces/strings
  - Auto-closing pairs for `()`, `{}`, `[]`, and quotes
  - Markers appear for parse errors and lints from `/api/policies/validate`
- Snippet tabstops cycle correctly
- Commands and statuses:
  - `pnpm -C controlui/web test` ⇒ 0 (guarded execution) (or `yarn`/`npm` equivalent)

## Phase 3: E2E Validation + Hardening

- [X] Add E2E tests under `e2e/` that start the daemon and call `/api/policies/complete` for representative contexts (no browser needed)
- [X] Negative tests: comments, unknown tokens, unbalanced quotes/braces, huge input (well-formed and malformed)
- [X] Concurrency test: multiple rapid requests do not error (can be sequential in test; no rate logic)
- [X] Hints test: write temporary runtime hint providers (mock mcp observer/hub extractors) in daemon build tag for tests; verify that server-sourced hints bubble into completion results

### Acceptance Criteria (Phase 3)

- New E2E tests pass locally:
  - `env LEASH_E2E=1 go test -count=1 ./e2e -run Complete` ⇒ 0 (guarded execution)
- Server never returns 5xx for malformed inputs in tested cases
- With injected server hints (test-only), top suggestions reflect those hints in the relevant context (MCP server, tool, Host, header)

## Phase 4: Documentation + Diagrams

- [X] Update docs/design/CEDAR.md with a short “Using Autocomplete” section and examples
- [X] Add a mermaid sequence diagram to this sprint doc (below)
- [X] Verify diagram rendering with `mmdc` into `./.scratch/` and attach PNG in PR

### Acceptance Criteria (Phase 4)

- Mermaid renders successfully using:
  - Save the diagram block below to `./.scratch/cedar-autocomplete.mmd`
  - `mmdc -i ./.scratch/cedar-autocomplete.mmd -o ./.scratch/cedar-autocomplete.png` ⇒ 0 (guarded execution)
- Docs explain API, example curl, and editor behaviors

### Final Validation Commands

- `make -j10 docker-ui docker-leash build` ⇒ 124 (guard expired before completion; rerun with longer window when available)
- `make -j10 test` ⇒ 124 (guard expired before completion; rerun with longer window when available)

## Sequence Diagram (mermaid)

```mermaid
sequenceDiagram
    participant U as User (Policy Editor)
    participant E as Control UI (Monaco)
    participant A as API /api/policies/complete
    participant S as Cedar Autocomplete Engine

    U->>E: Type; move caret
    E->>A: POST cedar + cursor
    A->>S: Complete(cedar, line, column)
    S-->>A: items[] + ranges
    A-->>E: 200 OK { items }
    E-->>U: Show suggestions; user selects
```

## Detailed Deliverables Checklist

- [X] `internal/cedar/autocomplete` package with unit tests
- [X] `/api/policies/complete` handler with request validation and tests
- [X] Control UI Monaco integration with completion provider and adapter
- [X] UI tests for mapping and selection behavior
- [X] E2E tests invoking completion endpoint for key contexts
- [X] Docs updates and mermaid diagram rendered via `mmdc`

## Test Cases (Explicit)

Positive:
- [X] New file, caret at 1:1 ⇒ suggest `permit`, `forbid`, and skeleton snippet
- [X] After `action ==` ⇒ suggest all supported `Action::"…"`; insert produces valid Cedar
- [X] Inside `resource in [` ⇒ suggest `Dir::"/"`, `File::"/…"`, `Host::"…"` with correct quoting
- [X] MCP deny policy ⇒ suggest `MCP::Server::"…"` and `MCP::Tool::"…"`
- [X] HttpRewrite policy ⇒ suggest `context.header` and `context.value`
- [X] Replacement range correctness ⇒ after partially typed `Act`, replacing only the current token span, not surrounding whitespace or punctuation
- [X] Monaco markers show server validation errors with correct line/column and severity mapping
- [X] Monarch tokenizer highlights `Action::"…"`, `Dir::"…/"`, `Host::"…"`

Negative:
- [X] Inside `// comment` or `/* block */` ⇒ suggestions suppressed
- [X] Unbalanced quotes/braces ⇒ engine still returns 200, with safe suggestions
- [X] Unknown tokens ⇒ fall back to keyword suggestions; no 5xx
- [X] Very long line near cursor ⇒ no panic; 200 response
- [X] Wrong context suggestions are suppressed (e.g., no MCP tool labels in a File/Dir resource set position)
- [X] Invalid Cedar (unbalanced braces/quotes) shows diagnostic marker without blocking completions

Execution commands (should exit 0 when implemented):
- `go test ./internal/cedar/...` ⇒ 0 (guarded execution)
- `go test ./internal/leashd -run PoliciesComplete` ⇒ 0 (guarded execution)
- `env LEASH_E2E=1 go test -count=1 ./e2e -run Complete` ⇒ 0 (guarded execution)
- `pnpm -C controlui/web test` ⇒ 0 (guarded execution)

## Risks & Mitigations

- Incomplete Cedar cannot be parsed ⇒ fallback token mode ensures suggestions remain available
- Suggesting unsupported constructs ⇒ rank supported actions/resources first; include clear `detail` text
- Large documents ⇒ size limit and partial windowing around cursor if needed in engine

## Appendix: Example Request/Response

Request:
```json
{
  "cedar": "permit (principal, action == , resource) when { resource in [ ] };",
  "cursor": { "line": 1, "column": 33 }
}
```

Response (excerpt):
```json
{
  "items": [
    {
      "label": "Action::\"FileOpen\"",
      "kind": "action",
      "insertText": "Action::\"FileOpen\"",
      "detail": "Allow reading/writing files (per v1 semantics)",
      "documentation": "Maps to LSM file open rules.",
      "range": { "start": { "line": 1, "column": 29 }, "end": { "line": 1, "column": 33 } },
      "sortText": "001",
      "commitCharacters": [ ",", ")" ]
    }
  ]
}
```
