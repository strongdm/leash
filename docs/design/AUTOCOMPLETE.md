# Policy Editor Cedar Autocompletion

This document captures the end-to-end design for Leash’s Cedar autocomplete experience, spanning the front-end [Monaco](https://microsoft.github.io/monaco-editor/) integration, HTTP surfaces, and the Go autocomplete engine that synthesizes runtime hints.

## Core Entities
- **CedarEditor (React)** drives Monaco, manages abortable completion fetches, and renders contextual suggestion help sourced from the top-ranked item.
- **Monaco Completion Provider** registers for Cedar language IDs, collects the full buffer plus cursor location, and routes requests through `fetchPolicyCompletions`.
- **Policy API (`/api/policies/complete`)** validates payloads, composes dynamic hints from runtime services, and delegates to the autocomplete engine.
- **Autocomplete Engine (`internal/cedar/autocomplete`)** parses the Cedar buffer, detects editing context, ranks candidates, and returns both completion items and the replacement range.
- **Hint Contributors** include the policy manager (compiled policy sets), MITM proxy (observed MCP servers/tools), and WebSocket hub (recent HTTP metadata); optional client hints are merged last to preserve server-derived priority.
- **Completion Schema** consists of `CompletionRequest`, `CompletionResponse`, `CompletionItem`, and `ReplaceRange`, ensuring Monaco receives label/kind metadata and the span to overwrite.

## Request Flow
```mermaid
flowchart TD
    User["User types in Cedar editor"]
    Editor["CedarEditor React component"]
    Provider["Monaco completion provider"]
    ApiCall["fetchPolicyCompletions()"]
    HTTP["POST /api/policies/complete"]
    Handler["policyAPI.handlePoliciesComplete"]
    Engine["autocomplete.Complete()"]
    Response["CompletionResponse payload"]
    Mapper["mapCompletionItem()"]
    Monaco["Monaco UI updates"]

    User --> Editor --> Provider --> ApiCall --> HTTP --> Handler
    Handler -->|calls| Engine
    Engine -->|items + range| Handler
    Handler --> Response --> Mapper --> Monaco
    Monaco --> Provider
```

## Hint Aggregation Pipeline
```mermaid
flowchart LR
    PolicyMgr["policy.Manager Snapshot()"]
    Mitm["MITM proxy MCP hints"]
    Hub["WebSocket hub telemetry"]
    ClientHints["Client-supplied idHints"]
    Builder["buildCompletionHints()"]
    Engine["autocomplete.Complete()"]

    PolicyMgr --> Builder
    Mitm --> Builder
    Hub --> Builder
    ClientHints --> Builder
    Builder -->|normalized + deduped Hints| Engine
```

## Data Model
```mermaid
erDiagram
    CedarEditor ||--|| CompletionRequest : emits
    CompletionRequest ||--|| CompletionCursor : uses
    CompletionRequest }o--|| ClientHints : "optional idHints"
    PolicyAPI ||--|| CompletionRequest : receives
    PolicyAPI ||--o{ Hints : builds
    PolicyManager ||--o{ Hints : contributes
    MITMProxy ||--o{ Hints : contributes
    WebSocketHub ||--o{ Hints : contributes
    AutocompleteEngine ||..|| PolicyAPI : invokedBy
    AutocompleteEngine ||--o{ CompletionItem : produces
    CompletionResponse ||--|{ CompletionItem : contains
    CompletionResponse ||--|| ReplaceRange : shares
    CedarEditor ||--o{ CompletionItem : renders
```

## End-to-End Narrative
1. **Keystroke Handling**: The Monaco provider fires on trigger characters. `CedarEditor` aborts any in-flight request before issuing `fetchPolicyCompletions`, preventing stale completions from racing in the UI.
2. **Request Validation**: `policyAPI.handlePoliciesComplete` enforces cursor bounds, limits payload size, rejects unknown fields, and converts optional `idHints` into structured hint requests.
3. **Hint Assembly**: Runtime artifacts are snapshot and merged—policy-derived file/dir/host data, MITM-proxy MCP identifiers, WebSocket-observed HTTP headers, and client hints. The builder normalizes casing, trims whitespace, and deduplicates with caps to avoid overwhelming Monaco.
4. **Context Detection & Ranking**: `autocomplete.Complete` tokenizes the buffer, skips comment regions, inspects the AST/lint signals, and ranks candidate pools (keywords, snippets, actions, resources, MCP/HttpRewrite helpers) with prefix-sensitive scoring.
5. **Response Mapping**: The handler wraps engine output into JSON. On the client, `mapCompletionItem` converts each item into Monaco’s structure, enabling snippet insertion rules and populating the suggestion help overlay with detail/documentation.
6. **User Feedback**: Monaco renders ranked suggestions inline; `CedarEditor` mirrors the top suggestion in the contextual help panel and preserves the server-defined replacement range for consistent edits.
