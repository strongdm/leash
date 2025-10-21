package suggest

// SuggestionKind enumerates mechanical compression opportunities.
type SuggestionKind string

const (
	// SuggestDirectory indicates multiple file policies in the same directory
	// could be rewritten using Dir::"/path" containers.
	SuggestDirectory SuggestionKind = "directory-group"

	// SuggestDomain indicates multiple network connect policies share the same
	// base domain and could be expressed as wildcard hosts.
	SuggestDomain SuggestionKind = "domain-group"

	// SuggestPort bundles policies that only differ by destination port.
	SuggestPort SuggestionKind = "port-group"

	// SuggestHTTPHost groups HTTP rewrite rules that share a host or domain.
	SuggestHTTPHost SuggestionKind = "http-host-group"

	// SuggestWorkflow summarizes frequently observed workflow patterns mined
	// from runtime event streams.
	SuggestWorkflow SuggestionKind = "workflow-cluster"
)

// PolicyReference provides lightweight metadata about an existing policy rule
// that contributed to a suggestion. These references allow the UI or an LLM
// layer to explain trade-offs to the operator.
type PolicyReference struct {
	Effect    string            // permit/forbid
	Operation string            // e.g. Action::"FileOpenReadOnly"
	Target    string            // path/host/ip/etc.
	Source    string            // runtime/file/http for context
	Metadata  map[string]string // additional facts (arguments, port, etc.)
}

// Suggestion captures a single mechanical rewrite idea. The ProposedCedar field
// uses Cedar syntax so higher-level layers (LLMs, UI workflows) can render it or
// run equivalence checks via cedar-go.
type Suggestion struct {
	Kind          SuggestionKind
	Summary       string
	ProposedCedar string
	PolicyCount   int
	Confidence    float64
	PolicyRefs    []PolicyReference
	Metadata      map[string]string
}

// Result bundles all suggestions generated from a control-plane snapshot.
type Result struct {
	Suggestions []Suggestion
}
