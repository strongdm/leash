package autocomplete

// Position represents a 1-based cursor position.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// ReplaceRange identifies the span that should be replaced when applying a completion item.
type ReplaceRange struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// ItemKind enumerates completion item categories surfaced to clients.
type ItemKind string

const (
	KindKeyword      ItemKind = "keyword"
	KindAction       ItemKind = "action"
	KindEntityType   ItemKind = "entityType"
	KindResource     ItemKind = "resource"
	KindConditionKey ItemKind = "conditionKey"
	KindSnippet      ItemKind = "snippet"
	KindTool         ItemKind = "tool"
	KindServer       ItemKind = "server"
	KindHeader       ItemKind = "header"
)

// Item represents one completion suggestion.
type Item struct {
	Label            string    `json:"label"`
	Kind             ItemKind  `json:"kind"`
	InsertText       string    `json:"insertText"`
	Detail           string    `json:"detail,omitempty"`
	Documentation    string    `json:"documentation,omitempty"`
	SortText         string    `json:"sortText,omitempty"`
	CommitCharacters []string  `json:"commitCharacters,omitempty"`
	Data             any       `json:"data,omitempty"`
	rangeOverride    *Position // optional start position override for snippets
}

// Hints surfaces runtime-observed identifiers to enrich completions.
type Hints struct {
	Servers []string
	Tools   []string
	Hosts   []string
	Headers []string
	Files   []string
	Dirs    []string
}
