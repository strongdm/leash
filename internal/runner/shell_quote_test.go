package runner

import "testing"

func TestQuoteShellArg(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: "''"},                                      // empty string must survive round-trip
		{name: "plain", input: "abc123", want: "abc123"},                            // alphanumeric word remains bare
		{name: "space", input: "foo bar", want: "'foo bar'"},                        // spaces require quoting
		{name: "tab", input: "foo\tbar", want: "'foo\tbar'"},                        // tabs must not split args
		{name: "newline", input: "foo\nbar", want: "'foo\nbar'"},                    // newlines stay literal
		{name: "doubleQuote", input: `say"hi`, want: "'say\"hi'"},                   // double quote must be contained
		{name: "singleQuote", input: "O'Brien", want: "'O'\"'\"'Brien'"},            // single quote escape dance
		{name: "backslash", input: `C:\path`, want: "'C:\\path'"},                   // backslashes stay literal
		{name: "dollar", input: "cost$5", want: "'cost$5'"},                         // embedded dollar must not expand
		{name: "dollarSolo", input: "$", want: "'$'"},                               // bare dollar should not expand
		{name: "backslashDollar", input: `\$`, want: "'\\$'"},                       // escaped dollar keeps slash
		{name: "singleBackslash", input: `\`, want: "'\\'"},                         // trailing backslash preserved
		{name: "doubleBackslash", input: `\\`, want: "'\\\\'"},                      // even backslashes intact
		{name: "tripleBackslash", input: `\\\`, want: "'\\\\\\'"},                   // odd backslashes intact
		{name: "backslashSlash", input: `\/`, want: "'\\/'"},                        // harmless slash escape stays
		{name: "backtick", input: "run`cmd`", want: "'run`cmd`'"},                   // backticks must not run commands
		{name: "semicolon", input: "echo;rm", want: "'echo;rm'"},                    // semicolon must not chain
		{name: "pipe", input: "ls|cat", want: "'ls|cat'"},                           // pipe must not create pipeline
		{name: "glob", input: "*.go", want: "'*.go'"},                               // globs must not expand
		{name: "tilde", input: "~user", want: "'~user'"},                            // tilde must not expand
		{name: "carriageReturn", input: "foo\rbar", want: "'foo\rbar'"},             // carriage return stays literal
		{name: "nullByte", input: "foo\x00bar", want: "'foo\x00bar'"},               // null byte must remain
		{name: "dollarQuoteLiteral", input: "$'\\n'", want: "'$'\"'\"'\\n'\"'\"''"}, // literal $'...' must not reparse
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := quoteShellArg(tt.input); got != tt.want {
				t.Fatalf("quoteShellArg(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{name: "nil", input: nil, want: ""},                                                                                         // nil slice renders empty
		{name: "singleSimple", input: []string{"simple"}, want: "simple"},                                                           // safe word stays bare
		{name: "withSpaces", input: []string{"foo bar", "baz"}, want: "'foo bar' baz"},                                              // selective quoting applies
		{name: "mixed", input: []string{"", "O'Brien", "line\nbreak", "cost$5"}, want: "'' 'O'\"'\"'Brien' 'line\nbreak' 'cost$5'"}, // varied tokens preserved
		{name: "specialChars", input: []string{"echo;rm", "foo\rbar", "$'\\n'"}, want: "'echo;rm' 'foo\rbar' '$'\"'\"'\\n'\"'\"''"}, // metacharacters stay literal
		{name: "nullByte", input: []string{"foo\x00bar"}, want: "'foo\x00bar'"},                                                     // null byte round-trips
		{name: "backslashVariants", input: []string{`\`, `\\`, `\\\`}, want: "'\\' '\\\\' '\\\\\\'"},                                // trailing backslashes intact
		{name: "dollarVariants", input: []string{"$", `\$`}, want: "'$' '\\$'"},                                                     // dollars escape safely
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := shellQuote(tt.input); got != tt.want {
				t.Fatalf("shellQuote(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
