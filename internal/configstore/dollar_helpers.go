package configstore

import (
	"bytes"
	"errors"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Regarding $Dollar$ handling in Leash config.toml:
//
// - go-toml rejects the non-standard escape sequence `\$` that users expect to
//   keep a literal dollar in double-quoted strings. When decodeConfig observes a
//   decode error referencing the invalid U+0024 escape, sanitizeDollarEscapes
//   rewrites the raw config bytes inside quoted TOML strings so the parser sees
//   `\\$` instead.
//
// - After decoding, expandConfigValue expands environment variables in secret
//   values while leaving escaped dollars untouched, preserving intentional
//   literals such as `$FOO`.

const (
	parseStateNormal = iota
	parseStateBasic
	parseStateBasicMultiline
	parseStateLiteral
	parseStateLiteralMultiline
)

func needsDollarEscapeFix(err error) bool {
	var decodeErr *toml.DecodeError
	if !errors.As(err, &decodeErr) {
		return false
	}
	return strings.Contains(decodeErr.Error(), "invalid escaped character U+0024 '$'")
}

func sanitizeDollarEscapes(data []byte) ([]byte, bool) {
	if !bytes.Contains(data, []byte(`\$`)) {
		return data, false
	}

	var out bytes.Buffer
	out.Grow(len(data) + 16)
	state := parseStateNormal
	modified := false

	for i := 0; i < len(data); i++ {
		ch := data[i]
		switch state {
		case parseStateNormal:
			switch ch {
			case '"':
				if i+2 < len(data) && data[i+1] == '"' && data[i+2] == '"' {
					out.WriteByte('"')
					out.WriteByte('"')
					out.WriteByte('"')
					i += 2
					state = parseStateBasicMultiline
				} else {
					out.WriteByte('"')
					state = parseStateBasic
				}
			case '\'':
				if i+2 < len(data) && data[i+1] == '\'' && data[i+2] == '\'' {
					out.WriteByte('\'')
					out.WriteByte('\'')
					out.WriteByte('\'')
					i += 2
					state = parseStateLiteralMultiline
				} else {
					out.WriteByte('\'')
					state = parseStateLiteral
				}
			default:
				out.WriteByte(ch)
			}
		case parseStateLiteral:
			out.WriteByte(ch)
			if ch == '\'' {
				state = parseStateNormal
			}
		case parseStateLiteralMultiline:
			out.WriteByte(ch)
			if ch == '\'' && i+2 < len(data) && data[i+1] == '\'' && data[i+2] == '\'' {
				out.WriteByte('\'')
				out.WriteByte('\'')
				i += 2
				state = parseStateNormal
			}
		case parseStateBasic:
			if ch == '\\' && i+1 < len(data) {
				next := data[i+1]
				out.WriteByte('\\')
				if next == '$' {
					out.WriteByte('\\')
					modified = true
				}
				i++
				out.WriteByte(next)
				continue
			}
			out.WriteByte(ch)
			if ch == '"' {
				backslashCount := 0
				for j := i - 1; j >= 0 && data[j] == '\\'; j-- {
					backslashCount++
				}
				if backslashCount%2 == 0 {
					state = parseStateNormal
				}
			}
		case parseStateBasicMultiline:
			if ch == '\\' && i+1 < len(data) {
				next := data[i+1]
				out.WriteByte('\\')
				if next == '$' {
					out.WriteByte('\\')
					modified = true
				}
				i++
				out.WriteByte(next)
				continue
			}
			if ch == '"' && i+2 < len(data) && data[i+1] == '"' && data[i+2] == '"' {
				out.WriteByte('"')
				out.WriteByte('"')
				i += 2
				state = parseStateNormal
				continue
			}
			out.WriteByte(ch)
		}
	}

	if !modified {
		return data, false
	}

	return out.Bytes(), true
}

const escapedDollarPlaceholder = "\x00LEASH_ESCAPED_DOLLAR\x00"

func expandConfigValue(raw string) string {
	if raw == "" {
		return ""
	}
	protected := protectEscapedDollar(raw)
	expanded := os.Expand(protected, os.Getenv)
	return restoreEscapedDollar(expanded)
}

func protectEscapedDollar(s string) string {
	if !strings.Contains(s, `\$`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '$' {
			b.WriteString(escapedDollarPlaceholder)
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func restoreEscapedDollar(s string) string {
	if !strings.Contains(s, escapedDollarPlaceholder) {
		return s
	}
	return strings.ReplaceAll(s, escapedDollarPlaceholder, "$")
}
