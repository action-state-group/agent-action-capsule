// SPDX-License-Identifier: BSD-3-Clause

// Package ecmaregexp compiles JSON Schema patterns for
// santhosh-tekuri/jsonschema with ECMA-262's meaning, the dialect the Python
// reference's checkers apply.
package ecmaregexp

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ecmaWhitespace is ECMA-262's \s (WhiteSpace and LineTerminator) as the
// body of an RE2 character class.
const ecmaWhitespace = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// Compile compiles a schema pattern with RE2, reading \s and \S as
// ECMA-262 does (JSON Schema's regular-expression dialect): Unicode
// whitespace, where RE2's \s is ASCII only. RE2's ^ and $ already match only
// at the ends of the text, as ECMA-262's do without the m flag. The schema's
// patterns use no other construct whose meaning differs between the two.
func Compile(pattern string) (jsonschema.Regexp, error) {
	var out strings.Builder
	inClass := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\\' && i+1 < len(pattern):
			next := pattern[i+1]
			i++
			switch {
			case next == 's' && inClass:
				out.WriteString(ecmaWhitespace)
			case next == 's':
				out.WriteString("[" + ecmaWhitespace + "]")
			case next == 'S' && !inClass:
				out.WriteString("[^" + ecmaWhitespace + "]")
			case next == 'S':
				return nil, fmt.Errorf("pattern %q: \\S inside a character class is not supported", pattern)
			default:
				out.WriteByte(c)
				out.WriteByte(next)
			}
			continue
		case c == '[' && !inClass:
			inClass = true
		case c == ']' && inClass:
			inClass = false
		}
		out.WriteByte(c)
	}
	return regexp.Compile(out.String())
}
