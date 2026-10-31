// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"errors"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

// The JSON reader a verifier reads received objects with (§5.2), matching
// the Python reference's parse_json, which is Python's json module with
// hooks:
//   - the first occurrence of a repeated member is kept, and the repeat is
//     recorded;
//   - a number that is not an unsigned integer from 0 to 2^53-1 (a
//     fraction, an exponent, a negative, NaN, Infinity, -Infinity, or too
//     large) is recorded and read as 0;
//   - an unpaired surrogate escape is kept as itself, not replaced with
//     U+FFFD: the string holds the surrogate's WTF-8 bytes, which are not
//     UTF-8, so it equals only the same escape, and JCS (and so any
//     signature over it) fails, as in the reference.
// encoding/json does not fit: it replaces an unpaired surrogate with
// U+FFFD, so a value would match one it does not equal, and it refuses
// NaN and Infinity, which the reference reads.

var errJSON = errors.New("not a JSON value")

type jsonParser struct {
	data       []byte
	i          int
	duplicates bool
	badNumber  bool
}

// parseReceivedJSON reads exactly one JSON value.
func parseReceivedJSON(data []byte) (value any, duplicates, badNumber bool, err error) {
	if !utf8.Valid(data) {
		return nil, false, false, errJSON
	}
	p := &jsonParser{data: data}
	p.space()
	if value, err = p.value(0); err != nil {
		return nil, false, false, err
	}
	p.space()
	if p.i != len(data) {
		return nil, false, false, errJSON
	}
	return value, p.duplicates, p.badNumber, nil
}

func (p *jsonParser) space() {
	for p.i < len(p.data) {
		switch p.data[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *jsonParser) literal(word string) bool {
	if len(p.data)-p.i >= len(word) && string(p.data[p.i:p.i+len(word)]) == word {
		p.i += len(word)
		return true
	}
	return false
}

// value reads one value enclosed by depth objects and arrays. An object or
// array that would nest more than canonical.MaxNestingDepth deep is not a
// value (vectors/json-nesting/).
func (p *jsonParser) value(depth int) (any, error) {
	if p.i >= len(p.data) {
		return nil, errJSON
	}
	if c := p.data[p.i]; (c == '{' || c == '[') && depth >= canonical.MaxNestingDepth {
		return nil, errJSON
	}
	switch c := p.data[p.i]; {
	case c == '{':
		p.i++
		object := map[string]any{}
		p.space()
		if p.i < len(p.data) && p.data[p.i] == '}' {
			p.i++
			return object, nil
		}
		for {
			p.space()
			if p.i >= len(p.data) || p.data[p.i] != '"' {
				return nil, errJSON
			}
			key, err := p.str()
			if err != nil {
				return nil, err
			}
			p.space()
			if p.i >= len(p.data) || p.data[p.i] != ':' {
				return nil, errJSON
			}
			p.i++
			p.space()
			item, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, repeated := object[key]; repeated {
				p.duplicates = true
			} else {
				object[key] = item
			}
			p.space()
			if p.i >= len(p.data) {
				return nil, errJSON
			}
			if p.data[p.i] == '}' {
				p.i++
				return object, nil
			}
			if p.data[p.i] != ',' {
				return nil, errJSON
			}
			p.i++
		}
	case c == '[':
		p.i++
		var array []any
		p.space()
		if p.i < len(p.data) && p.data[p.i] == ']' {
			p.i++
			return []any{}, nil
		}
		for {
			p.space()
			item, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			array = append(array, item)
			p.space()
			if p.i >= len(p.data) {
				return nil, errJSON
			}
			if p.data[p.i] == ']' {
				p.i++
				return array, nil
			}
			if p.data[p.i] != ',' {
				return nil, errJSON
			}
			p.i++
		}
	case c == '"':
		return p.str()
	case p.literal("true"):
		return true, nil
	case p.literal("false"):
		return false, nil
	case p.literal("null"):
		return nil, nil
	case p.literal("NaN"), p.literal("Infinity"), p.literal("-Infinity"):
		p.badNumber = true
		return uint64(0), nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, errJSON
}

func (p *jsonParser) number() (any, error) {
	start := p.i
	if p.data[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.data) && p.data[p.i] >= '0' && p.data[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	intStart := p.i
	if n := digits(); n == 0 || (n > 1 && p.data[intStart] == '0') {
		return nil, errJSON
	}
	integer := true
	if p.i < len(p.data) && p.data[p.i] == '.' {
		p.i++
		integer = false
		if digits() == 0 {
			return nil, errJSON
		}
	}
	if p.i < len(p.data) && (p.data[p.i] == 'e' || p.data[p.i] == 'E') {
		p.i++
		integer = false
		if p.i < len(p.data) && (p.data[p.i] == '+' || p.data[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return nil, errJSON
		}
	}
	if n, ok := UintValue(JSONNumber(p.data[start:p.i])); integer && ok {
		return n, nil
	}
	p.badNumber = true
	return uint64(0), nil
}

func (p *jsonParser) str() (string, error) {
	p.i++ // the opening quote
	var out []byte
	for p.i < len(p.data) {
		c := p.data[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), nil
		case c < 0x20:
			return "", errJSON // a control character must be escaped
		case c != '\\':
			out = append(out, c)
			p.i++
			continue
		}
		p.i++
		if p.i >= len(p.data) {
			return "", errJSON
		}
		e := p.data[p.i]
		p.i++
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := p.hex4()
			if !ok {
				return "", errJSON
			}
			if utf16.IsSurrogate(r) && r < 0xdc00 && p.i+6 <= len(p.data) && p.data[p.i] == '\\' && p.data[p.i+1] == 'u' {
				save := p.i
				p.i += 2
				if low, ok := p.hex4(); ok && low >= 0xdc00 && low <= 0xdfff {
					out = utf8.AppendRune(out, utf16.DecodeRune(r, low))
					continue
				}
				p.i = save
			}
			out = appendWTF8(out, r)
		default:
			return "", errJSON
		}
	}
	return "", errJSON
}

func (p *jsonParser) hex4() (rune, bool) {
	if p.i+4 > len(p.data) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(p.data[p.i:p.i+4]), 16, 16)
	if err != nil {
		return 0, false
	}
	p.i += 4
	return rune(n), true
}

// appendWTF8 appends a code point, encoding a lone surrogate as its three
// generalized UTF-8 bytes (which UTF-8 forbids), so it survives as itself.
func appendWTF8(out []byte, r rune) []byte {
	if utf16.IsSurrogate(r) {
		return append(out, byte(0xe0|r>>12), byte(0x80|(r>>6)&0x3f), byte(0x80|r&0x3f))
	}
	return utf8.AppendRune(out, r)
}

// hasInvalidText reports a text string that is not UTF-8: a lone
// surrogate kept by parseReceivedJSON. JCS has no form for it.
func hasInvalidText(v any) bool {
	switch x := v.(type) {
	case string:
		return !utf8.ValidString(x)
	case []any:
		for _, item := range x {
			if hasInvalidText(item) {
				return true
			}
		}
	case map[string]any:
		for k, item := range x {
			if !utf8.ValidString(k) || hasInvalidText(item) {
				return true
			}
		}
	}
	return false
}
