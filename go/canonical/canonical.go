// SPDX-License-Identifier: BSD-3-Clause
// Canonicalization and JSON-DIGEST (draft-mih-scitt-agent-action-capsule, §2, §5.1).
//
// Current JSON-DIGEST := HEX(SHA-256(JCS(v))) using plain RFC 8785 JCS.
// Absent-field normalization remains only for vintage Capsule-ID verification.
//
// The profile forbids JSON floating-point numbers in any digest-bearing field (§5.1);
// a float reaching the serializer is a producer error and is rejected.
// Integers outside the ±(2^53−1) JS-safe range are also rejected (digest-reproducibility
// hazard across ECMAScript-Number-based readers).
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

// MaxSafeInteger is IEEE-754 double Number.MAX_SAFE_INTEGER = 2^53 − 1.
const MaxSafeInteger = int64(1<<53 - 1) // 9007199254740991

// CanonicalizationJCS selects plain RFC 8785 JCS for new Capsule IDs.
const CanonicalizationJCS = "jcs"

// ChainLinkageFields are excluded by the vintage absent-field jcs-n identity
// construction. Declared jcs Capsules exclude only capsule_id and commit chain.
var ChainLinkageFields = map[string]bool{
	"capsule_id": true,
	"chain":      true,
}

// FloatError is returned when a JSON float appears in a digest-bearing field.
type FloatError struct{ Path string }

func (e *FloatError) Error() string {
	return fmt.Sprintf("float at %s: §5.1 forbids floating-point values in digest-bearing fields", e.Path)
}

// UnsafeIntError is returned when an integer exceeds ±MaxSafeInteger.
type UnsafeIntError struct{ Path string }

func (e *UnsafeIntError) Error() string {
	return fmt.Sprintf("unsafe integer at %s: outside ±%d (§5.1)", e.Path, MaxSafeInteger)
}

// IsFloat returns true if the json.Number represents a floating-point value.
func IsFloat(n json.Number) bool {
	s := n.String()
	for _, c := range s {
		if c == '.' || c == 'e' || c == 'E' {
			return true
		}
	}
	return false
}

// IsUnsafeInt returns true if the integer's magnitude exceeds MaxSafeInteger.
// Pre-condition: !IsFloat(n).
func IsUnsafeInt(n json.Number) bool {
	s := n.String()
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	// 9007199254740991 is 16 digits; anything longer is definitely unsafe.
	if len(s) > 16 {
		return true
	}
	if len(s) < 16 {
		return false
	}
	// Equal-length decimal strings have the same numeric ordering as lexicographic.
	return s > "9007199254740991"
}

// Normalize applies absent-field normalization bottom-up (§2):
// remove members whose value is null, an empty array, or an empty object.
// Arrays are normalized element-wise but null elements within arrays are kept
// (only dict members are pruned).
func Normalize(v interface{}) interface{} {
	switch tv := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{})
		for k, val := range tv {
			nv := Normalize(val)
			if nv == nil {
				continue
			}
			switch nval := nv.(type) {
			case map[string]interface{}:
				if len(nval) == 0 {
					continue
				}
			case []interface{}:
				if len(nval) == 0 {
					continue
				}
			}
			out[k] = nv
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(tv))
		for i, x := range tv {
			out[i] = Normalize(x)
		}
		return out
	default:
		return v
	}
}

// utf16Units encodes a Go string to UTF-16 code units (for JCS key sorting).
func utf16Units(s string) []uint16 {
	return utf16.Encode([]rune(s))
}

// compareUTF16 implements the RFC 8785 §3.2.3 key-ordering comparison:
// object members sorted by the UTF-16 code-unit sequence of the member name.
func compareUTF16(a, b string) bool {
	au := utf16Units(a)
	bu := utf16Units(b)
	for i := 0; i < len(au) && i < len(bu); i++ {
		if au[i] != bu[i] {
			return au[i] < bu[i]
		}
	}
	return len(au) < len(bu)
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return compareUTF16(keys[i], keys[j])
	})
	return keys
}

// jcsString produces the RFC 8785 §3.2.2.2 string encoding.
func jcsString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, ch := range s {
		switch ch {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if ch < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, ch)
			} else {
				b.WriteRune(ch)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func jcsValue(v interface{}) (string, error) {
	if v == nil {
		return "null", nil
	}
	switch tv := v.(type) {
	case bool:
		if tv {
			return "true", nil
		}
		return "false", nil
	case string:
		return jcsString(tv), nil
	case json.Number:
		if IsFloat(tv) {
			return "", &FloatError{Path: ""}
		}
		if IsUnsafeInt(tv) {
			return "", &UnsafeIntError{Path: ""}
		}
		return tv.String(), nil
	case []interface{}:
		parts := make([]string, len(tv))
		for i, x := range tv {
			s, err := jcsValue(x)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]interface{}:
		keys := sortedKeys(tv)
		parts := make([]string, len(keys))
		for i, k := range keys {
			vs, err := jcsValue(tv[k])
			if err != nil {
				return "", err
			}
			parts[i] = jcsString(k) + ":" + vs
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		return "", fmt.Errorf("unsupported type %T in JCS serialization", v)
	}
}

// JCS returns the RFC 8785 JCS serialization of v as UTF-8 bytes (no normalization).
func JCS(v interface{}) ([]byte, error) {
	s, err := jcsValue(v)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// JSONDigest computes the current JSON-DIGEST (§2): lowercase-hex SHA-256 of
// plain RFC 8785 JCS. Absent-field normalization is reserved for vintage
// Capsule-ID verification and is not used for newly produced digests.
func JSONDigest(v interface{}) (string, error) {
	return digestJCS(v)
}

func digestJCS(v interface{}) (string, error) {
	b, err := JCS(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// ComputeCapsuleID recomputes capsule_id using the Capsule's declared
// canonicalization algorithm.
//
// A record without canonicalization_id uses the vintage jcs-n construction:
// remove capsule_id and chain, normalize absent fields, then apply JCS. This
// compatibility path is selected only by the field's absence.
//
// A record declaring jcs removes only capsule_id, then applies plain RFC 8785
// JCS. The declaration and chain therefore participate in the Capsule ID.
// Unknown, null, and non-string declarations fail closed.
func ComputeCapsuleID(capsule map[string]interface{}) (string, error) {
	declared, present := capsule["canonicalization_id"]
	if !present {
		return computeVintageCapsuleID(capsule)
	}

	algorithm, ok := declared.(string)
	if !ok {
		return "", fmt.Errorf("canonicalization_id must be a string")
	}
	if algorithm != CanonicalizationJCS {
		return "", fmt.Errorf("unsupported canonicalization_id %q", algorithm)
	}
	return computeJCSCapsuleID(capsule)
}

func computeVintageCapsuleID(capsule map[string]interface{}) (string, error) {
	canonical := make(map[string]interface{})
	for k, v := range capsule {
		if !ChainLinkageFields[k] {
			canonical[k] = v
		}
	}
	return digestJCS(Normalize(canonical))
}

func computeJCSCapsuleID(capsule map[string]interface{}) (string, error) {
	canonical := make(map[string]interface{})
	for k, v := range capsule {
		if k == "capsule_id" {
			continue
		}
		canonical[k] = v
	}
	return digestJCS(canonical)
}
