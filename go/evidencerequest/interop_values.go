// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// The five property statuses (profile §7.1).
const (
	StatusPass         = "PASS"
	StatusFail         = "FAIL"
	StatusNotPresent   = "NOT_PRESENT"
	StatusNotChecked   = "NOT_CHECKED"
	StatusInconclusive = "INCONCLUSIVE"
)

// CLLKinds are the three verification material kinds this revision
// registers (profile §6.2.1).
var CLLKinds = []string{KindCLLCheckpoint, KindCLLInclusionProof, KindCLLConsistencyProof}

// PropertyReport is one checked property: its name, its §7.1 status, the
// method used and an optional detail (profile §7.1).
type PropertyReport struct {
	Property string
	Status   string
	Method   string
	Detail   string
}

// receivedValue is a received reply or record read the way a verifier must
// read it: the first occurrence of a duplicated member is kept, and the map
// is still classified by its members, but it is not well formed (§5.2).
type receivedValue struct {
	value      any
	wellFormed bool
	why        string
}

// decodeReceived reads octets as a verifier reads a reply or record: JSON
// with duplicate members and numbers outside 0 to 2^53-1 recorded, not
// refused; CBOR with duplicate keys and values outside the data model
// recorded. ok is false when the octets are no value at all in that
// encoding. In-domain JSON numbers decode as uint64, like CBOR integers, so
// values from either encoding compare by value.
func decodeReceived(m Message) (receivedValue, bool, string) {
	switch m.MediaType {
	case MediaTypeJSON:
		return decodeReceivedJSON(m.Octets)
	case MediaTypeCBOR:
		return decodeReceivedCBOR(m.Octets)
	}
	return receivedValue{}, false, fmt.Sprintf("unknown media type %q", m.MediaType)
}

func decodeReceivedJSON(data []byte) (receivedValue, bool, string) {
	value, duplicates, badNumber, err := parseReceivedJSON(data)
	if err != nil {
		return receivedValue{}, false, "not a JSON object"
	}
	out := receivedValue{value: value, wellFormed: !duplicates && !badNumber}
	switch {
	case duplicates:
		out.why = "duplicate member"
	case badNumber:
		out.why = "a number outside 0 to 2^53 - 1"
	}
	return out, true, ""
}

// maxReceivedNesting bounds how deep a received value may nest before it is
// treated as no value; no object the profile defines nests near it.
const maxReceivedNesting = 512

func decodeReceivedCBOR(data []byte) (receivedValue, bool, string) {
	d, err := decodeCBORItem(data)
	if err != nil {
		return receivedValue{}, false, "not a CBOR data item"
	}
	if _, isMap := d.value.(map[string]any); !isMap {
		return receivedValue{}, false, "not a CBOR map"
	}
	// Classified by its members whatever else is wrong with it (§1). The
	// signature is over JCS whatever the frame (§5.1), so a frame that is
	// not deterministic CBOR is not, by itself, a reason to fail it.
	inDomain := !d.nonTextKeys && numbersInDomain(d.value)
	out := receivedValue{value: d.value, wellFormed: !d.duplicateKeys && !d.irregular && inDomain}
	switch {
	case d.duplicateKeys:
		out.why = "duplicate map key"
	case !out.wellFormed:
		out.why = "a value outside the §5.2 data model (a float, a non-text key, or a number out of range)"
	}
	return out, true, ""
}

func numbersInDomain(v any) bool {
	switch x := v.(type) {
	case OutsideModel, cborNegative:
		return false
	case cborTag:
		return numbersInDomain(x.Value)
	case []any:
		for _, item := range x {
			if !numbersInDomain(item) {
				return false
			}
		}
	case map[string]any:
		for _, item := range x {
			if !numbersInDomain(item) {
				return false
			}
		}
	}
	return true
}

// jcsOrNil is UTF-8 of JCS of v, or nil when JCS cannot represent it: a
// byte string, a value outside the data model.
func jcsOrNil(v any) []byte {
	if hasBytes(v) || hasInvalidText(v) {
		return nil
	}
	out, err := EncodeJCS(v)
	if err != nil {
		return nil
	}
	return out
}

func hasBytes(v any) bool {
	switch x := v.(type) {
	case []byte:
		return true
	case []any:
		for _, item := range x {
			if hasBytes(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range x {
			if hasBytes(item) {
				return true
			}
		}
	}
	return false
}

var b64urlText = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// opaqueReceived reads opaque bytes as a verifier receives them: a byte
// string in CBOR, base64url without padding in JSON (§4).
func opaqueReceived(v any, mediaType string) ([]byte, bool) {
	if mediaType == MediaTypeCBOR {
		b, ok := v.([]byte)
		return b, ok
	}
	text, ok := v.(string)
	if !ok || !b64urlText.MatchString(text) || len(text)%4 == 1 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(text)
	return decoded, err == nil
}

var (
	profileTimeText = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)
	rfc3339Text     = regexp.MustCompile(`^(\d{4})-(\d\d)-(\d\d)[Tt](\d\d):(\d\d):(\d\d)(\.\d+)?([Zz]|[+-]\d\d:\d\d)$`)
)

// isProfileTime reports the §5.2 time form, YYYY-MM-DDTHH:MM:SSZ, naming a
// real calendar instant.
func isProfileTime(v any) bool {
	s, ok := v.(string)
	if !ok || !profileTimeText.MatchString(s) {
		return false
	}
	_, ok = parseInstant(s)
	return ok
}

// parseInstant reads any RFC 3339 date-time as a UTC instant. A leap second
// names the instant after second 59.
func parseInstant(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	m := rfc3339Text.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, false
	}
	n := make([]int, 7)
	for k := 1; k <= 6; k++ {
		n[k], _ = strconv.Atoi(m[k])
	}
	second := n[6]
	if second > 60 || n[2] < 1 || n[2] > 12 || n[3] < 1 || n[4] > 23 || n[5] > 59 {
		return time.Time{}, false
	}
	base := time.Date(n[1], time.Month(n[2]), n[3], n[4], n[5], min(second, 59), 0, time.UTC)
	if base.Day() != n[3] || base.Year() < 1 {
		return time.Time{}, false
	}
	if second == 60 {
		base = base.Add(time.Second)
	}
	if frac := m[7]; frac != "" {
		digits := (frac[1:] + "000000")[:6]
		micros, _ := strconv.Atoi(digits)
		base = base.Add(time.Duration(micros) * time.Microsecond)
	}
	if offset := m[8]; offset != "Z" && offset != "z" {
		hours, _ := strconv.Atoi(offset[1:3])
		minutes, _ := strconv.Atoi(offset[4:6])
		shift := time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute
		if offset[0] == '+' {
			shift = -shift
		}
		base = base.Add(shift)
	}
	return base, true
}

func isText(v any) bool {
	_, ok := v.(string)
	return ok
}

func isDigestValue(v any) bool {
	s, ok := v.(string)
	return ok && IsDigest(s)
}

var hex128 = regexp.MustCompile(`^[0-9a-f]{128}$`)

// verifyHexSignature is an Ed25519 check over message for the §5.2 hex
// forms of a key and a signature; false when either form is wrong.
func verifyHexSignature(key, sig any, message []byte) bool {
	keyHex, ok1 := key.(string)
	sigHex, ok2 := sig.(string)
	if !ok1 || !ok2 || !IsDigest(keyHex) || !hex128.MatchString(sigHex) {
		return false
	}
	signature, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return VerifySignature(keyHex, message, signature) == nil
}

func uintMember(v any) (uint64, bool) {
	n, ok := v.(uint64)
	return n, ok && n <= MaxSafeInteger
}
