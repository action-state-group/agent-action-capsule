// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/fxamacker/cbor/v2"
)

// ErrInvalid reports input that violates a request, reply or proof shape.
var ErrInvalid = errors.New("evidencerequest: invalid")

// The two encodings a request and its reply travel in (profile §4, §11.4.1
// rule 7). Media types are compared as exact strings.
const (
	MediaTypeJSON = "application/json"
	MediaTypeCBOR = "application/cbor"
)

// Message is octets as carried, with the media type they were carried under.
// A request digest is always over Octets exactly as received.
type Message struct {
	Octets    []byte
	MediaType string
}

// Digest is the SHA-256 of data as 64 lowercase hex characters: the form of
// every digest the draft names (ERV A2). The request digest is Digest of the
// request octets as received, never of a re-encoding (ER §4.2 item 1).
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// IsDigest reports whether s is a digest in the form Digest returns.
func IsDigest(s string) bool { return hex64.MatchString(s) }

// maxNesting bounds how deep a received JSON or CBOR value may nest. No
// object the profile defines nests deeper than a handful of levels.
const maxNesting = 32

// errNotWellFormed marks a received map that is not well formed (§5.2): a
// duplicate member, trailing bytes, invalid UTF-8, or a value outside the
// data model.
var errNotWellFormed = errors.New("not well formed")

// JSONNumber is a JSON number token as received. Whether it is a value the
// profile allows (an unsigned integer up to 2^53-1) is decided where a
// defined member is read; an unknown member may hold any number.
type JSONNumber string

// OutsideModel is a received item the profile's data model has no place for
// (a negative or out-of-range integer, a float, a tag, a non-text map key).
// It is kept, not rejected, so an unknown member holding one is ignored.
type OutsideModel struct{}

// MaxSafeInteger is 2^53-1, the largest integer every JCS implementation
// represents exactly (§5.2).
const MaxSafeInteger = 1<<53 - 1

var unsignedText = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)

// UintValue reads a decoded value as an unsigned integer in [0, 2^53-1].
func UintValue(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, n <= MaxSafeInteger
	case JSONNumber:
		if !unsignedText.MatchString(string(n)) {
			return 0, false
		}
		parsed, err := strconv.ParseUint(string(n), 10, 64)
		return parsed, err == nil && parsed <= MaxSafeInteger
	}
	return 0, false
}

// Decode decodes a received object in the encoding its media type names.
// Duplicate members, trailing bytes and invalid UTF-8 are errors. The result
// is the profile's data model: map[string]any, []any, string, bool, nil,
// uint64 (CBOR), JSONNumber (JSON), []byte (CBOR) and OutsideModel.
func Decode(m Message) (any, error) {
	switch m.MediaType {
	case MediaTypeJSON:
		return DecodeJSON(m.Octets)
	case MediaTypeCBOR:
		return DecodeCBOR(m.Octets)
	}
	return nil, fmt.Errorf("%w: media type %q is neither %s nor %s", ErrInvalid, m.MediaType, MediaTypeJSON, MediaTypeCBOR)
}

// DecodeJSON decodes one JSON value. Unlike encoding/json it refuses a
// duplicate member (§5.2), matches member names exactly (no case folding),
// and keeps numbers as their token text (JSONNumber).
func DecodeJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: invalid UTF-8", errNotWellFormed)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after the JSON value", errNotWellFormed)
	}
	return value, nil
}

func readJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxNesting {
		return nil, fmt.Errorf("%w: nested too deeply", errNotWellFormed)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNotWellFormed, err)
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, fmt.Errorf("%w: %v", errNotWellFormed, err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("%w: member name is not a string", errNotWellFormed)
				}
				if _, duplicate := object[key]; duplicate {
					return nil, fmt.Errorf("%w: duplicate member %q", errNotWellFormed, key)
				}
				if object[key], err = readJSONValue(decoder, depth+1); err != nil {
					return nil, err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return nil, fmt.Errorf("%w: %v", errNotWellFormed, err)
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				item, err := readJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, fmt.Errorf("%w: %v", errNotWellFormed, err)
			}
			return array, nil
		}
		return nil, fmt.Errorf("%w: unexpected %v", errNotWellFormed, t)
	case json.Number:
		return JSONNumber(t), nil
	case string, bool, nil:
		return t, nil
	}
	return nil, fmt.Errorf("%w: unexpected token %v", errNotWellFormed, token)
}

var strictCBOR = func() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:   maxNesting,
		UTF8:              cbor.UTF8RejectInvalid,
		IndefLength:       cbor.IndefLengthAllowed,
		TagsMd:            cbor.TagsAllowed,
		IntDec:            cbor.IntDecConvertNone,
		ExtraReturnErrors: cbor.ExtraDecErrorNone,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// DecodeCBOR decodes one CBOR data item into the profile's data model. It
// need not be deterministic: a request digest is over the octets as
// received, never over a re-encoding (ERV digest.json).
func DecodeCBOR(data []byte) (any, error) {
	var raw any
	if err := strictCBOR.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", errNotWellFormed, err)
	}
	return fromCBOR(raw), nil
}

func fromCBOR(v any) any {
	switch x := v.(type) {
	case nil, bool, string, []byte:
		return x
	case uint64:
		if x > MaxSafeInteger {
			return OutsideModel{}
		}
		return x
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = fromCBOR(item)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for key, item := range x {
			name, ok := key.(string)
			if !ok {
				return OutsideModel{}
			}
			out[name] = fromCBOR(item)
		}
		return out
	}
	return OutsideModel{}
}

// EncodeJCS serializes a profile value (map[string]any, []any, string,
// bool, uint64, JSONNumber, []byte as base64url without padding, nil) as
// UTF-8 of RFC 8785 JCS.
func EncodeJCS(v any) ([]byte, error) {
	converted, err := jsonModel(v)
	if err != nil {
		return nil, err
	}
	return canonical.JCS(converted)
}

func jsonModel(v any) (any, error) {
	switch x := v.(type) {
	case nil, bool, string:
		return x, nil
	case uint64:
		if x > MaxSafeInteger {
			return nil, fmt.Errorf("%w: integer %d is above 2^53-1", ErrInvalid, x)
		}
		return json.Number(strconv.FormatUint(x, 10)), nil
	case JSONNumber:
		return json.Number(x), nil
	case []byte:
		return base64.RawURLEncoding.EncodeToString(x), nil
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			converted, err := jsonModel(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, item := range x {
			converted, err := jsonModel(item)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: %T has no place in the profile's data model", ErrInvalid, v)
}

var deterministicCBOR = func() cbor.EncMode {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// EncodeCBOR serializes a profile value as deterministic CBOR (RFC 8949
// §4.2.1); []byte is a byte string.
func EncodeCBOR(v any) ([]byte, error) {
	if err := cborModel(v); err != nil {
		return nil, err
	}
	return deterministicCBOR.Marshal(v)
}

func cborModel(v any) error {
	switch x := v.(type) {
	case nil, bool, string, []byte:
		return nil
	case uint64:
		if x > MaxSafeInteger {
			return fmt.Errorf("%w: integer %d is above 2^53-1", ErrInvalid, x)
		}
		return nil
	case []any:
		for _, item := range x {
			if err := cborModel(item); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for _, item := range x {
			if err := cborModel(item); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%w: %T has no place in the profile's data model", ErrInvalid, v)
}

// Encode serializes v in the encoding mediaType names: JCS for JSON,
// deterministic CBOR for CBOR.
func Encode(mediaType string, v any) ([]byte, error) {
	switch mediaType {
	case MediaTypeJSON:
		return EncodeJCS(v)
	case MediaTypeCBOR:
		return EncodeCBOR(v)
	}
	return nil, fmt.Errorf("%w: media type %q", ErrInvalid, mediaType)
}

// OpaqueBytes reads an opaque byte value: a byte string in CBOR, base64url
// without padding in JSON (§4).
func OpaqueBytes(v any, mediaType string) ([]byte, bool) {
	switch x := v.(type) {
	case []byte:
		return x, mediaType == MediaTypeCBOR
	case string:
		if mediaType != MediaTypeJSON {
			return nil, false
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(x)
		return decoded, err == nil
	}
	return nil, false
}

// ProfileTimeLayout is the §5.2 time form: RFC 3339 UTC, seconds precision.
const ProfileTimeLayout = "2006-01-02T15:04:05Z"

// ProfileTime formats t in the §5.2 form, dropping any fraction.
func ProfileTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(ProfileTimeLayout)
}

var profileTimeForm = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// ParseProfileTime reads a time in exactly the §5.2 form.
func ParseProfileTime(s string) (time.Time, bool) {
	if !profileTimeForm.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(ProfileTimeLayout, s)
	return t, err == nil
}

var rfc3339UTC = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$`)

// ParseRequestTime reads a time a request carries (deadline, min_freshness):
// an RFC 3339 UTC time (ERV A3, A5). The §5.2 seconds form is what a
// requester following the profile sends; a fraction from a requester
// following the request draft alone is accepted.
func ParseRequestTime(s string) (time.Time, bool) {
	if !rfc3339UTC.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}
