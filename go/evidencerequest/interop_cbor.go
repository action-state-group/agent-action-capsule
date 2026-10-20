// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"bytes"
	"errors"
	"math"
	"sort"
	"strconv"
	"unicode/utf8"
)

// The strict CBOR decoder a verifier reads received objects with (profile
// §5.2), a port of the Python reference's interop_profile._cbor. A generic
// decoder keeps one of two duplicate keys silently, maps undefined to null
// and accepts any encoding, so this one decodes by hand and records every
// irregularity: a duplicate key (the first occurrence is kept), a head not
// in shortest form or map keys out of order (not deterministic, RFC 8949
// §4.2.1), and a float or a map key that is not text (outside the data
// model). Undefined, other simple values and indefinite lengths are no data
// item of the model at all.

// cborTag is a tagged item as the decoder keeps it.
type cborTag struct {
	Number uint64
	Value  any
}

type cborDecoded struct {
	value         any
	duplicateKeys bool
	deterministic bool
	// irregular: a float, or a map key that is not a scalar (an array, a
	// map, a tag), as the reference flags them.
	irregular bool
	// nonTextKeys: a map has an integer or byte-string key. The reference
	// keeps those and its data-model check flags them (§5.2); a COSE header
	// is made of them.
	nonTextKeys bool
}

func (d cborDecoded) wellFormed() bool { return !d.duplicateKeys && !d.irregular }

var errCBOR = errors.New("not one CBOR data item of the supported data model")

const maxCBORDepth = 64

type cborState struct {
	data          []byte
	dup, odd      bool
	nonText       bool
	deterministic bool
	// generic: maps keep every scalar key (map[any]any), integers keep
	// their values (uint64, or int64 when negative), as a COSE structure
	// needs. Otherwise a map is map[string]any whose non-text keys are
	// kept under names no text key can have (receivedKey).
	generic bool
}

// cborNegative is a negative integer, -1 - N, kept so that it can still be
// told from any other value.
type cborNegative struct{ N uint64 }

// decodeCBORItem decodes exactly one data item into the received model.
func decodeCBORItem(data []byte) (cborDecoded, error) {
	return decodeCBOR(data, false)
}

// decodeCBORGeneric decodes exactly one data item keeping every scalar map
// key and integer value, for a COSE structure.
func decodeCBORGeneric(data []byte) (cborDecoded, error) {
	return decodeCBOR(data, true)
}

func decodeCBOR(data []byte, generic bool) (cborDecoded, error) {
	st := &cborState{data: data, deterministic: true, generic: generic}
	value, end, err := st.item(0, 0)
	if err != nil {
		return cborDecoded{}, err
	}
	if end != len(data) {
		return cborDecoded{}, errCBOR
	}
	return cborDecoded{value: value, duplicateKeys: st.dup, deterministic: st.deterministic, irregular: st.odd, nonTextKeys: st.nonText}, nil
}

func (st *cborState) item(i, depth int) (any, int, error) {
	if depth > maxCBORDepth || i >= len(st.data) {
		return nil, 0, errCBOR
	}
	initial := st.data[i]
	major, info := initial>>5, initial&31
	i++
	if major == 7 && info >= 25 && info <= 27 {
		width := 1 << (info - 24)
		if i+width > len(st.data) {
			return nil, 0, errCBOR
		}
		st.odd = true // a float is outside the data model (§5.2)
		return OutsideModel{}, i + width, nil
	}
	var arg uint64
	switch {
	case info < 24:
		arg = uint64(info)
	case info <= 27:
		width := 1 << (info - 24)
		if i+width > len(st.data) {
			return nil, 0, errCBOR
		}
		for _, b := range st.data[i : i+width] {
			arg = arg<<8 | uint64(b)
		}
		i += width
		least := uint64(24)
		if width > 1 {
			least = 1 << (4 * width)
		}
		if arg < least {
			st.deterministic = false // not the shortest head
		}
	default:
		return nil, 0, errCBOR // indefinite length, or reserved
	}
	switch major {
	case 0:
		if arg > MaxSafeInteger && !st.generic {
			return OutsideModel{}, i, nil
		}
		return arg, i, nil
	case 1:
		if st.generic {
			if arg > math.MaxInt64 {
				return nil, 0, errCBOR
			}
			return -1 - int64(arg), i, nil
		}
		return cborNegative{N: arg}, i, nil
	case 2, 3:
		if arg > uint64(len(st.data)-i) {
			return nil, 0, errCBOR
		}
		chunk := st.data[i : i+int(arg)]
		if major == 2 {
			return bytes.Clone(chunk), i + int(arg), nil
		}
		if !utf8.Valid(chunk) {
			return nil, 0, errCBOR
		}
		return string(chunk), i + int(arg), nil
	case 4:
		if arg > uint64(len(st.data)) {
			return nil, 0, errCBOR
		}
		// No preallocation from the head's count: a short input claiming
		// huge arrays at every level would reserve memory it never fills.
		out := []any{}
		for range arg {
			v, next, err := st.item(i, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, v)
			i = next
		}
		return out, i, nil
	case 5:
		if arg > uint64(len(st.data)) {
			return nil, 0, errCBOR
		}
		result := map[string]any{}
		generic := map[any]any{}
		seen := map[string]bool{}
		var keys [][]byte
		for range arg {
			start := i
			key, next, err := st.item(i, depth+1)
			if err != nil {
				return nil, 0, err
			}
			keys = append(keys, st.data[start:next])
			value, after, err := st.item(next, depth+1)
			if err != nil {
				return nil, 0, err
			}
			i = after
			// A key is compared by its encoded form, so text and byte
			// keys never collide and an integer key is never confused
			// with text.
			if scalarKey(key) {
				id := cborKeyID(key, keys[len(keys)-1])
				if seen[id] {
					st.dup = true
					continue
				}
				seen[id] = true
			}
			if !scalarKey(key) {
				st.odd = true // a key that is no scalar
				continue
			}
			if st.generic {
				if b, isBytes := key.([]byte); isBytes {
					key = string(b) // hashable; a COSE header has no byte-string keys
				}
				generic[key] = value
				continue
			}
			if k, isText := key.(string); isText {
				result[k] = value
				continue
			}
			// The reference keeps an integer or byte-string key, and its
			// data-model check flags it (§5.2). It is kept here too, under
			// a name no text key can have, so a subject with such a key
			// never equals one without it.
			st.nonText = true
			result[receivedKey(key, keys[len(keys)-1])] = value
		}
		if !sort.SliceIsSorted(keys, func(a, b int) bool { return bytes.Compare(keys[a], keys[b]) < 0 }) {
			st.deterministic = false
		}
		if st.generic {
			return generic, i, nil
		}
		return result, i, nil
	case 6:
		v, next, err := st.item(i, depth+1)
		if err != nil {
			return nil, 0, err
		}
		return cborTag{Number: arg, Value: v}, next, nil
	}
	switch initial {
	case 0xf4:
		return false, i, nil
	case 0xf5:
		return true, i, nil
	case 0xf6:
		return nil, i, nil
	}
	return nil, 0, errCBOR // undefined, or another simple value
}

// cborKeyID identifies a map key for duplicate detection as the reference
// does: a key by its type and value, so two encodings of one key collide.
func cborKeyID(key any, encoded []byte) string {
	switch k := key.(type) {
	case string:
		return "t" + k
	case []byte:
		return "b" + string(k)
	case uint64:
		return "u" + strconv.FormatUint(k, 10)
	case int64:
		return "n" + strconv.FormatInt(k, 10)
	case cborNegative:
		return "n" + strconv.FormatUint(k.N, 10)
	}
	return "e" + string(encoded)
}

// receivedKey names a non-text map key in the received model: 0xff, which
// no UTF-8 text holds, then the key's identity. No text key can collide
// with it, and JCS has no form for it.
func receivedKey(key any, encoded []byte) string {
	return "\xff" + cborKeyID(key, encoded)
}

// scalarKey is a key the reference can hold in a map: an integer, a text
// or a byte string. Any other key is dropped and flagged before any
// duplicate check.
func scalarKey(key any) bool {
	switch key.(type) {
	case string, uint64, int64, []byte, OutsideModel, cborNegative:
		return true
	}
	return false
}
