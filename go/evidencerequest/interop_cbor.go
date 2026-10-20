// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"bytes"
	"errors"
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
}

// decodeCBORItem decodes exactly one data item.
func decodeCBORItem(data []byte) (cborDecoded, error) {
	st := &cborState{data: data, deterministic: true}
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
		if arg > MaxSafeInteger {
			return OutsideModel{}, i, nil
		}
		return arg, i, nil
	case 1:
		return OutsideModel{}, i, nil // a negative integer
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
		out := make([]any, 0, arg)
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
			switch k := key.(type) {
			case string:
				result[k] = value
			case uint64, []byte:
				st.nonText = true // kept by the reference, outside the data model
			case OutsideModel:
				st.nonText = true // a negative or out-of-range integer key
			default:
				st.odd = true // a key that is no scalar
			}
		}
		if !sort.SliceIsSorted(keys, func(a, b int) bool { return bytes.Compare(keys[a], keys[b]) < 0 }) {
			st.deterministic = false
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
// does: a text, byte-string or unsigned key by its type and value, so two
// encodings of one key collide, and any other key by its encoding.
func cborKeyID(key any, encoded []byte) string {
	switch k := key.(type) {
	case string:
		return "t" + k
	case []byte:
		return "b" + string(k)
	case uint64:
		return "u" + strconv.FormatUint(k, 10)
	}
	return "e" + string(encoded)
}

// scalarKey is a key the reference can hold in a map: an integer, a text
// or a byte string. Any other key is dropped and flagged before any
// duplicate check.
func scalarKey(key any) bool {
	switch key.(type) {
	case string, uint64, []byte, OutsideModel:
		return true
	}
	return false
}
