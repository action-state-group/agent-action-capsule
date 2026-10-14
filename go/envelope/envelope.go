// SPDX-License-Identifier: BSD-3-Clause
// Package envelope verifies AAC producer envelopes over signer-independent
// Capsule IDs. Signer authorization is intentionally outside this package.
package envelope

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"unicode/utf8"
)

const (
	// ContentType is the media type of the producer envelope's raw 32-byte payload.
	ContentType = "application/agent-action-capsule-id"
	// COSEAlgorithmEdDSA is the COSE algorithm code point for EdDSA.
	COSEAlgorithmEdDSA = int64(-8)

	maxEnvelopeBytes = 4096
	// Decoder bounds. A conforming envelope nests two levels deep and its
	// largest container has four elements, so these only cap the work spent
	// on input that is invalid anyway.
	maxNestedLevels  = 8
	maxArrayElements = 16
	maxMapPairs      = 16
)

var capsuleIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Finding is one structured producer-envelope verification failure.
type Finding struct {
	Code   string
	Detail string
}

// VerificationResult is the never-panicking result of Verify.
type VerificationResult struct {
	OK        bool
	Findings  []Finding
	CapsuleID string
	PublicKey []byte
}

// Verify authenticates one producer envelope against a carried lowercase-hex
// Capsule ID. It checks the exact AAC wire profile, including its CBOR encoding
// rules, and verifies the Ed25519 signature under the raw public key carried in
// the protected kid header.
// Authorization of that key for an operator or developer is a separate policy.
func Verify(capsuleID string, data []byte) VerificationResult {
	result := VerificationResult{CapsuleID: capsuleID}
	payload, err := decodeCapsuleID(capsuleID)
	if err != nil {
		return failed(result, "capsule_id_malformed", err.Error())
	}
	if len(data) > maxEnvelopeBytes {
		return failed(result, "envelope_too_large", fmt.Sprintf("producer envelope is %d bytes; maximum is %d", len(data), maxEnvelopeBytes))
	}

	protected, carriedPayload, signature, err := decodeEnvelope(data)
	if err != nil {
		return failed(result, "envelope_malformed", err.Error())
	}

	if !protected.get(1).isInt(COSEAlgorithmEdDSA) {
		return failed(result, "envelope_algorithm_mismatch", "protected alg (label 1) MUST be EdDSA (-8)")
	}
	if protected.get(3).kind != kindText || string(protected.get(3).bytes) != ContentType {
		return failed(result, "envelope_content_type_mismatch", fmt.Sprintf("protected content type (label 3) MUST be %q", ContentType))
	}
	publicKey := protected.get(4).bytes
	if protected.get(4).kind != kindBytes || len(publicKey) != ed25519.PublicKeySize {
		return failed(result, "envelope_kid_invalid", "protected kid (label 4) MUST be the raw 32-byte Ed25519 public key")
	}
	if len(protected.pairs) != 3 {
		return failed(result, "envelope_protected_headers_invalid", "protected header MUST contain exactly alg, content type, and kid")
	}
	if len(carriedPayload) != len(payload) || !equalBytes(carriedPayload, payload) {
		return failed(result, "envelope_payload_mismatch", "attached payload MUST equal the raw 32-byte Capsule ID")
	}
	if len(signature) != ed25519.SignatureSize {
		return failed(result, "envelope_signature_invalid", "Ed25519 signature MUST be 64 bytes")
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKey), sigStructure(protected.raw, carriedPayload), signature) {
		return failed(result, "envelope_signature_invalid", "Ed25519 signature verification failed")
	}

	result.OK = true
	result.PublicKey = append([]byte(nil), publicKey...)
	return result
}

// item is one decoded CBOR data item, typed only as far as the profile checks
// need. Floats and simple values are never valid header values, so they
// decode to kindOther and keep only their encoded bytes, for map-key equality.
type item struct {
	kind     itemKind
	negative bool   // kindInt: the value is -1 - magnitude
	value    uint64 // kindInt: magnitude; kindTag: tag number
	bytes    []byte // kindBytes, kindText; the encoding for kindOther
	items    []item // kindArray, kindTag (one content item)
	pairs    []pair // kindMap
}

type itemKind int

const (
	kindOther itemKind = iota
	kindInt
	kindBytes
	kindText
	kindArray
	kindMap
	kindTag
)

type pair struct{ key, value item }

// isInt reports whether the item is the CBOR integer want.
func (i item) isInt(want int64) bool {
	if i.kind != kindInt {
		return false
	}
	if want < 0 {
		return i.negative && i.value == uint64(-1-want)
	}
	return !i.negative && i.value == uint64(want)
}

func (i item) equal(other item) bool {
	if i.kind != other.kind || i.negative != other.negative || i.value != other.value || !bytes.Equal(i.bytes, other.bytes) ||
		len(i.items) != len(other.items) || len(i.pairs) != len(other.pairs) {
		return false
	}
	for index := range i.items {
		if !i.items[index].equal(other.items[index]) {
			return false
		}
	}
	// Map equality ignores entry order. Keys are unique within each map, so
	// equal lengths and a match for every entry make the maps equal.
	for _, entry := range i.pairs {
		matched := false
		for _, candidate := range other.pairs {
			if entry.key.equal(candidate.key) && entry.value.equal(candidate.value) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

type protectedHeader struct {
	pairs []pair
	raw   []byte
}

// get returns the value under an integer label; the zero item when absent.
func (h protectedHeader) get(label int64) item {
	for _, entry := range h.pairs {
		if entry.key.isInt(label) {
			return entry.value
		}
	}
	return item{}
}

func decodeEnvelope(data []byte) (protectedHeader, []byte, []byte, error) {
	top, err := decodeAll(data)
	if err != nil {
		return protectedHeader{}, nil, nil, fmt.Errorf("decoding COSE_Sign1: %w", err)
	}
	if top.kind != kindTag || top.value != 18 {
		return protectedHeader{}, nil, nil, errors.New("top-level CBOR tag MUST be COSE_Sign1 tag 18")
	}
	content := top.items[0]
	if content.kind != kindArray || len(content.items) != 4 {
		return protectedHeader{}, nil, nil, errors.New("COSE_Sign1 MUST contain four array elements")
	}
	protectedItem, unprotected, payload, signature := content.items[0], content.items[1], content.items[2], content.items[3]
	if protectedItem.kind != kindBytes || len(protectedItem.bytes) == 0 {
		return protectedHeader{}, nil, nil, errors.New("protected header MUST be a non-empty byte string")
	}
	protected, err := decodeAll(protectedItem.bytes)
	if err != nil {
		return protectedHeader{}, nil, nil, fmt.Errorf("decoding protected header: %w", err)
	}
	if protected.kind != kindMap {
		return protectedHeader{}, nil, nil, errors.New("protected header MUST be a map")
	}
	for _, entry := range protected.pairs {
		if entry.key.kind != kindInt {
			return protectedHeader{}, nil, nil, errors.New("protected header labels MUST be integers")
		}
	}
	if unprotected.kind != kindMap {
		return protectedHeader{}, nil, nil, errors.New("unprotected header MUST be a map")
	}
	if len(unprotected.pairs) != 0 {
		return protectedHeader{}, nil, nil, errors.New("unprotected header MUST be an empty map")
	}
	if payload.kind != kindBytes {
		return protectedHeader{}, nil, nil, errors.New("attached payload MUST be a byte string")
	}
	if signature.kind != kindBytes {
		return protectedHeader{}, nil, nil, errors.New("signature MUST be a byte string")
	}
	return protectedHeader{pairs: protected.pairs, raw: protectedItem.bytes}, payload.bytes, signature.bytes, nil
}

// decodeAll decodes exactly one CBOR data item under the profile's encoding
// rules: definite lengths, the shortest form of every argument and float,
// unique map keys, no trailing bytes, and a tag only on the outermost item.
func decodeAll(data []byte) (item, error) {
	r := reader{data: data}
	value, err := r.item(0)
	if err != nil {
		return item{}, err
	}
	if r.offset != len(data) {
		return item{}, errors.New("trailing CBOR data")
	}
	return value, nil
}

type reader struct {
	data   []byte
	offset int
}

func (r *reader) take(n uint64) ([]byte, error) {
	if n > uint64(len(r.data)-r.offset) {
		return nil, errors.New("truncated CBOR")
	}
	value := r.data[r.offset : r.offset+int(n)]
	r.offset += int(n)
	return value, nil
}

// head reads one initial byte and its argument, rejecting any argument not in
// its shortest form. For major type 7 it validates the simple value or float
// and returns a zero argument.
func (r *reader) head() (byte, uint64, error) {
	first, err := r.take(1)
	if err != nil {
		return 0, 0, err
	}
	major, info := first[0]>>5, first[0]&31
	if info < 24 {
		return major, uint64(info), nil
	}
	if info > 27 {
		if info == 31 {
			return 0, 0, errors.New("indefinite-length CBOR is not allowed")
		}
		return 0, 0, errors.New("reserved CBOR additional information")
	}
	raw, err := r.take(1 << (info - 24))
	if err != nil {
		return 0, 0, err
	}
	var argument uint64
	for _, b := range raw {
		argument = argument<<8 | uint64(b)
	}
	if major == 7 {
		switch info {
		case 24:
			if argument < 32 {
				return 0, 0, errors.New("CBOR simple value below 32 in the two-byte form")
			}
		case 26:
			value := float64(math.Float32frombits(binary.BigEndian.Uint32(raw)))
			if math.IsNaN(value) || fitsHalf(value) {
				return 0, 0, errors.New("CBOR float is not in its shortest form")
			}
		case 27:
			value := math.Float64frombits(argument)
			if math.IsNaN(value) || float64(float32(value)) == value {
				return 0, 0, errors.New("CBOR float is not in its shortest form")
			}
		}
		return major, 0, nil
	}
	if argument < [...]uint64{24, 1 << 8, 1 << 16, 1 << 32}[info-24] {
		return 0, 0, errors.New("CBOR argument is not in its shortest form")
	}
	return major, argument, nil
}

// fitsHalf reports whether value is exactly representable as an IEEE 754
// half-precision float, so that a wider encoding of it is not the shortest.
func fitsHalf(value float64) bool {
	magnitude := math.Abs(value)
	if math.IsInf(value, 0) || magnitude == 0 {
		return true
	}
	if magnitude > 65504 {
		return false
	}
	fraction, exponent := math.Frexp(magnitude)
	if exponent >= -13 { // normal: 11 significant bits
		scaled := fraction * (1 << 11)
		return scaled == math.Trunc(scaled)
	}
	scaled := magnitude * (1 << 24) // subnormal: multiples of 2^-24
	return scaled == math.Trunc(scaled)
}

func (r *reader) item(depth int) (item, error) {
	if depth > maxNestedLevels {
		return item{}, errors.New("CBOR nesting exceeds the limit")
	}
	start := r.offset
	major, argument, err := r.head()
	if err != nil {
		return item{}, err
	}
	switch major {
	case 0, 1:
		return item{kind: kindInt, negative: major == 1, value: argument}, nil
	case 2, 3:
		value, err := r.take(argument)
		if err != nil {
			return item{}, err
		}
		if major == 3 {
			if !utf8.Valid(value) {
				return item{}, errors.New("CBOR text is not UTF-8")
			}
			return item{kind: kindText, bytes: value}, nil
		}
		return item{kind: kindBytes, bytes: value}, nil
	case 4:
		if argument > maxArrayElements {
			return item{}, errors.New("CBOR array exceeds the element limit")
		}
		items := make([]item, 0, argument)
		for range argument {
			value, err := r.item(depth + 1)
			if err != nil {
				return item{}, err
			}
			items = append(items, value)
		}
		return item{kind: kindArray, items: items}, nil
	case 5:
		if argument > maxMapPairs {
			return item{}, errors.New("CBOR map exceeds the pair limit")
		}
		pairs := make([]pair, 0, argument)
		for range argument {
			key, err := r.item(depth + 1)
			if err != nil {
				return item{}, err
			}
			for _, existing := range pairs {
				if existing.key.equal(key) {
					return item{}, errors.New("duplicate CBOR map key")
				}
			}
			value, err := r.item(depth + 1)
			if err != nil {
				return item{}, err
			}
			pairs = append(pairs, pair{key: key, value: value})
		}
		return item{kind: kindMap, pairs: pairs}, nil
	case 6:
		if depth > 0 {
			return item{}, errors.New("only the outer COSE_Sign1 may carry a CBOR tag")
		}
		content, err := r.item(depth + 1)
		if err != nil {
			return item{}, err
		}
		return item{kind: kindTag, value: argument, items: []item{content}}, nil
	}
	return item{kind: kindOther, bytes: r.data[start:r.offset]}, nil
}

// sigStructure is the RFC 9052 Sig_structure for COSE_Sign1 with an empty
// external AAD, in deterministic encoding.
func sigStructure(protected, payload []byte) []byte {
	out := []byte{0x84}
	out = appendHead(out, 3, uint64(len("Signature1")))
	out = append(out, "Signature1"...)
	out = appendHead(out, 2, uint64(len(protected)))
	out = append(out, protected...)
	out = append(out, 0x40)
	out = appendHead(out, 2, uint64(len(payload)))
	return append(out, payload...)
}

func appendHead(out []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(out, m|byte(n))
	case n <= math.MaxUint8:
		return append(out, m|24, byte(n))
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(out, m|25), uint16(n))
	case n <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(out, m|26), uint32(n))
	default:
		return binary.BigEndian.AppendUint64(append(out, m|27), n)
	}
}

func decodeCapsuleID(value string) ([]byte, error) {
	if !capsuleIDPattern.MatchString(value) {
		return nil, fmt.Errorf("capsule_id MUST be 64 lowercase hexadecimal characters")
	}
	return hex.DecodeString(value)
}

func failed(result VerificationResult, code, detail string) VerificationResult {
	result.Findings = append(result.Findings, Finding{Code: code, Detail: detail})
	return result
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}
