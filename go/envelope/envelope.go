// SPDX-License-Identifier: BSD-3-Clause
// Package envelope verifies AAC producer envelopes over signer-independent
// Capsule IDs. Signer authorization is intentionally outside this package.
package envelope

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/fxamacker/cbor/v2"
)

const (
	// ContentType is the media type of the producer envelope's raw 32-byte payload.
	ContentType = "application/agent-action-capsule-id"
	// COSEAlgorithmEdDSA is the COSE algorithm code point for EdDSA.
	COSEAlgorithmEdDSA = int64(-8)

	maxEnvelopeBytes = 4096
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

var (
	decodeMode = mustDecodeMode()
	encodeMode = mustEncodeMode()
)

func mustDecodeMode() cbor.DecMode {
	mode, err := (cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsAllowed,
		MaxNestedLevels:  8,
		MaxArrayElements: 16,
		MaxMapPairs:      16,
	}).DecMode()
	if err != nil {
		panic(fmt.Sprintf("constructing producer-envelope CBOR decoder: %v", err))
	}
	return mode
}

func mustEncodeMode() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("constructing producer-envelope CBOR encoder: %v", err))
	}
	return mode
}

// Verify authenticates one producer envelope against a carried lowercase-hex
// Capsule ID. It checks the exact AAC wire profile and verifies the Ed25519
// signature under the raw public key carried in the protected kid header.
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

	algorithm, ok := protected.get(1).(int64)
	if !ok || algorithm != COSEAlgorithmEdDSA {
		return failed(result, "envelope_algorithm_mismatch", "protected alg (label 1) MUST be EdDSA (-8)")
	}
	contentType, ok := protected.get(3).(string)
	if !ok || contentType != ContentType {
		return failed(result, "envelope_content_type_mismatch", fmt.Sprintf("protected content type (label 3) MUST be %q", ContentType))
	}
	publicKey, ok := protected.get(4).([]byte)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return failed(result, "envelope_kid_invalid", "protected kid (label 4) MUST be the raw 32-byte Ed25519 public key")
	}
	if protected.len() != 3 {
		return failed(result, "envelope_protected_headers_invalid", "protected header MUST contain exactly alg, content type, and kid")
	}
	if len(carriedPayload) != len(payload) || !equalBytes(carriedPayload, payload) {
		return failed(result, "envelope_payload_mismatch", "attached payload MUST equal the raw 32-byte Capsule ID")
	}
	if len(signature) != ed25519.SignatureSize {
		return failed(result, "envelope_signature_invalid", "Ed25519 signature MUST be 64 bytes")
	}

	toBeSigned, err := encodeMode.Marshal([]interface{}{"Signature1", protected.raw, []byte{}, carriedPayload})
	if err != nil {
		return failed(result, "envelope_malformed", fmt.Sprintf("encoding Sig_structure: %v", err))
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), toBeSigned, signature) {
		return failed(result, "envelope_signature_invalid", "Ed25519 signature verification failed")
	}

	result.OK = true
	result.PublicKey = append([]byte(nil), publicKey...)
	return result
}

type protectedHeader struct {
	values map[int64]interface{}
	raw    []byte
}

func (h protectedHeader) len() int { return len(h.values) }

func (h protectedHeader) get(label int64) interface{} { return h.values[label] }

func decodeEnvelope(data []byte) (protectedHeader, []byte, []byte, error) {
	var tag cbor.RawTag
	if err := decodeMode.Unmarshal(data, &tag); err != nil {
		return protectedHeader{}, nil, nil, fmt.Errorf("decoding COSE_Sign1: %w", err)
	}
	if tag.Number != 18 {
		return protectedHeader{}, nil, nil, fmt.Errorf("top-level CBOR tag MUST be COSE_Sign1 tag 18")
	}

	var items []cbor.RawMessage
	if err := decodeMode.Unmarshal(tag.Content, &items); err != nil {
		return protectedHeader{}, nil, nil, fmt.Errorf("decoding COSE_Sign1 array: %w", err)
	}
	if len(items) != 4 {
		return protectedHeader{}, nil, nil, fmt.Errorf("COSE_Sign1 MUST contain four array elements")
	}

	var protectedBytes []byte
	if err := decodeMode.Unmarshal(items[0], &protectedBytes); err != nil || len(protectedBytes) == 0 {
		return protectedHeader{}, nil, nil, fmt.Errorf("protected header MUST be a non-empty byte string")
	}
	values := make(map[int64]interface{})
	if err := decodeMode.Unmarshal(protectedBytes, &values); err != nil {
		return protectedHeader{}, nil, nil, fmt.Errorf("decoding protected header: %w", err)
	}

	var unprotected map[interface{}]interface{}
	if err := decodeMode.Unmarshal(items[1], &unprotected); err != nil {
		return protectedHeader{}, nil, nil, fmt.Errorf("decoding unprotected header: %w", err)
	}
	if len(unprotected) != 0 {
		return protectedHeader{}, nil, nil, fmt.Errorf("unprotected header MUST be an empty map")
	}

	var payload []byte
	if err := decodeMode.Unmarshal(items[2], &payload); err != nil {
		return protectedHeader{}, nil, nil, fmt.Errorf("attached payload MUST be a byte string")
	}
	var signature []byte
	if err := decodeMode.Unmarshal(items[3], &signature); err != nil {
		return protectedHeader{}, nil, nil, fmt.Errorf("signature MUST be a byte string")
	}

	return protectedHeader{values: values, raw: protectedBytes}, payload, signature, nil
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
