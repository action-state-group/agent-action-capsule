// SPDX-License-Identifier: BSD-3-Clause
package witness

// The COSE Receipt check follows the scitt-cose verifiers (Python
// scitt_cose.verify_receipt and action-state-group/scitt-cose's
// scitt-cose-go-verify, Apache-2.0), restricted to the profile of
// vectors/bundle/strict/README.md ("COSE Receipts"): a detached payload,
// vds 1 (RFC9162_SHA256) and alg EdDSA or ES256.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// COSE header labels and values a receipt check reads.
const (
	labelAlg        = 1
	labelCrit       = 2
	labelCWTClaims  = 15
	labelVDS        = 395
	labelVDP        = 396
	labelGrade      = -65537
	vdpInclusion    = -1
	vdsRFC9162      = 1
	algEdDSA        = -8
	algES256        = -7
	maxReceiptBytes = 10 << 20
	maxProofs       = 16
	maxAuditPath    = 64
	maxTreeSize     = int64(1) << 62
)

// understoodLabels are the protected labels a receipt check processes; a
// receipt marking any other label critical (RFC 9052 section 3.1) is refused.
var understoodLabels = map[uint64]bool{labelAlg: true, labelCrit: true, labelVDS: true, labelCWTClaims: true}

var (
	strictDecoding = func() cbor.DecMode {
		mode, err := cbor.DecOptions{
			DupMapKey:   cbor.DupMapKeyEnforcedAPF,
			IndefLength: cbor.IndefLengthForbidden,
			IntDec:      cbor.IntDecConvertNone,
		}.DecMode()
		if err != nil {
			panic(err)
		}
		return mode
	}()
	lenientDecoding = func() cbor.DecMode {
		mode, err := cbor.DecOptions{IntDec: cbor.IntDecConvertNone}.DecMode()
		if err != nil {
			panic(err)
		}
		return mode
	}()
	deterministicEncoding = func() cbor.EncMode {
		mode, err := cbor.CoreDetEncOptions().EncMode()
		if err != nil {
			panic(err)
		}
		return mode
	}()
)

// COSEReceipt is what a verified COSE Receipt states.
type COSEReceipt struct {
	// TreeSize, LeafIndex and Root are those of the inclusion proof the
	// signature verified over.
	TreeSize, LeafIndex int64
	Root                []byte
	// GradeLabel reports whether the protected header carries label -65537;
	// Grade is its value when it is a known grade (countersigned-observed
	// read as observed-only), else nil.
	GradeLabel bool
	Grade      *string
}

// VerifyCOSEReceipt verifies an RFC 9162 COSE Receipt (draft-ietf-cose-
// merkle-tree-proofs) for leaf under key (ed25519.PublicKey or
// *ecdsa.PublicKey). The receipt must be a strictly encoded tag-18
// COSE_Sign1 with a detached payload, protected vds 1 and alg EdDSA (-8) or
// ES256 (-7), and an unprotected vdp map whose -1 entry is a non-empty array
// of inclusion proofs, each CBOR [tree_size, leaf_index, [audit_path...]];
// every entry must decode. It verifies when, for some proof, the root
// rebuilt from leaf (hashed as an RFC 6962 leaf) verifies the signature.
// The alg fixes the key type: ES256 verifies only under an ECDSA P-256 key
// and EdDSA only under an Ed25519 key.
// Protected-header claims are reported only after the signature verified.
func VerifyCOSEReceipt(receipt, leaf []byte, key crypto.PublicKey) (COSEReceipt, error) {
	if len(receipt) == 0 || len(receipt) > maxReceiptBytes {
		return COSEReceipt{}, errors.New("receipt size is invalid")
	}
	decoded, err := strictItem(receipt)
	if err != nil {
		return COSEReceipt{}, fmt.Errorf("receipt rejected: %w", err)
	}
	tag, isTag := decoded.(cbor.Tag)
	parts, isArray := tag.Content.([]interface{})
	if !isTag || tag.Number != 18 || !isArray || len(parts) != 4 {
		return COSEReceipt{}, errors.New("receipt is not a COSE_Sign1 message")
	}
	protectedBytes, isBytes := parts[0].([]byte)
	if !isBytes {
		return COSEReceipt{}, errors.New("receipt is not a COSE_Sign1 message")
	}
	if parts[2] != nil {
		return COSEReceipt{}, errors.New("receipt payload is attached; a receipt's payload must be detached")
	}
	signature, isBytes := parts[3].([]byte)
	if !isBytes {
		return COSEReceipt{}, errors.New("receipt signature is not a byte string")
	}
	protected := map[interface{}]interface{}{}
	if len(protectedBytes) != 0 {
		value, err := strictItem(protectedBytes)
		if err != nil {
			return COSEReceipt{}, fmt.Errorf("protected header rejected: %w", err)
		}
		var isMap bool
		if protected, isMap = value.(map[interface{}]interface{}); !isMap {
			return COSEReceipt{}, errors.New("protected header is not a map")
		}
	}
	if vds, _ := protected[uint64(labelVDS)].(uint64); vds != vdsRFC9162 {
		return COSEReceipt{}, errors.New("receipt vds is not RFC9162_SHA256 (1)")
	}
	alg, _ := protected[uint64(labelAlg)].(int64)
	if alg != algEdDSA && alg != algES256 {
		return COSEReceipt{}, errors.New("receipt alg is not EdDSA (-8) or ES256 (-7)")
	}
	if err := checkKeyType(alg, key); err != nil {
		return COSEReceipt{}, err
	}
	if err := checkCritical(protected); err != nil {
		return COSEReceipt{}, err
	}
	unprotected, isMap := parts[1].(map[interface{}]interface{})
	if !isMap {
		return COSEReceipt{}, errors.New("unprotected header is not a map")
	}
	vdp, isMap := unprotected[uint64(labelVDP)].(map[interface{}]interface{})
	if !isMap {
		return COSEReceipt{}, errors.New("unprotected vdp (label 396) missing or not a map")
	}
	proofs, isArray := vdp[int64(vdpInclusion)].([]interface{})
	if !isArray || len(proofs) == 0 {
		return COSEReceipt{}, errors.New("vdp has no inclusion proofs (key -1)")
	}
	if len(proofs) > maxProofs {
		return COSEReceipt{}, fmt.Errorf("too many inclusion proofs (%d > %d)", len(proofs), maxProofs)
	}
	// Decode every candidate before verifying any: a valid proof must not hide
	// a malformed later entry in this unauthenticated array.
	type candidate struct {
		size, index int64
		path        [][]byte
	}
	candidates := make([]candidate, 0, len(proofs))
	for _, entry := range proofs {
		blob, isBytes := entry.([]byte)
		if !isBytes {
			return COSEReceipt{}, errors.New("inclusion proof entry is not a byte string")
		}
		size, index, path, err := decodeInclusionProof(blob)
		if err != nil {
			return COSEReceipt{}, err
		}
		candidates = append(candidates, candidate{size, index, path})
	}
	for _, proof := range candidates {
		root, ok := rootFromInclusionProof(leaf, proof.index, proof.size, proof.path)
		if !ok || !verifySignature(alg, key, sigStructure(protectedBytes, root), signature) {
			continue
		}
		result := COSEReceipt{TreeSize: proof.size, LeafIndex: proof.index, Root: root}
		if label, present := protected[int64(labelGrade)]; present {
			result.GradeLabel = true
			if text, isString := label.(string); isString {
				if grade, known := grades[text]; known {
					result.Grade = &grade
				}
			}
		}
		return result, nil
	}
	return COSEReceipt{}, errors.New("receipt signature did not verify over any reconstructed root")
}

// strictItem decodes one CBOR item and refuses any encoding other than its
// deterministic one up to map order: trailing bytes, indefinite lengths,
// duplicate keys, and non-minimal arguments or floats. Like scitt-cose's
// strict_decode it compares lengths, so a validly signed header whose map
// keys are not in canonical order is accepted.
func strictItem(data []byte) (interface{}, error) {
	var value interface{}
	if err := strictDecoding.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	canonical, err := deterministicEncoding.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(canonical) != len(data) {
		return nil, errors.New("non-deterministic CBOR encoding")
	}
	return value, nil
}

// checkKeyType holds the key to the type the receipt's alg fixes: ES256 is
// ECDSA over P-256 only, and EdDSA is Ed25519.
func checkKeyType(alg int64, key crypto.PublicKey) error {
	switch alg {
	case algES256:
		if public, isECDSA := key.(*ecdsa.PublicKey); !isECDSA || public.Curve != elliptic.P256() {
			return errors.New("receipt alg ES256 needs an ECDSA P-256 key")
		}
	case algEdDSA:
		if public, isEd25519 := key.(ed25519.PublicKey); !isEd25519 || len(public) != ed25519.PublicKeySize {
			return errors.New("receipt alg EdDSA needs an Ed25519 key")
		}
	}
	return nil
}

// checkCritical enforces RFC 9052 section 3.1: a crit list must be a
// non-empty array of labels that are present and understood.
func checkCritical(protected map[interface{}]interface{}) error {
	raw, present := protected[uint64(labelCrit)]
	if !present {
		return nil
	}
	labels, isArray := raw.([]interface{})
	if !isArray || len(labels) == 0 {
		return errors.New("crit (label 2) must be a non-empty array")
	}
	for _, label := range labels {
		switch label.(type) {
		case uint64, int64, string:
		default:
			return errors.New("crit lists a label that is not an integer or text")
		}
		if _, listed := protected[label]; !listed {
			return errors.New("crit lists a header absent from the protected header")
		}
		if value, isUint := label.(uint64); !isUint || !understoodLabels[value] {
			return errors.New("crit marks a header this verifier does not understand")
		}
	}
	return nil
}

// decodeInclusionProof decodes CBOR [tree_size, leaf_index, [audit_path]].
func decodeInclusionProof(blob []byte) (int64, int64, [][]byte, error) {
	var value interface{}
	if err := lenientDecoding.Unmarshal(blob, &value); err != nil {
		return 0, 0, nil, fmt.Errorf("inclusion proof is not valid CBOR: %w", err)
	}
	parts, isArray := value.([]interface{})
	if !isArray || len(parts) != 3 {
		return 0, 0, nil, errors.New("inclusion proof must be [tree_size, leaf_index, [path]]")
	}
	size, sizeOK := cborInteger(parts[0])
	index, indexOK := cborInteger(parts[1])
	if !sizeOK || !indexOK {
		return 0, 0, nil, errors.New("inclusion proof tree_size and leaf_index must be integers")
	}
	nodes, isArray := parts[2].([]interface{})
	if !isArray {
		return 0, 0, nil, errors.New("inclusion proof path must be an array")
	}
	if len(nodes) > maxAuditPath {
		return 0, 0, nil, errors.New("inclusion proof path too long")
	}
	path := make([][]byte, len(nodes))
	for i, node := range nodes {
		raw, isBytes := node.([]byte)
		if !isBytes {
			return 0, 0, nil, errors.New("inclusion proof path element is not a byte string")
		}
		path[i] = raw
	}
	if index < 0 || index >= size || size > maxTreeSize {
		return 0, 0, nil, errors.New("invalid tree size or leaf index")
	}
	if int64(len(path)) != expectedPathLength(size, index) {
		return 0, 0, nil, errors.New("invalid inclusion proof path length")
	}
	for _, node := range path {
		if len(node) != sha256.Size {
			return 0, 0, nil, errors.New("inclusion proof path node must be 32 bytes")
		}
	}
	return size, index, path, nil
}

// cborInteger reads a decoded CBOR integer, a bignum included, that fits an
// int64; the range checks that follow bound it further.
func cborInteger(value interface{}) (int64, bool) {
	switch value := value.(type) {
	case uint64:
		if value > math.MaxInt64 {
			return 0, false
		}
		return int64(value), true
	case int64:
		return value, true
	case big.Int:
		if value.IsInt64() {
			return value.Int64(), true
		}
	case *big.Int:
		if value.IsInt64() {
			return value.Int64(), true
		}
	}
	return 0, false
}

func largestPowerOfTwoBelow(n int64) int64 {
	k := int64(1)
	for k <= (n-1)/2 {
		k *= 2
	}
	return k
}

// expectedPathLength is the number of audit-path siblings for index in an
// RFC 6962 tree of size entries.
func expectedPathLength(size, index int64) int64 {
	var n int64
	for size > 1 {
		k := largestPowerOfTwoBelow(size)
		if index < k {
			size = k
		} else {
			size, index = size-k, index-k
		}
		n++
	}
	return n
}

// rootFromInclusionProof folds leaf up its audit path to the root (RFC 6962
// section 2.1.1), consuming the path outermost-first.
func rootFromInclusionProof(leaf []byte, index, size int64, path [][]byte) ([]byte, bool) {
	if index < 0 || index >= size || size > maxTreeSize || int64(len(path)) != expectedPathLength(size, index) {
		return nil, false
	}
	leafHash := sha256.Sum256(append([]byte{0}, leaf...))
	siblings := append([][]byte(nil), path...)
	var fold func(size, index int64) []byte
	fold = func(size, index int64) []byte {
		if size == 1 {
			return leafHash[:]
		}
		k := largestPowerOfTwoBelow(size)
		sibling := siblings[len(siblings)-1]
		siblings = siblings[:len(siblings)-1]
		if index < k {
			return nodeHash(fold(k, index), sibling)
		}
		return nodeHash(sibling, fold(size-k, index-k))
	}
	return fold(size, index), true
}

func nodeHash(left, right []byte) []byte {
	input := make([]byte, 0, 1+len(left)+len(right))
	input = append(append(append(input, 1), left...), right...)
	sum := sha256.Sum256(input)
	return sum[:]
}

func verifySignature(alg int64, key crypto.PublicKey, message, signature []byte) bool {
	switch alg {
	case algEdDSA:
		public, isEd25519 := key.(ed25519.PublicKey)
		return isEd25519 && len(public) == ed25519.PublicKeySize && ed25519.Verify(public, message, signature)
	case algES256:
		public, isECDSA := key.(*ecdsa.PublicKey)
		if !isECDSA || len(signature) != 64 {
			return false
		}
		digest := sha256.Sum256(message)
		r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(public, digest[:], r, s)
	}
	return false
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
