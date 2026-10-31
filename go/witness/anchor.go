// SPDX-License-Identifier: BSD-3-Clause

package witness

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"regexp"

	"github.com/fxamacker/cbor/v2"
)

// AnchorWitnessKind is the verification-material kind of a witness Receipt
// over a Checkpointed Local Log anchor (spec/interop-profile-v1.md §6.2.2).
const AnchorWitnessKind = "cll-witness-receipt"

// AnchorWitnessProperty is the check §6.2.2 defines. It is not an envelope
// property and never enters the profile's §8 mapping.
const AnchorWitnessProperty = "anchor_witnessed"

// The statuses an anchor_witnessed report uses (profile §7.1).
const (
	AnchorPass       = "PASS"
	AnchorFail       = "FAIL"
	AnchorNotPresent = "NOT_PRESENT"
	AnchorNotChecked = "NOT_CHECKED"
)

var anchorDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// AnchorWitnessPolicy is the relying party's witness list: each witness's
// name and the DER SubjectPublicKeyInfo keys, hex in JSON, it signs Receipts
// under. Only Ed25519 and ECDSA P-256 keys count.
type AnchorWitnessPolicy struct {
	Witnesses []AnchorWitness `json:"witnesses"`
}

// AnchorWitness is one row of an AnchorWitnessPolicy.
type AnchorWitness struct {
	Name string   `json:"name"`
	Keys []string `json:"keys"`
}

// AnchorReceiptReport is one Receipt's status, its witness's name when it
// passed, and its registration time (a NumericDate) when it passed with a
// protected iat.
type AnchorReceiptReport struct {
	Status           string  `json:"status"`
	Witness          *string `json:"witness"`
	RegistrationTime *int64  `json:"registration_time"`
	Detail           string  `json:"-"`
}

// AnchorWitnessReport is anchor_witnessed over every Receipt for one anchor.
// Witness and WitnessedTime always come from the same Receipt.
type AnchorWitnessReport struct {
	Status        string                `json:"status"`
	Receipts      []AnchorReceiptReport `json:"receipts"`
	Witness       *string               `json:"witness"`
	WitnessedTime *int64                `json:"witnessed_time"`
}

var (
	ed25519SPKIPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	p256SPKIPrefix    = []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04}
	lowerHex          = regexp.MustCompile(`^(?:[0-9a-f]{2})*$`)
)

// receiptDecoding is the decode mode of every COSE Receipt check: repeated
// keys, indefinite lengths, CBOR undefined and the bignum tags refused, so
// that null alone decodes to nil. A negative integer below -2^63 decodes to a
// big.Int, which strictReceiptItem refuses, as profile v1 §6.2.2 does. The
// array and map limits cover a whole receipt of maxReceiptBytes: §6.2.2 sets
// no item count below the octet limit, where fxamacker's default is 131072.
var receiptDecoding = func() cbor.DecMode {
	simple, err := cbor.NewSimpleValueRegistryFromDefaults(cbor.WithRejectedSimpleValue(23))
	if err != nil {
		panic(err)
	}
	mode, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		IntDec:           cbor.IntDecConvertNone,
		BignumTag:        cbor.BignumTagForbidden,
		SimpleValues:     simple,
		MaxArrayElements: maxReceiptBytes,
		MaxMapPairs:      maxReceiptBytes,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// privateLabel bounds the private-use COSE labels (RFC 9052 section 16.4):
// a label below it may carry any value.
const privateLabel = -65536

// maxReceiptDepth is the deepest nesting §6.2.2 allows.
const maxReceiptDepth = 16

type policyKey struct {
	name string
	alg  int64
	// key is nil when the entry has a key's shape but is not a valid key:
	// it is listed, and nothing verifies under it.
	key crypto.PublicKey
}

// keys returns the policy's listed keys in order (profile v1 §6.2.2 step
// 2): lowercase hex of one of two exact SubjectPublicKeyInfo shapes.
func (p AnchorWitnessPolicy) keys() []policyKey {
	var out []policyKey
	for _, row := range p.Witnesses {
		for _, text := range row.Keys {
			if !lowerHex.MatchString(text) {
				continue
			}
			der, _ := hex.DecodeString(text)
			switch {
			case len(der) == 44 && bytes.HasPrefix(der, ed25519SPKIPrefix):
				out = append(out, policyKey{row.Name, algEdDSA, ed25519.PublicKey(der[12:])})
			case len(der) == 91 && bytes.HasPrefix(der, p256SPKIPrefix):
				key, err := parsePublicKey(der)
				if err != nil {
					key = nil
				}
				out = append(out, policyKey{row.Name, algES256, key})
			}
		}
	}
	return out
}

// anchorProof is one inclusion proof of a Receipt in the one form.
type anchorProof struct {
	size, index int64
	path        [][]byte
}

// anchorReceipt is a Receipt in the one form of §6.2.2.
type anchorReceipt struct {
	alg       int64
	protected []byte
	proofs    []anchorProof
	signature []byte
	time      *int64
}

// strictReceiptItem decodes one CBOR item under the encoding rule of profile
// v1 §6.2.2, which the strict Bundle check (VerifyCOSEReceipt) shares: no
// trailing bytes, definite lengths, shortest arguments, no repeated key,
// integer or text keys, no float, no simple value but false, true and null,
// no tag but an outer 18 when topTag, and at most maxReceiptDepth levels.
// Map order is not checked.
func strictReceiptItem(data []byte, topTag bool) (interface{}, bool) {
	var value interface{}
	if err := receiptDecoding.Unmarshal(data, &value); err != nil {
		return nil, false
	}
	// Shortest arguments: the deterministic re-encoding is as long as the
	// input, whatever the map order.
	if canonical, err := deterministicEncoding.Marshal(value); err != nil || len(canonical) != len(data) {
		return nil, false
	}
	var walk func(v interface{}, depth int) bool
	walk = func(v interface{}, depth int) bool {
		if depth > maxReceiptDepth {
			return false
		}
		switch v := v.(type) {
		case nil, bool, uint64, int64, []byte, string:
			return true
		case cbor.Tag:
			return depth == 0 && topTag && v.Number == 18 && walk(v.Content, depth+1)
		case []interface{}:
			for _, item := range v {
				if !walk(item, depth+1) {
					return false
				}
			}
			return true
		case map[interface{}]interface{}:
			for key, item := range v {
				switch key.(type) {
				case uint64, int64, string:
				default:
					return false
				}
				if !walk(item, depth+1) {
					return false
				}
			}
			return true
		}
		return false // a float, a bignum, a simple value or any other decoded type
	}
	return value, walk(value, 0)
}

// protectedLabelOK reports whether one protected header entry is allowed.
func protectedLabelOK(label, value interface{}, out *anchorReceipt) bool {
	switch label {
	case uint64(labelAlg):
		alg, isInt := value.(int64)
		out.alg = alg
		return isInt && (alg == algEdDSA || alg == algES256)
	case uint64(labelVDS):
		vds, isUint := value.(uint64)
		return isUint && vds == vdsRFC9162
	case uint64(4):
		_, isBytes := value.([]byte)
		return isBytes
	case uint64(labelCWTClaims):
		claims, isMap := value.(map[interface{}]interface{})
		if iat, isUint := claims[uint64(cwtIat)].(uint64); isMap && isUint && iat <= maxIat {
			seconds := int64(iat)
			out.time = &seconds
		}
		return isMap
	}
	negative, isInt := label.(int64)
	return isInt && negative < privateLabel
}

// parseAnchorReceipt is step 1 of profile v1 §6.2.2.
func parseAnchorReceipt(receipt []byte) (anchorReceipt, bool) {
	var out anchorReceipt
	if len(receipt) == 0 || len(receipt) > maxReceiptBytes {
		return out, false
	}
	decoded, ok := strictReceiptItem(receipt, true)
	tag, isTag := decoded.(cbor.Tag)
	if !ok || !isTag || tag.Number != 18 {
		return out, false
	}
	parts, isArray := tag.Content.([]interface{})
	if !isArray || len(parts) != 4 || parts[2] != nil {
		return out, false
	}
	protected, isBytes := parts[0].([]byte)
	signature, sigBytes := parts[3].([]byte)
	if !isBytes || len(protected) == 0 || !sigBytes || len(signature) != 64 {
		return out, false
	}
	value, ok := strictReceiptItem(protected, false)
	headers, isMap := value.(map[interface{}]interface{})
	if !ok || !isMap {
		return out, false
	}
	_, hasAlg := headers[uint64(labelAlg)]
	_, hasVDS := headers[uint64(labelVDS)]
	if !hasAlg || !hasVDS {
		return out, false
	}
	for label, value := range headers {
		if !protectedLabelOK(label, value, &out) {
			return out, false
		}
	}
	unprotected, isMap := parts[1].(map[interface{}]interface{})
	if !isMap || len(unprotected) != 1 {
		return out, false
	}
	vdp, isMap := unprotected[uint64(labelVDP)].(map[interface{}]interface{})
	if !isMap || len(vdp) != 1 {
		return out, false
	}
	proofs, isArray := vdp[int64(vdpInclusion)].([]interface{})
	if !isArray || len(proofs) == 0 || len(proofs) > maxProofs {
		return out, false
	}
	for _, entry := range proofs {
		blob, isBytes := entry.([]byte)
		if !isBytes {
			return out, false
		}
		value, ok := strictReceiptItem(blob, false)
		proof, isArray := value.([]interface{})
		if !ok || !isArray || len(proof) != 3 {
			return out, false
		}
		size, sizeOK := proof[0].(uint64)
		index, indexOK := proof[1].(uint64)
		nodes, nodesOK := proof[2].([]interface{})
		if !sizeOK || !indexOK || !nodesOK || index >= size || size > uint64(maxTreeSize) ||
			int64(len(nodes)) != expectedPathLength(int64(size), int64(index)) {
			return out, false
		}
		path := make([][]byte, len(nodes))
		for i, node := range nodes {
			raw, isBytes := node.([]byte)
			if !isBytes || len(raw) != 32 {
				return out, false
			}
			path[i] = raw
		}
		out.proofs = append(out.proofs, anchorProof{int64(size), int64(index), path})
	}
	out.protected, out.signature = protected, signature
	return out, true
}

// CheckAnchorReceipt runs steps 1 to 5 of profile v1 §6.2.2 for one
// Receipt over the anchor whose digest is anchor (64 lowercase hex
// characters).
func CheckAnchorReceipt(anchor string, receipt []byte, policy AnchorWitnessPolicy) AnchorReceiptReport {
	if !anchorDigest.MatchString(anchor) {
		return AnchorReceiptReport{Status: AnchorFail, Detail: "the anchor digest is not 64 lowercase hex characters"}
	}
	parsed, ok := parseAnchorReceipt(receipt)
	if !ok {
		return AnchorReceiptReport{Status: AnchorFail, Detail: "not a Receipt in the one form of profile v1 §6.2.2"}
	}
	var keys []policyKey
	for _, key := range policy.keys() {
		if key.alg == parsed.alg {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return AnchorReceiptReport{Status: AnchorNotChecked, Detail: "the witness policy lists no key of the type alg needs"}
	}
	leaf, _ := hex.DecodeString(anchor)
	for _, key := range keys {
		if key.key == nil {
			continue
		}
		for _, proof := range parsed.proofs {
			root, ok := rootFromInclusionProof(leaf, proof.index, proof.size, proof.path)
			if ok && verifySignature(parsed.alg, key.key, sigStructure(parsed.protected, root), parsed.signature) {
				name := key.name
				return AnchorReceiptReport{Status: AnchorPass, Witness: &name, RegistrationTime: parsed.time}
			}
		}
	}
	return AnchorReceiptReport{Status: AnchorFail, Detail: "no accepted witness key verifies the Receipt over this anchor"}
}

// CheckAnchorWitnessed reports anchor_witnessed over receipts, in the order
// received, for the anchor anchor under policy (profile v1 §6.2.2). The
// anchor's witnessed time is the earliest registration time of a passing
// Receipt, with that Receipt's witness; the first received wins a tie.
// With no timed passing Receipt, the first passing Receipt names the witness.
func CheckAnchorWitnessed(anchor string, receipts [][]byte, policy AnchorWitnessPolicy) AnchorWitnessReport {
	report := AnchorWitnessReport{Status: AnchorNotPresent, Receipts: []AnchorReceiptReport{}}
	var failed, passed bool
	var chosen *AnchorReceiptReport
	for _, receipt := range receipts {
		report.Receipts = append(report.Receipts, CheckAnchorReceipt(anchor, receipt, policy))
	}
	for i := range report.Receipts {
		r := &report.Receipts[i]
		switch r.Status {
		case AnchorPass:
			passed = true
			switch {
			case chosen == nil:
				chosen = r
			case r.RegistrationTime != nil && (chosen.RegistrationTime == nil || *r.RegistrationTime < *chosen.RegistrationTime):
				chosen = r
			}
		case AnchorFail:
			failed = true
		}
	}
	switch {
	case len(receipts) == 0:
	case passed:
		report.Status = AnchorPass
	case failed:
		report.Status = AnchorFail
	default:
		report.Status = AnchorNotChecked
	}
	if chosen != nil {
		report.Witness, report.WitnessedTime = chosen.Witness, chosen.RegistrationTime
	}
	return report
}
