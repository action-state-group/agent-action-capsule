// SPDX-License-Identifier: BSD-3-Clause

package witness

import (
	"crypto"
	"crypto/ecdsa"
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

type policyKey struct {
	name string
	key  crypto.PublicKey
}

// keys returns the policy's usable keys in order; an entry that is not hex
// of an Ed25519 or ECDSA P-256 SubjectPublicKeyInfo lists no key.
func (p AnchorWitnessPolicy) keys() []policyKey {
	var out []policyKey
	for _, row := range p.Witnesses {
		for _, text := range row.Keys {
			der, err := hex.DecodeString(text)
			if err != nil {
				continue
			}
			if key, err := parsePublicKey(der); err == nil {
				out = append(out, policyKey{row.Name, key})
			}
		}
	}
	return out
}

// receiptAlg reads a Receipt's protected alg after step 1 of §6.2.2: a
// tag-18 COSE_Sign1 with a detached payload, vds 1, alg EdDSA or ES256 and
// no crit.
func receiptAlg(receipt []byte) (int64, bool) {
	if len(receipt) == 0 || len(receipt) > maxReceiptBytes {
		return 0, false
	}
	decoded, err := strictItem(receipt)
	if err != nil {
		return 0, false
	}
	tag, isTag := decoded.(cbor.Tag)
	parts, isArray := tag.Content.([]interface{})
	if !isTag || tag.Number != 18 || !isArray || len(parts) != 4 || parts[2] != nil {
		return 0, false
	}
	protectedBytes, isBytes := parts[0].([]byte)
	if !isBytes || len(protectedBytes) == 0 {
		return 0, false
	}
	value, err := strictItem(protectedBytes)
	if err != nil {
		return 0, false
	}
	protected, isMap := value.(map[interface{}]interface{})
	if !isMap {
		return 0, false
	}
	if vds, _ := protected[uint64(labelVDS)].(uint64); vds != vdsRFC9162 {
		return 0, false
	}
	if _, crit := protected[uint64(labelCrit)]; crit {
		return 0, false
	}
	alg, _ := protected[uint64(labelAlg)].(int64)
	return alg, alg == algEdDSA || alg == algES256
}

func keyFits(alg int64, key crypto.PublicKey) bool {
	switch key.(type) {
	case ed25519.PublicKey:
		return alg == algEdDSA
	case *ecdsa.PublicKey:
		return alg == algES256
	}
	return false
}

// CheckAnchorReceipt runs steps 1 to 5 of profile v1 §6.2.2 for one
// Receipt over the anchor whose digest is anchor (64 lowercase hex
// characters): the Receipt is checked as VerifyCOSEReceipt checks one, with
// the anchor digest's 32 octets as the leaf entry.
func CheckAnchorReceipt(anchor string, receipt []byte, policy AnchorWitnessPolicy) AnchorReceiptReport {
	if !anchorDigest.MatchString(anchor) {
		return AnchorReceiptReport{Status: AnchorFail, Detail: "the anchor digest is not 64 lowercase hex characters"}
	}
	alg, ok := receiptAlg(receipt)
	if !ok {
		return AnchorReceiptReport{Status: AnchorFail, Detail: "not a tag-18 COSE_Sign1 Receipt with a detached payload, vds 1, alg EdDSA or ES256 and no crit"}
	}
	var keys []policyKey
	for _, key := range policy.keys() {
		if keyFits(alg, key.key) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return AnchorReceiptReport{Status: AnchorNotChecked, Detail: "the witness policy lists no key of the type alg needs"}
	}
	leaf, _ := hex.DecodeString(anchor)
	for _, key := range keys {
		verified, err := VerifyCOSEReceipt(receipt, leaf, key.key)
		if err != nil {
			continue
		}
		name := key.name
		return AnchorReceiptReport{Status: AnchorPass, Witness: &name, RegistrationTime: verified.RegistrationTime}
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
