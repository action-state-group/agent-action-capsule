// SPDX-License-Identifier: BSD-3-Clause
package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

// A record's producer-signature verdicts (VerifyRecordSignature).
const (
	// Authored: the envelope verifies under key_id over the record's own
	// Capsule ID.
	Authored = "authored"
	// Unclaimed: the record carries neither signature nor key_id. An unsigned
	// record, not a forgery.
	Unclaimed = "unclaimed"
	// Invalid: only one of them is present, or the envelope does not verify.
	Invalid = "invalid"
)

// VerifyRecordSignature grades a record's producer signature: Authored,
// Unclaimed or Invalid. record["signature"] is the hex Producer Envelope and
// record["key_id"] the hex raw Ed25519 public key. The envelope must verify
// over the Capsule ID recomputed from the record's own content as its
// canonicalization_id declares (jcs, or the vintage jcs-n, declared or
// implied by an absent or null member); the carried capsule_id is not read.
// It returns the verdict and messages, which are empty unless Invalid.
// It never panics.
func VerifyRecordSignature(value interface{}) (string, []string) {
	record, isObject := value.(map[string]interface{})
	if !isObject {
		return Invalid, []string{"not a mapping"}
	}
	// Recomputing the Capsule ID recurses; a record nested more than
	// canonical.MaxNestingDepth levels deep is refused before it runs.
	if canonical.TooDeep(record) {
		return Invalid, []string{"record is nested too deeply"}
	}
	carried := "<none>"
	if id, present := record["capsule_id"]; present {
		carried = fmt.Sprint(id)
	}
	_, hasSignature := record["signature"]
	_, hasKeyID := record["key_id"]
	if !hasSignature && !hasKeyID {
		return Unclaimed, nil
	}
	if hasSignature != hasKeyID {
		return Invalid, []string{fmt.Sprintf("capsule_id=%s: only one of signature/key_id present -- malformed producer envelope", carried)}
	}
	malformed := func(err error) (string, []string) {
		return Invalid, []string{fmt.Sprintf("capsule_id=%s: producer envelope malformed: %v", carried, err)}
	}
	capsuleID, err := recordCapsuleID(record)
	if err != nil {
		return malformed(err)
	}
	signatureHex, isString := record["signature"].(string)
	if !isString {
		return malformed(fmt.Errorf("signature is not a string"))
	}
	data, err := hex.DecodeString(signatureHex)
	if err != nil {
		return malformed(err)
	}
	result := Verify(capsuleID, data)
	ok := result.OK
	if ok {
		keyHex, isString := record["key_id"].(string)
		if !isString {
			return malformed(fmt.Errorf("key_id is not a string"))
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			return malformed(err)
		}
		ok = bytes.Equal(result.PublicKey, key)
	}
	if ok {
		return Authored, nil
	}
	return Invalid, []string{fmt.Sprintf("capsule_id=%s: self-attested Ed25519 signature does not verify against key_id -- "+
		"content, signature, or key_id was tampered or forged", carried)}
}

// recordCapsuleID recomputes the Capsule ID a record declares by its
// canonicalization_id. jcs commits every member but capsule_id and the
// local-only envelope fields; jcs-n also drops chain, then null, empty-array
// and empty-object members bottom-up before JCS.
func recordCapsuleID(record map[string]interface{}) (string, error) {
	algorithm := interface{}("jcs-n")
	if declared := record["canonicalization_id"]; declared != nil {
		algorithm = declared
	}
	preimage := make(map[string]interface{}, len(record))
	for name, member := range record {
		if name != "capsule_id" && !canonical.LocalOnlyFields[name] {
			preimage[name] = member
		}
	}
	var data []byte
	var err error
	switch algorithm {
	case "jcs-n":
		delete(preimage, "chain")
		data, err = canonical.JCS(normalize(preimage))
	case canonical.CanonicalizationJCS:
		data, err = canonical.JCS(preimage)
	default:
		return "", fmt.Errorf("cannot compute capsule_id with canonicalization_id %v", algorithm)
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// normalize is the vintage jcs-n absent-field normalization: members whose
// value is null, an empty array or an empty object are removed, bottom-up, so
// an object emptied by its own removals is removed by its parent. Array
// elements are normalized but never removed.
func normalize(value interface{}) interface{} {
	switch value := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(value))
		for name, member := range value {
			normalized := normalize(member)
			switch normalized := normalized.(type) {
			case nil:
				continue
			case map[string]interface{}:
				if len(normalized) == 0 {
					continue
				}
			case []interface{}:
				if len(normalized) == 0 {
					continue
				}
			}
			out[name] = normalized
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(value))
		for i, member := range value {
			out[i] = normalize(member)
		}
		return out
	}
	return value
}
