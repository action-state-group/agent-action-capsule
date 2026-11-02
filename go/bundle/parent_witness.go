// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/witness"
	"github.com/action-state-group/checkpointed-local-log/go/mmr"
)

// ParentLogWitnessKind is the extension kind of a parent-log witness
// (Evidence Bundle -03, "The parent-log-witness/v1 Extension").
const ParentLogWitnessKind = "parent-log-witness/v1"

// ParentWitnessMaxPath is the most hashes a parent-log-witness path may hold.
const ParentWitnessMaxPath = 32

// ParentWitnessExtent is how much of the log a passed parent-log witness
// covers: the leaf counts of the covered checkpoint and of the Bundle's
// checkpoint. The extent is whole when Entries equals Of.
type ParentWitnessExtent struct {
	Entries uint64
	Of      uint64
}

// ParentWitnessResult is the result of a parent-log-witness/v1 block. Status
// is "pass", "withheld" or "fail". Extent is set only when Status is "pass";
// it is computed from the verified checkpoints, never read from the block.
// Receipts are the Receipts over the parent checkpoint, checked once every
// link of the chain held.
type ParentWitnessResult struct {
	Status   string
	Findings []string
	Extent   *ParentWitnessExtent
	Receipts []witness.ReceiptResult
}

func parentWitnessFail(finding string) ParentWitnessResult {
	return ParentWitnessResult{Status: witness.StatusFail, Findings: []string{finding}}
}

// uintValue is a JSON integer from 0 to 2^53-1: never a boolean, a string or
// a float such as 4.0.
func uintValue(value interface{}) (uint64, bool) {
	parsed, ok := integer(value)
	if !ok || parsed < 0 {
		return 0, false
	}
	return uint64(parsed), true
}

// signedCheckpointOf verifies stated["checkpoint"]["cose"]. malformed is true
// when the value is not unpadded canonical base64url; invalid when the octets
// do not verify as a CLL COSE checkpoint under its own key.
func signedCheckpointOf(stated interface{}) (signed witness.SignedCheckpoint, cose []byte, malformed, invalid bool) {
	object, _ := stated.(map[string]interface{})
	checkpoint, _ := object["checkpoint"].(map[string]interface{})
	encoded, isString := checkpoint["cose"].(string)
	if !isString || !b64url.MatchString(encoded) {
		return signed, nil, true, false
	}
	cose, err := strictB64URL.DecodeString(encoded)
	if err != nil {
		return signed, nil, true, false
	}
	signed, err = witness.ParseSignedCheckpoint(cose)
	if err != nil {
		return signed, nil, false, true
	}
	return signed, cose, false, false
}

// parseConsistencyProof reads the block's consistency proof, or reports false
// when its shape is not the draft's: v 1, kind "consistency", old_size and
// new_size integers, old_peaks and new_peaks lists of lowercase 64-hex
// hashes, and witness a list of such lists.
func parseConsistencyProof(raw interface{}) (mmr.ConsistencyProof, bool) {
	m, isObject := raw.(map[string]interface{})
	if !isObject {
		return mmr.ConsistencyProof{}, false
	}
	v, vOK := uintValue(m["v"])
	oldSize, oldOK := uintValue(m["old_size"])
	newSize, newOK := uintValue(m["new_size"])
	oldPeaks, oldErr := hashes(m["old_peaks"])
	newPeaks, newErr := hashes(m["new_peaks"])
	paths, pathsOK := m["witness"].([]interface{})
	if m["kind"] != "consistency" || !vOK || v != 1 || !oldOK || !newOK || oldErr != nil || newErr != nil || !pathsOK {
		return mmr.ConsistencyProof{}, false
	}
	witnessPaths := make([][][]byte, len(paths))
	for i, path := range paths {
		decoded, err := hashes(path)
		if err != nil {
			return mmr.ConsistencyProof{}, false
		}
		witnessPaths[i] = decoded
	}
	return mmr.ConsistencyProof{
		V: 1, Kind: "consistency", OldSize: oldSize, NewSize: newSize,
		OldPeaks: oldPeaks, Witness: witnessPaths, NewPeaks: newPeaks,
	}, true
}

// parentWitnessLeaf is the tree leaf naming a checkpoint:
// SHA-256(0x00 || JCS({checkpoint_sha256, log_id, salt, size})).
func parentWitnessLeaf(logID string, size uint64, checkpointCOSE []byte, salt string) ([]byte, bool) {
	digest := sha256.Sum256(checkpointCOSE)
	body, err := canonical.JCS(map[string]interface{}{
		"checkpoint_sha256": hex.EncodeToString(digest[:]),
		"log_id":            logID,
		"salt":              salt,
		"size":              json.Number(strconv.FormatUint(size, 10)),
	})
	if err != nil {
		return nil, false
	}
	leaf := sha256.Sum256(append([]byte{0}, body...))
	return leaf[:], true
}

// parentWitnessRoot is the tree root from a leaf, its index and its path
// (leaf first); an interior node is SHA-256(0x01 || left || right).
func parentWitnessRoot(leaf []byte, index uint64, path [][]byte) []byte {
	h := leaf
	for level, sibling := range path {
		buffer := make([]byte, 0, 1+2*sha256.Size)
		buffer = append(buffer, 1)
		if (index>>uint(level))&1 == 0 {
			buffer = append(append(buffer, h...), sibling...)
		} else {
			buffer = append(append(buffer, sibling...), h...)
		}
		sum := sha256.Sum256(buffer)
		h = sum[:]
	}
	return h
}

// VerifyParentLogWitness checks a parent-log-witness/v1 block against the
// Bundle's signed checkpoint (signed and checkpointCOSE; nil when the
// checkpoint was not authenticated) and the Receipts over the parent
// checkpoint under directory. It applies the draft's checks in order and
// stops at the first that fails; it never panics on its input.
func VerifyParentLogWitness(block interface{}, signed *witness.SignedCheckpoint, checkpointCOSE []byte, directory witness.Directory) ParentWitnessResult {
	if signed == nil || checkpointCOSE == nil {
		return ParentWitnessResult{Status: witness.StatusWithheld, Findings: []string{"checkpoint_unverified"}}
	}
	object, isObject := block.(map[string]interface{})
	if !isObject {
		return parentWitnessFail("parent_witness_malformed")
	}

	covered, coveredCOSE := *signed, checkpointCOSE
	if earlier, present := object["earlier"]; present {
		prior, priorCOSE, malformed, invalid := signedCheckpointOf(earlier)
		if malformed {
			return parentWitnessFail("parent_witness_earlier_checkpoint_malformed")
		}
		if invalid {
			return parentWitnessFail("parent_witness_earlier_checkpoint_signature_invalid")
		}
		if prior.KeyID != signed.KeyID || prior.LogID != signed.LogID || prior.MMRSize >= signed.MMRSize {
			return parentWitnessFail("parent_witness_earlier_checkpoint_not_this_log")
		}
		earlierObject, _ := earlier.(map[string]interface{})
		proof, proofOK := parseConsistencyProof(earlierObject["consistency_proof"])
		oldRoot, oldErr := hex.DecodeString(prior.Root)
		newRoot, newErr := hex.DecodeString(signed.Root)
		if !proofOK || proof.OldSize != prior.MMRSize || proof.NewSize != signed.MMRSize ||
			oldErr != nil || newErr != nil || !mmr.VerifyConsistency(oldRoot, newRoot, proof) {
			return parentWitnessFail("parent_witness_earlier_checkpoint_not_a_prefix")
		}
		covered, coveredCOSE = prior, priorCOSE
	}

	logID, logOK := object["log_id"].(string)
	size, sizeOK := uintValue(object["size"])
	if !logOK || logID != covered.LogID || !sizeOK || size != covered.MMRSize {
		return parentWitnessFail("parent_witness_leaf_does_not_name_this_checkpoint")
	}
	rawPath, pathIsList := object["path"].([]interface{})
	var path [][]byte
	var pathErr error
	if pathIsList {
		path, pathErr = hashes(rawPath)
	}
	if !pathIsList || len(rawPath) > ParentWitnessMaxPath || pathErr != nil {
		return parentWitnessFail("parent_witness_path_malformed")
	}
	salt, saltOK := object["salt"].(string)
	index, indexOK := uintValue(object["index"])
	if !saltOK || salt == "" || !indexOK || index >= uint64(1)<<uint(len(path)) {
		return parentWitnessFail("parent_witness_leaf_malformed")
	}
	leaf, leafOK := parentWitnessLeaf(logID, size, coveredCOSE, salt)
	if !leafOK {
		return parentWitnessFail("parent_witness_leaf_malformed")
	}
	root := parentWitnessRoot(leaf, index, path)

	parentSigned, parentCOSE, malformed, invalid := signedCheckpointOf(object["parent"])
	if malformed {
		return parentWitnessFail("parent_witness_parent_checkpoint_malformed")
	}
	if invalid {
		return parentWitnessFail("parent_witness_parent_checkpoint_signature_invalid")
	}
	if parentSigned.KeyID != signed.KeyID {
		return parentWitnessFail("parent_witness_parent_signer_differs")
	}
	parent, _ := object["parent"].(map[string]interface{})
	if parentLogID, isString := parent["log_id"].(string); !isString || parentLogID != parentSigned.LogID {
		return parentWitnessFail("parent_witness_parent_log_id_mismatch")
	}
	entryIndex, entryOK := uintValue(parent["entry_index"])
	inclusion, inclusionErr := parseInclusionProof(parent["inclusion_proof"])
	parentRoot, rootErr := hex.DecodeString(parentSigned.Root)
	if !entryOK || inclusionErr != nil || inclusion.Size != parentSigned.MMRSize || inclusion.LeafIndex != entryIndex ||
		rootErr != nil || !mmr.VerifyInclusion(parentRoot, parentSigned.MMRSize, entryIndex, root, inclusion) {
		return parentWitnessFail("parent_witness_entry_not_included")
	}

	status, findings, receipts := witness.VerifyReceipts(parent["witnesses"], &parentSigned, parentCOSE, directory)
	result := ParentWitnessResult{Status: status, Findings: findings, Receipts: receipts}
	if status == witness.StatusPass {
		entries, entriesOK := mmr.LeafCount(covered.MMRSize)
		of, ofOK := mmr.LeafCount(signed.MMRSize)
		if entriesOK && ofOK {
			result.Extent = &ParentWitnessExtent{Entries: entries, Of: of}
		}
	}
	return result
}
