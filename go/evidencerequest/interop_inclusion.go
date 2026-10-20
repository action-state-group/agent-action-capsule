// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// anchor_inclusion for Checkpointed Local Log material (profile §6.2.1,
// steps 1 to 14). The steps run in order and the first that yields a
// status decides.

const inclusionBaseMethod = "§6.2.1 Checkpointed Local Log procedure"

func inclusionReport(status, detail string) PropertyReport {
	return report("anchor_inclusion", status, inclusionBaseMethod, detail)
}

type malformed string

func (m malformed) Error() string { return string(m) }

// deterministicItem decodes one CBOR data item and requires it to be well
// formed and in deterministic encoding (RFC 8949 §4.2.1): re-encoding the
// decoded item must give the same octets.
func deterministicItem(octets []byte, label string) (any, error) {
	d, err := decodeCBORItem(octets)
	if err != nil {
		return nil, malformed(label + ": " + err.Error())
	}
	if !d.deterministic || !d.wellFormed() {
		return nil, malformed(label + " is not deterministic CBOR")
	}
	return d.value, nil
}

func peakList(raw any) ([][]byte, error) {
	data, ok := raw.([]byte)
	if !ok {
		return nil, malformed("commitment is not a byte string")
	}
	item, err := deterministicItem(data, "commitment")
	if err != nil {
		return nil, err
	}
	list, ok := byteStrings32(item)
	if !ok || len(list) == 0 {
		return nil, malformed("commitment is not an array of one or more 32-octet byte strings")
	}
	return list, nil
}

func wellFormedCBOR(octets []byte, label string) error {
	d, err := decodeCBORItem(octets)
	if err != nil {
		return malformed(label + ": " + err.Error())
	}
	if !d.wellFormed() {
		return malformed(label + " has a duplicate map key or a value outside the data model")
	}
	return nil
}

type cllCheckpoint struct {
	protected, payload, signature []byte
	alg                           any
	kid                           any
	crit                          bool
	iss, sub                      any
	issuedAt                      string
	logSize, prevSize             uint64
	commitment, prevCommitment    [][]byte
}

func intKey(m map[any]any, k int64) (any, bool) {
	for key, v := range m {
		switch n := key.(type) {
		case uint64:
			if k >= 0 && n == uint64(k) {
				return v, true
			}
		case int64:
			if n == k {
				return v, true
			}
		}
	}
	return nil, false
}

func asUint(v any) (uint64, bool) {
	n, ok := v.(uint64)
	return n, ok && n <= MaxSafeInteger
}

// decodeCLLCheckpoint is step 7: the one fixed COSE_Sign1 form of a CLL
// checkpoint, decoded and checked.
func decodeCLLCheckpoint(octets []byte) (*cllCheckpoint, error) {
	// The reference decodes the checkpoint, its header and its payload with
	// its strict decoder and fails step 7 when any is not well formed (a
	// duplicate key, a float, a key that is no scalar, undefined or an
	// indefinite length). The same gate runs first here.
	if err := wellFormedCBOR(octets, "checkpoint"); err != nil {
		return nil, err
	}
	var outer cbor.Tag
	if err := strictCBOR.Unmarshal(octets, &outer); err != nil || outer.Number != 18 {
		var raw any
		if err2 := strictCBOR.Unmarshal(octets, &raw); err2 != nil {
			return nil, malformed(fmt.Sprintf("checkpoint: %v", err2))
		}
		return nil, malformed("checkpoint is not CBOR tag 18")
	}
	body, ok := outer.Content.([]any)
	if !ok || len(body) != 4 {
		return nil, malformed("COSE_Sign1 is not a four-element array")
	}
	if u, isMap := body[1].(map[any]any); !isMap || len(u) != 0 {
		return nil, malformed("unprotected header is not empty")
	}
	if body[2] == nil {
		return nil, malformed("payload is detached")
	}
	protected, ok1 := body[0].([]byte)
	payload, ok2 := body[2].([]byte)
	signature, ok3 := body[3].([]byte)
	if !ok1 || !ok2 || !ok3 {
		return nil, malformed("COSE_Sign1 member has the wrong type")
	}
	cp := &cllCheckpoint{protected: protected, payload: payload, signature: signature}
	if err := wellFormedCBOR(protected, "checkpoint header"); err != nil {
		return nil, err
	}
	if err := wellFormedCBOR(payload, "checkpoint payload"); err != nil {
		return nil, err
	}
	var hdr, claims any
	if err := strictCBOR.Unmarshal(protected, &hdr); err != nil {
		return nil, malformed(fmt.Sprintf("checkpoint header or payload: %v", err))
	}
	if err := strictCBOR.Unmarshal(payload, &claims); err != nil {
		return nil, malformed(fmt.Sprintf("checkpoint header or payload: %v", err))
	}
	h, ok := hdr.(map[any]any)
	alg, hasAlg := intKey(h, 1)
	kid, hasKid := intKey(h, 4)
	if !ok || !hasAlg || !hasKid {
		return nil, malformed("protected header lacks alg or kid")
	}
	cwtRaw, _ := intKey(h, 15)
	cwt, ok := cwtRaw.(map[any]any)
	iss, hasIss := intKey(cwt, 1)
	sub, hasSub := intKey(cwt, 2)
	if !ok || !hasIss || !hasSub {
		return nil, malformed("protected header lacks CWT_Claims with iss and sub")
	}
	_, cp.crit = intKey(h, 2)
	cp.alg, cp.kid, cp.iss, cp.sub = alg, kid, iss, sub
	c, ok := claims.(map[any]any)
	if !ok {
		return nil, malformed("payload is not a claims map")
	}
	if c["kind"] != "cll-checkpoint" {
		return nil, malformed("kind claim is not cll-checkpoint")
	}
	logSize, ok1 := asUint(c["log_size"])
	prevSize, ok2 := asUint(c["prev_size"])
	if !ok1 || !ok2 || prevSize > logSize {
		return nil, malformed("log_size or prev_size is not a valid unsigned integer pair")
	}
	cp.logSize, cp.prevSize = logSize, prevSize
	issued, isString := c["issued_at"].(string)
	if _, ok := parseInstant(issued); !isString || !ok {
		return nil, malformed("issued_at is not an RFC 3339 text string")
	}
	cp.issuedAt = issued
	var err error
	if cp.commitment, err = peakList(c["commitment"]); err != nil {
		return nil, err
	}
	prev := c["prev_commitment"]
	if prevSize == 0 {
		if b, isBytes := prev.([]byte); !isBytes || len(b) != 0 {
			return nil, malformed("prev_size is 0 and prev_commitment is not zero-length")
		}
	} else if cp.prevCommitment, err = peakList(prev); err != nil {
		return nil, err
	}
	return cp, nil
}

// sigStructure is the Signature1 Sig_structure with an empty external AAD
// (RFC 9052 §4.4).
func sigStructure(protected, payload []byte) []byte {
	out, _ := deterministicCBOR.Marshal([]any{"Signature1", protected, []byte{}, payload})
	return out
}

func checkAnchorInclusion(env map[string]any, material [][]byte, prerequisites map[string]string, trust TrustPolicy, kindsImplemented []string) PropertyReport {
	subject, isMap := env["subject"].(map[string]any)
	_, hasRecord := subject["record"]
	// Step 1. Only the record subject with no derivation has a method in
	// this revision (P-13).
	if !isMap || len(subject) != 1 || !hasRecord || present(env, "derivation") {
		why := "the subject is not the record form"
		if present(env, "derivation") {
			why = "a derivation is present"
		}
		return inclusionReport(StatusNotChecked, "step 1: "+why+"; no kind in this revision defines a method (P-13)")
	}
	// Step 2.
	rawVerification, has := env["verification"]
	verification, isList := rawVerification.([]any)
	if !has || rawVerification == nil || (isList && len(verification) == 0) {
		return inclusionReport(StatusNotPresent, "step 2: the envelope carries no verification material")
	}
	if !isList {
		return inclusionReport(StatusNotChecked, "step 3: verification is not an array of entries")
	}
	// Step 3.
	kinds := make([]any, len(verification))
	for i, e := range verification {
		if m, ok := e.(map[string]any); ok {
			kinds[i] = m["kind"]
		}
	}
	for _, k := range kinds {
		s, ok := k.(string)
		if !ok || !slices.Contains(CLLKinds, s) || !slices.Contains(kindsImplemented, s) {
			return inclusionReport(StatusNotChecked, fmt.Sprintf("step 3: kind %s is not implemented (§6.2)", pyRepr(k)))
		}
	}
	count := func(kind string) int {
		n := 0
		for _, k := range kinds {
			if k == kind {
				n++
			}
		}
		return n
	}
	for _, k := range CLLKinds {
		if count(k) > 1 {
			return inclusionReport(StatusFail, "step 3: kind "+k+" appears more than once")
		}
	}
	for _, need := range []string{KindCLLCheckpoint, KindCLLInclusionProof} {
		if count(need) == 0 {
			return inclusionReport(StatusNotPresent, "step 3: no "+need+" entry")
		}
	}
	// Step 4. Material not bound to a verified envelope is never checked.
	var unverified []string
	for _, p := range []string{"envelope_signature", "artifact_digest", "verification_binding"} {
		if prerequisites[p] != StatusPass {
			unverified = append(unverified, p)
		}
	}
	if len(unverified) > 0 || material == nil || len(material) != len(verification) {
		named := strings.Join(unverified, ", ")
		if named == "" {
			named = "verification_binding"
		}
		return inclusionReport(StatusNotChecked, "step 4: "+named+" is not PASS")
	}
	// Step 5.
	artifactDigest := env["artifact_digest"]
	if !strictEqual(subject["record"], artifactDigest) {
		return inclusionReport(StatusNotChecked, "step 5: subject.record is not the artifact digest; outside the scope of the cll-* kinds (P-31)")
	}
	items := map[string][]byte{}
	var checkpointEntry map[string]any
	for i, k := range kinds {
		items[k.(string)] = material[i]
		if k == KindCLLCheckpoint {
			checkpointEntry = verification[i].(map[string]any)
		}
	}
	// Step 6.
	anchor, _ := env["anchor"].(map[string]any)
	if !strictEqual(checkpointEntry["digest"], anchor["digest"]) {
		return inclusionReport(StatusFail, "step 6: the cll-checkpoint entry's digest is not anchor.digest")
	}
	// Step 7.
	cp, err := decodeCLLCheckpoint(items[KindCLLCheckpoint])
	if err != nil {
		return inclusionReport(StatusFail, "step 7: "+err.Error())
	}
	// Step 8.
	if alg, ok := cp.alg.(int64); !ok || alg != -8 || cp.crit {
		return inclusionReport(StatusNotChecked, "step 8: only EdDSA (-8) checkpoint signatures with no crit are checked in this revision (P-31)")
	}
	// Step 9. The log key, as of the checkpoint's own issued_at.
	kid, ok := cp.kid.([]byte)
	if !ok || len(kid) != ed25519.PublicKeySize {
		return inclusionReport(StatusFail, "step 9: kid is not a 32-octet Ed25519 public key")
	}
	switch trust.acceptsLogKey(cp.iss, cp.sub, hex.EncodeToString(kid), cp.issuedAt) {
	case StatusFail:
		return inclusionReport(StatusFail, fmt.Sprintf("step 9: the trust policy does not accept this key for (iss %s, sub %s) as of the checkpoint's issued_at", pyRepr(cp.iss), pyRepr(cp.sub)))
	case StatusInconclusive:
		return inclusionReport(StatusInconclusive, "step 9: the trust policy cannot resolve the log key's status")
	}
	// Step 10.
	if len(cp.signature) != ed25519.SignatureSize || !ed25519.Verify(kid, sigStructure(cp.protected, cp.payload), cp.signature) {
		return inclusionReport(StatusFail, "step 10: the checkpoint's COSE_Sign1 signature does not verify")
	}
	// Step 11.
	if fresh, ok := anchor["freshness"]; ok {
		if n, isUint := uintMember(fresh); isUint {
			if n != cp.logSize {
				return inclusionReport(StatusFail, "step 11: anchor.freshness is not the checkpoint's log_size")
			}
		} else {
			at, _ := parseInstant(cp.issuedAt)
			if fresh != ProfileTime(at) {
				return inclusionReport(StatusFail, "step 11: anchor.freshness is not the checkpoint's issued_at")
			}
		}
	}
	// Step 12.
	if !isDigestValue(artifactDigest) {
		return inclusionReport(StatusFail, "step 12: artifact_digest is not a digest")
	}
	entry, _ := hex.DecodeString(artifactDigest.(string))
	if failure := inclusionFailure(cp.commitment, entry, items[KindCLLInclusionProof]); failure != "" {
		return inclusionReport(StatusFail, "step 12: "+failure)
	}
	method := "CLL-01 checkpoint (Ed25519) + MMR-02 inclusion"
	// Step 13.
	if consistency, ok := items[KindCLLConsistencyProof]; ok {
		failure := ""
		if cp.prevSize == 0 {
			failure = "prev_size is 0, so there is no earlier commitment to extend"
		} else {
			failure = consistencyFailure(cp.prevCommitment, cp.commitment, consistency)
		}
		if failure != "" {
			return inclusionReport(StatusFail, "step 13: "+failure)
		}
		method += " + MMR-02 consistency"
	}
	// Step 14.
	return report("anchor_inclusion", StatusPass, method, "steps 1 to 14")
}

// inclusionFailure is why cll-inclusion-proof octets do not prove entry a
// leaf whose path reaches one of peaks (§6.2.1 step 12), or "" when they
// do.
func inclusionFailure(peaks [][]byte, entry, octets []byte) string {
	if _, err := deterministicItem(octets, "inclusion proof"); err != nil {
		return err.Error()
	}
	if err := VerifyCLLInclusion(peaks, entry, octets); err != nil {
		return strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
	}
	return ""
}

// consistencyFailure is why cll-consistency-proof octets do not prove the
// commitment newPeaks extends oldPeaks (§6.2.1 step 13), or "" when they
// do.
func consistencyFailure(oldPeaks, newPeaks [][]byte, octets []byte) string {
	if _, err := deterministicItem(octets, "consistency proof"); err != nil {
		return err.Error()
	}
	if err := VerifyCLLConsistency(oldPeaks, newPeaks, octets); err != nil {
		return strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
	}
	return ""
}

// pyRepr writes a value as the reference verifier's details do.
func pyRepr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return "'" + x + "'"
	}
	return fmt.Sprint(v)
}
