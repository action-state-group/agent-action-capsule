// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/disclosure"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/action-state-group/agent-action-capsule/go/witness"
	"github.com/action-state-group/checkpointed-local-log/go/mmr"
)

// SelectionProducerSelected is completeness.selection of a producer-selected
// Bundle: records the producer picked from its log, each proven on its own,
// with no claim about the records between them (Bundle -02).
const SelectionProducerSelected = "producer-selected"

// CertificateModeUnsupported is the finding for a completeness.selection value
// naming a certificate mode this verifier does not implement (Bundle -02):
// interval coverage and per-record membership are withheld, never failed.
const CertificateModeUnsupported = "certificate_mode_unsupported"

// Strict-mode verdicts.
const (
	VerdictValid      = "VALID"
	VerdictIncomplete = "INCOMPLETE"
	VerdictInvalid    = "INVALID"
)

const bundleKind = "evidence-bundle/v2"

// StrictOptions configures VerifyStrict.
type StrictOptions struct {
	// RequireSignature makes an unsigned record fail the signatures claim
	// instead of withholding it.
	RequireSignature bool
	// WitnessDirectory supplies the witness keys; nil trusts no witness.
	WitnessDirectory *witness.Directory
	// Options are the plain verifier's deployment options.
	Options Options
}

// NamedClaim is one strict-mode claim in report order.
type NamedClaim struct {
	Name string
	ClaimResult
}

// RecordResult is one object of the Bundle's records list in strict mode.
// Signature is envelope.Authored, Unclaimed or Invalid; KeyID is the record's
// key_id when it is a string; Seq is the record's log position as its
// membership states it.
type RecordResult struct {
	CapsuleID  string
	IdentityOK bool
	Signature  string
	KeyID      *string
	Seq        *int64
	Messages   []string
}

// StrictResult is the result of VerifyStrict. The embedded VerificationResult
// is the plain verifier's, except that IntervalCoverage and
// PerRecordMembership hold the strict readings.
type StrictResult struct {
	VerificationResult
	// KindOK is false for a value that is not an evidence-bundle/v2 object;
	// its only claim is records (not_an_evidence_bundle_v2).
	KindOK bool
	// Claims are the gating claims in report order: records, signatures,
	// graph_closure, checkpoint, interval_coverage, per_record_membership,
	// then disclosures when the Bundle carries a disclosures member.
	Claims []NamedClaim
	// Witnesses is reported beside the claims and gates only when it fails;
	// nil when the kind check failed.
	Witnesses       *ClaimResult
	WitnessReceipts []witness.ReceiptResult
	Records         []RecordResult
	// SignedCheckpoint is the checkpoint as its COSE statement states it,
	// when the checkpoint claim passed (the checkpoint is authenticated).
	SignedCheckpoint *witness.SignedCheckpoint
	// SignerMatchesCheckpoint states, for an authenticated checkpoint and at
	// least one record, whether every record's key_id is the checkpoint's
	// key_id. It is reported and never gates.
	SignerMatchesCheckpoint *bool
	// Verdict is VALID when every claim passed, INVALID when a claim, the
	// witnesses or a gating category_coverage property failed, and
	// INCOMPLETE otherwise.
	Verdict string
}

// Claim returns the named claim, or nil.
func (r StrictResult) Claim(name string) *ClaimResult {
	for i := range r.Claims {
		if r.Claims[i].Name == name {
			return &r.Claims[i].ClaimResult
		}
	}
	return nil
}

// VerifyStrict runs VerifyBundleWithOptions and adds the checks a verifier
// handing a verdict to a person needs (vectors/bundle/strict/README.md):
//
//   - each record's producer signature (signatures; an unsigned record is
//     withheld unless RequireSignature);
//   - the checkpoint read only from its signed COSE form (checkpoint):
//     withheld without one, fail when it does not verify or the JSON copy,
//     or the completeness certificate's log_id, differs from it. Without a
//     signed checkpoint the interval and membership claims are not shown, so
//     the Bundle is never VALID;
//   - a producer-selected Bundle (completeness.selection producer-selected):
//     interval coverage is withheld and each record's own inclusion proof is
//     checked against the signed checkpoint;
//   - a category_coverage member: a FAIL of its form, signature or
//     consistency makes the verdict INVALID;
//   - the disclosures overlay as one claim, when the Bundle carries one;
//   - the witness receipts in checkpoint.witnesses under the keys of
//     WitnessDirectory.
func VerifyStrict(value interface{}, opts StrictOptions) StrictResult {
	// A value nested more than canonical.MaxNestingDepth levels deep is
	// refused before any recursive check runs: bundle_malformed on every claim, as the plain verifier reports a
	// value that is not a Bundle.
	if canonical.TooDeep(value) {
		malformed := ClaimResult{Status: "fail", Findings: []string{"bundle_malformed"}}
		return StrictResult{
			VerificationResult: VerificationResult{GraphClosure: malformed, IntervalCoverage: malformed, PerRecordMembership: malformed},
			Claims:             []NamedClaim{{"records", malformed}},
			Verdict:            VerdictInvalid,
		}
	}
	result := StrictResult{VerificationResult: VerifyBundleWithOptions(value, opts.Options)}
	bundle, isObject := value.(map[string]interface{})
	if !isObject || bundle["bundle_kind"] != bundleKind || bundle["bundle_version"] != "2" {
		result.Claims = []NamedClaim{{"records", ClaimResult{Status: "fail", Findings: []string{"not_an_evidence_bundle_v2"}}}}
		result.Verdict = VerdictInvalid
		return result
	}
	result.KindOK = true

	rawRecords, _ := bundle["records"].([]interface{})
	seqs := membershipSeqs(bundle)
	seen := map[string]bool{}
	for _, raw := range rawRecords {
		record, isObject := raw.(map[string]interface{})
		if !isObject {
			continue
		}
		id, _ := record["capsule_id"].(string)
		verdict, messages := envelope.VerifyRecordSignature(record)
		// A repeated capsule_id is a second record the plain verifier skipped.
		plain, verified := result.CapsuleResults[id]
		verified = verified && !seen[id]
		seen[id] = true
		entry := RecordResult{
			CapsuleID:  id,
			IdentityOK: verified && plain.OK && plain.CapsuleID != nil && *plain.CapsuleID == id,
			Signature:  verdict,
			Messages:   messages,
		}
		if keyID, isString := record["key_id"].(string); isString {
			entry.KeyID = &keyID
		}
		if seq, found := seqs[id]; found {
			entry.Seq = &seq
		}
		result.Records = append(result.Records, entry)
	}
	records := ClaimResult{Status: "pass"}
	for _, record := range result.Records {
		if !record.IdentityOK {
			records.Findings = append(records.Findings, "record_identity_invalid:"+record.CapsuleID)
		}
	}
	if len(result.Records) == 0 {
		records.Findings = []string{"no_records"}
	}
	if len(records.Findings) != 0 {
		records.Status = "fail"
	}

	signatures := ClaimResult{}
	var invalid, unclaimed int
	for _, record := range result.Records {
		if record.Signature == envelope.Invalid {
			invalid++
			signatures.Findings = append(signatures.Findings, "producer_signature_invalid:"+record.CapsuleID)
		}
	}
	for _, record := range result.Records {
		if record.Signature == envelope.Unclaimed {
			unclaimed++
			signatures.Findings = append(signatures.Findings, "producer_signature_unclaimed:"+record.CapsuleID)
		}
	}
	switch {
	case invalid != 0 || (unclaimed != 0 && opts.RequireSignature) || len(result.Records) == 0:
		signatures.Status = "fail"
	case unclaimed != 0:
		signatures.Status = "withheld"
	default:
		signatures.Status = "pass"
	}

	stated, _ := bundle["checkpoint"].(map[string]interface{})
	checkpointClaim, signed, cose := VerifyCheckpoint(bundle)
	authenticated := checkpointClaim.Status == "pass"

	if complete, _ := bundle["completeness"].(map[string]interface{}); complete["selection"] == SelectionProducerSelected {
		// The certificate binds the producer's selection, not an interval: the
		// interval proof cannot be read, each record's own proof still can.
		result.IntervalCoverage = ClaimResult{Status: "withheld", Findings: []string{"selection_not_checkable"}}
		if authenticated {
			result.PerRecordMembership = selectedMembership(bundle, signed.Root, signed.MMRSize, signed.LogID)
		}
		// Otherwise the plain reading stands: each proof against the stated
		// checkpoint, withheld below unless it failed, as for a range Bundle.
	}
	if !authenticated {
		result.IntervalCoverage = unanchored(result.IntervalCoverage)
		result.PerRecordMembership = unanchored(result.PerRecordMembership)
	}

	result.Claims = []NamedClaim{
		{"records", records},
		{"signatures", signatures},
		{"graph_closure", result.GraphClosure},
		{"checkpoint", checkpointClaim},
		{"interval_coverage", result.IntervalCoverage},
		{"per_record_membership", result.PerRecordMembership},
	}
	if _, present := bundle["disclosures"]; present {
		claim := ClaimResult{Status: "pass"}
		for _, d := range result.Disclosures {
			if d.Status != disclosure.Match && d.Status != "withheld" {
				claim.Findings = append(claim.Findings, d.Status+":"+d.CapsuleID+":"+d.Member)
			}
		}
		if len(claim.Findings) != 0 {
			claim.Status = "fail"
		}
		result.Claims = append(result.Claims, NamedClaim{"disclosures", claim})
	}

	var directory witness.Directory
	if opts.WitnessDirectory != nil {
		directory = *opts.WitnessDirectory
	}
	var anchor *witness.SignedCheckpoint
	if authenticated {
		anchor = signed
	} else {
		cose = nil
	}
	status, findings, receipts := witness.VerifyReceipts(stated["witnesses"], anchor, cose, directory)
	result.Witnesses = &ClaimResult{Status: status, Findings: findings}
	result.WitnessReceipts = receipts

	if authenticated {
		result.SignedCheckpoint = signed
		if signed.KeyID != "" && len(result.Records) != 0 {
			matches := true
			for _, record := range result.Records {
				if record.KeyID == nil || *record.KeyID != signed.KeyID {
					matches = false
				}
			}
			result.SignerMatchesCheckpoint = &matches
		}
	}
	result.Verdict = strictVerdict(result.Claims, *result.Witnesses)
	if coverageFails(result.CategoryCoverage) {
		result.Verdict = VerdictInvalid
	}
	return result
}

func strictVerdict(claims []NamedClaim, witnesses ClaimResult) string {
	verdict := VerdictValid
	for _, claim := range claims {
		switch claim.Status {
		case "fail":
			return VerdictInvalid
		case "pass":
		default:
			verdict = VerdictIncomplete
		}
	}
	if witnesses.Status == "fail" {
		return VerdictInvalid
	}
	return verdict
}

// VerifyCheckpoint is VerifyStrict's checkpoint claim on its own: it verifies
// the Bundle's checkpoint.cose and holds the JSON copy, and the completeness
// certificate's log_id when stated, to the signed statement. It returns the
// claim and, when it passed, the signed fields and the COSE bytes, for a
// caller that checks something further against the authenticated
// checkpoint. As for VerifyStrict, the Bundle must be decoded with
// json.Decoder.UseNumber: a float64 never equals a signed integer, so a
// Bundle decoded without it fails on mmr_size.
func VerifyCheckpoint(bundle map[string]interface{}) (ClaimResult, *witness.SignedCheckpoint, []byte) {
	stated, _ := bundle["checkpoint"].(map[string]interface{})
	encodedValue := stated["cose"]
	if encodedValue == nil {
		return ClaimResult{Status: "withheld", Findings: []string{"checkpoint_signature_absent"}}, nil, nil
	}
	encoded, isString := encodedValue.(string)
	if !isString || !b64url.MatchString(encoded) {
		return ClaimResult{Status: "fail", Findings: []string{"checkpoint_signature_malformed"}}, nil, nil
	}
	cose, err := strictB64URL.DecodeString(encoded)
	if err != nil {
		return ClaimResult{Status: "fail", Findings: []string{"checkpoint_signature_malformed"}}, nil, nil
	}
	signed, err := witness.ParseSignedCheckpoint(cose)
	if err != nil {
		return ClaimResult{Status: "fail", Findings: []string{"checkpoint_signature_invalid"}}, nil, nil
	}
	fields := []struct {
		name string
		same func(interface{}) bool
	}{
		{"log_id", sameString(signed.LogID)},
		{"mmr_size", sameInteger(signed.MMRSize)},
		{"root", sameString(signed.Root)},
		{"key_id", sameString(signed.KeyID)},
		{"timestamp", sameString(signed.Timestamp)},
		{"prev_size", sameInteger(signed.PrevSize)},
		{"prev_root", sameString(signed.PrevRoot)},
	}
	// The certificate's log_id is a second stated copy of the signed one
	// (bundle -01 §Completeness): either copy differing is one mismatch.
	certificate, _ := bundle["completeness_certificate"].(map[string]interface{})
	certificateLogID, certificateStates := certificate["log_id"]
	var findings []string
	for _, field := range fields {
		value, present := stated[field.name]
		mismatch := present && !field.same(value)
		if field.name == "log_id" && certificateStates && !field.same(certificateLogID) {
			mismatch = true
		}
		if mismatch {
			findings = append(findings, "checkpoint_field_mismatch:"+field.name)
		}
	}
	for _, name := range []string{"log_id", "mmr_size", "root"} {
		if _, present := stated[name]; !present {
			findings = append(findings, "checkpoint_field_missing:"+name)
		}
	}
	if len(findings) != 0 {
		return ClaimResult{Status: "fail", Findings: findings}, nil, nil
	}
	return ClaimResult{Status: "pass"}, &signed, cose
}

func sameString(want string) func(interface{}) bool {
	return func(value interface{}) bool {
		text, isString := value.(string)
		return isString && text == want
	}
}

// sameInteger holds JSON types apart: only an integer equals the signed
// integer, never a boolean, a float or a string. A json.Number with a
// fraction or an exponent ("0.0", "0e0") is a float, and so is any Go float:
// encoding/json without UseNumber decodes every number, 0 and 0.0 alike, to
// float64, which cannot tell them apart, so such a copy never matches.
func sameInteger(want uint64) func(interface{}) bool {
	return func(value interface{}) bool {
		switch number := value.(type) {
		case json.Number:
			if canonical.IsFloat(number) {
				return false
			}
			parsed, ok := new(big.Int).SetString(number.String(), 10)
			return ok && parsed.Cmp(new(big.Int).SetUint64(want)) == 0
		case float32, float64:
			return false
		}
		parsed, ok := integer(value)
		return ok && parsed >= 0 && uint64(parsed) == want
	}
}

// unanchored is a proof claim with no signed checkpoint behind it: a failure
// stays a failure; anything else is not shown.
func unanchored(claim ClaimResult) ClaimResult {
	if claim.Status == "fail" {
		return claim
	}
	findings := append([]string(nil), claim.Findings...)
	present := false
	for _, finding := range findings {
		present = present || finding == "checkpoint_unverified"
	}
	if !present {
		findings = append(findings, "checkpoint_unverified")
	}
	return ClaimResult{Status: "withheld", Findings: findings}
}

// selectedMembership checks each record's inclusion proof against rootHex
// and size, for a producer-selected Bundle. A non_record_leaves member makes
// the certificate invalid: with no range there is no interval for it to
// cover.
func selectedMembership(bundle map[string]interface{}, rootHex, sizeValue, logID interface{}) ClaimResult {
	invalid := ClaimResult{Status: "fail", Findings: []string{"completeness_certificate_invalid"}}
	certificate, _ := bundle["completeness_certificate"].(map[string]interface{})
	members, isObject := certificate["memberships"].(map[string]interface{})
	_, carriesLeaves := certificate["non_record_leaves"]
	rootText, rootOK := rootHex.(string)
	logText, logOK := logID.(string)
	size, sizeOK := integer(sizeValue)
	if !isObject || carriesLeaves || !logOK || !rootOK || certificate["range_root"] != rootText ||
		certificate["log_id"] != logText || !hex64RE.MatchString(rootText) || !sizeOK {
		return invalid
	}
	root, _ := hex.DecodeString(rootText)
	rawRecords, _ := bundle["records"].([]interface{})
	var ids []string
	inBundle := map[string]bool{}
	for _, raw := range rawRecords {
		if record, isObject := raw.(map[string]interface{}); isObject {
			id, _ := record["capsule_id"].(string)
			ids = append(ids, id)
			inBundle[id] = true
		}
	}
	var findings []string
	seen := map[int64]bool{}
	for _, id := range ids {
		member, _ := members[id].(map[string]interface{})
		coordinates, isObject := member["log_coordinates"].(map[string]interface{})
		if !isObject {
			findings = append(findings, "membership_record_unbound:"+id)
			continue
		}
		seq, seqOK := integer(coordinates["seq"])
		index, indexOK := integer(coordinates["leaf_index"])
		if coordinates["log_id"] != logText || !seqOK || !indexOK || seq < 1 || index != seq-1 || seen[seq] {
			findings = append(findings, "membership_coordinates_invalid:"+id)
			continue
		}
		seen[seq] = true
		proof, err := parseInclusionProof(member["inclusion_proof"])
		if err != nil || size < 0 || proof.Size != uint64(size) || !mmr.VerifyHexInclusion(root, proof.Size, uint64(index), id, proof) {
			findings = append(findings, "membership_proof_invalid:"+id)
		}
	}
	unknown := make([]string, 0, len(members))
	for id := range members {
		if !inBundle[id] {
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown)
	for _, id := range unknown {
		findings = append(findings, "membership_record_unknown:"+id)
	}
	if len(findings) != 0 {
		return ClaimResult{Status: "fail", Findings: findings}
	}
	return ClaimResult{Status: "pass"}
}

// membershipSeqs maps each Capsule ID to its membership's log_coordinates.seq.
func membershipSeqs(bundle map[string]interface{}) map[string]int64 {
	out := map[string]int64{}
	certificate, _ := bundle["completeness_certificate"].(map[string]interface{})
	members, _ := certificate["memberships"].(map[string]interface{})
	for id, raw := range members {
		member, _ := raw.(map[string]interface{})
		coordinates, _ := member["log_coordinates"].(map[string]interface{})
		if seq, ok := integer(coordinates["seq"]); ok {
			out[id] = seq
		}
	}
	return out
}
