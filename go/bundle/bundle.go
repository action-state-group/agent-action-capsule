// SPDX-License-Identifier: BSD-3-Clause
// Package bundle implements the AAC Evidence Bundle v2 codec and verifier.
package bundle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/disclosure"
	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/action-state-group/cll-go/checkpoint"
	"github.com/action-state-group/cll-go/mmr"
)

var (
	hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	b64url  = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
)

// ClaimResult reports one independent completeness claim.
type ClaimResult struct {
	Status   string
	Findings []string
}

// DisclosureResult reports one Bundle-level disclosure overlay member.
type DisclosureResult struct {
	CapsuleID string
	Member    string
	Status    string
}

// ExtensionResult reports an integrity-covered extension whose semantics were
// deliberately not interpreted by the neutral core.
type ExtensionResult struct {
	Kind             string
	Status           string
	IntegrityCovered bool
}

// CountersignatureResult makes the reserved countersignature slot explicit:
// this neutral verifier does not yet verify countersignatures.
type CountersignatureResult struct {
	Value  interface{}
	Status string
}

// ProducerSelfReport preserves the producer's verification member without
// treating it as independently verified evidence.
type ProducerSelfReport struct {
	Value  interface{}
	Status string
}

// VerificationResult is the structured result of VerifyBundle.
type VerificationResult struct {
	BundleDigest        *string
	GraphClosure        ClaimResult
	IntervalCoverage    ClaimResult
	PerRecordMembership ClaimResult
	Disclosures         []DisclosureResult
	Extensions          []ExtensionResult
	Countersignatures   []CountersignatureResult
	Verification        *ProducerSelfReport
	CapsuleResults      map[string]verify.VerificationResult
}

// EncodeFragment returns unpadded RFC 4648 base64url over UTF-8 JCS bytes.
func EncodeFragment(value interface{}) (string, error) {
	encoded, err := canonical.JCS(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// DecodeFragment decodes an unpadded Evidence Bundle URL fragment. It only
// decodes transport; VerifyBundle applies the Bundle semantic checks.
func DecodeFragment(fragment string) (interface{}, error) {
	if !b64url.MatchString(fragment) {
		return nil, fmt.Errorf("fragment must be unpadded base64url")
	}
	raw, err := base64.RawURLEncoding.DecodeString(fragment)
	if err != nil {
		return nil, fmt.Errorf("fragment is not UTF-8 JSON: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("fragment is not UTF-8 JSON: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("fragment is not UTF-8 JSON")
	}
	return value, nil
}

// BundleDigest returns SHA-256(JCS(bundle without countersignatures)).
func BundleDigest(value interface{}) (string, error) {
	bundle, ok := value.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("bundle must be a JSON object")
	}
	canonicalBundle := make(map[string]interface{}, len(bundle))
	for key, member := range bundle {
		if key != "countersignatures" {
			canonicalBundle[key] = member
		}
	}
	data, err := canonical.JCS(canonicalBundle)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyBundle checks the Bundle's independent claims using only its supplied
// evidence. Unknown extension blocks remain integrity-covered and uninterpreted.
func VerifyBundle(value interface{}) VerificationResult {
	invalid := ClaimResult{Status: "fail", Findings: []string{"bundle_malformed"}}
	bundle, ok := value.(map[string]interface{})
	if !ok {
		return VerificationResult{GraphClosure: invalid, IntervalCoverage: invalid, PerRecordMembership: invalid}
	}

	result := VerificationResult{CapsuleResults: make(map[string]verify.VerificationResult)}
	if digest, err := BundleDigest(bundle); err == nil {
		result.BundleDigest = &digest
	}
	records, recordFindings := records(bundle["records"], result.CapsuleResults)
	result.GraphClosure = graph(bundle, records, recordFindings)
	result.IntervalCoverage, result.PerRecordMembership = completeness(bundle, records)
	if raw, present := bundle["disclosures"]; present {
		result.Disclosures = disclosures(raw, records)
	} else {
		result.Disclosures = disclosures(map[string]interface{}{}, records)
	}
	result.Extensions = extensions(bundle["extensions"])
	if signatures, ok := bundle["countersignatures"].([]interface{}); ok {
		result.Countersignatures = make([]CountersignatureResult, len(signatures))
		for i, signature := range signatures {
			result.Countersignatures[i] = CountersignatureResult{Value: signature, Status: "unverified"}
		}
	}
	if report, ok := bundle["verification"]; ok {
		result.Verification = &ProducerSelfReport{Value: report, Status: "producer_self_report"}
	}
	return result
}

func records(raw interface{}, results map[string]verify.VerificationResult) (map[string]map[string]interface{}, []string) {
	records := make(map[string]map[string]interface{})
	list, ok := raw.([]interface{})
	if !ok {
		return records, []string{"records_malformed"}
	}
	var findings []string
	for index, rawRecord := range list {
		record, ok := rawRecord.(map[string]interface{})
		if !ok {
			findings = append(findings, fmt.Sprintf("record_malformed:%d", index))
			continue
		}
		id, ok := record["capsule_id"].(string)
		if !ok || !hex64RE.MatchString(id) {
			findings = append(findings, fmt.Sprintf("record_identity_invalid:%d", index))
			continue
		}
		if _, duplicate := records[id]; duplicate {
			findings = append(findings, "record_duplicate:"+id)
			continue
		}
		verification := verify.Verify(record, nil, nil)
		results[id] = verification
		if !verification.OK || verification.CapsuleID == nil || *verification.CapsuleID != id {
			findings = append(findings, "record_identity_invalid:"+id)
			continue
		}
		records[id] = record
	}
	return records, findings
}

func graph(bundle map[string]interface{}, records map[string]map[string]interface{}, recordFindings []string) ClaimResult {
	findings := append([]string(nil), recordFindings...)
	if bundle["bundle_version"] != "2" || bundle["bundle_kind"] != "evidence-bundle/v2" {
		findings = append(findings, "bundle_version_or_kind_invalid")
	}
	root, ok := bundle["root"].(string)
	if !ok || records[root] == nil {
		return ClaimResult{Status: "fail", Findings: append(findings, "root_not_supplied_with_matching_identity")}
	}
	complete, ok := bundle["completeness"].(map[string]interface{})
	if !ok {
		return ClaimResult{Status: "fail", Findings: append(findings, "completeness_malformed")}
	}
	depthValue, present := complete["closure_depth"]
	if !present {
		depthValue = 2
	}
	depth, ok := integer(depthValue)
	if !ok || depth < 0 {
		return ClaimResult{Status: "fail", Findings: append(findings, "closure_depth_invalid")}
	}
	missingValue, present := complete["missing"]
	if !present {
		missingValue = []interface{}{}
	}
	missingList, ok := missingValue.([]interface{})
	if !ok {
		return ClaimResult{Status: "fail", Findings: append(findings, "missing_malformed")}
	}
	missing := make(map[string]bool, len(missingList))
	for _, item := range missingList {
		id, valid := item.(string)
		if !valid || !hex64RE.MatchString(id) {
			return ClaimResult{Status: "fail", Findings: append(findings, "missing_malformed")}
		}
		if missing[id] {
			findings = append(findings, "missing_duplicate")
		}
		missing[id] = true
	}
	expectedMode := "complete"
	if len(missing) != 0 {
		expectedMode = "declared_incomplete"
	}
	if complete["records_mode"] != expectedMode {
		findings = append(findings, "records_mode_mismatch")
	}
	frontier := []string{root}
	for i := int64(0); i < depth; i++ {
		var next []string
		for _, sourceID := range frontier {
			for _, target := range citationTargets(records[sourceID]) {
				if records[target] != nil {
					next = append(next, target)
				} else if !missing[target] {
					findings = append(findings, "citation_dangling:"+target)
				}
			}
		}
		frontier = next
	}
	if len(findings) != 0 {
		return ClaimResult{Status: "fail", Findings: findings}
	}
	if len(missing) != 0 {
		return ClaimResult{Status: "withheld", Findings: []string{"declared_incomplete"}}
	}
	return ClaimResult{Status: "pass"}
}

func citationTargets(record map[string]interface{}) []string {
	var targets []string
	if chain, ok := record["chain"].(map[string]interface{}); ok {
		if parent, ok := chain["parent_capsule_id"].(string); ok {
			targets = append(targets, parent)
		}
	}
	if references, ok := record["references"].([]interface{}); ok {
		for _, raw := range references {
			if reference, ok := raw.(map[string]interface{}); ok && reference["type"] == "agent-action-capsule" && reference["digest_alg"] == "SHA-256" {
				if digest, ok := reference["digest"].(string); ok {
					targets = append(targets, digest)
				}
			}
		}
	}
	return targets
}

func completeness(bundle map[string]interface{}, records map[string]map[string]interface{}) (ClaimResult, ClaimResult) {
	certificate, certificateOK := bundle["completeness_certificate"].(map[string]interface{})
	checkpoint, checkpointOK := bundle["checkpoint"].(map[string]interface{})
	if !certificateOK || !checkpointOK {
		absent := ClaimResult{Status: "withheld", Findings: []string{"completeness_evidence_absent"}}
		return absent, absent
	}
	root, logID, first, last, rangeProof, ok := certificateData(certificate, checkpoint)
	if !ok {
		failure := ClaimResult{Status: "fail", Findings: []string{"completeness_certificate_invalid"}}
		return failure, failure
	}
	if !verifyRange(root, first, last, certificate, rangeProof) {
		failure := ClaimResult{Status: "fail", Findings: []string{"range_proof_invalid"}}
		return failure, failure
	}
	authentication := authenticateCheckpoint(checkpoint, logID, root, rangeProof.Size)
	if authentication == "invalid" {
		failure := ClaimResult{Status: "fail", Findings: []string{"checkpoint_authentication_invalid"}}
		return failure, failure
	}
	findings := verifyMemberships(root, logID, first, last, certificate["memberships"], records, bundle["completeness"])
	interval := ClaimResult{Status: "pass"}
	if authentication != "verified" {
		interval.Findings = []string{"checkpoint_unverified"}
	}
	if len(findings) != 0 {
		return interval, ClaimResult{Status: "fail", Findings: findings}
	}
	membership := ClaimResult{Status: "pass"}
	if authentication != "verified" {
		membership.Findings = []string{"checkpoint_unverified"}
	}
	return interval, membership
}

func authenticateCheckpoint(checkpointValue map[string]interface{}, logID string, root []byte, size uint64) string {
	raw, present := checkpointValue["cose"]
	if !present {
		return "unverified"
	}
	encoded, ok := raw.(string)
	if !ok || !b64url.MatchString(encoded) {
		return "invalid"
	}
	cose, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "invalid"
	}
	record, err := checkpoint.ParseRecord(cose)
	if err != nil || record.VerifySignature() != nil {
		return "invalid"
	}
	payload := record.Payload()
	if payload.LogID != logID || payload.MMRSize != size || payload.Root != hex.EncodeToString(root) {
		return "invalid"
	}
	return "verified"
}

func certificateData(certificate, checkpoint map[string]interface{}) ([]byte, string, int64, int64, rangeProof, bool) {
	logID, logOK := certificate["log_id"].(string)
	rootHex, rootOK := certificate["range_root"].(string)
	first, firstOK := integer(certificate["first_seq"])
	last, lastOK := integer(certificate["last_seq"])
	if !logOK || !rootOK || !firstOK || !lastOK || first < 1 || last < first || checkpoint["root"] != rootHex {
		return nil, "", 0, 0, rangeProof{}, false
	}
	root, err := hex.DecodeString(rootHex)
	proof, errProof := parseRangeProof(certificate["range_proof"])
	checkpointSize, checkpointSizeOK := integer(checkpoint["mmr_size"])
	if err != nil || errProof != nil || len(root) != sha256.Size || !checkpointSizeOK || checkpointSize < 0 || uint64(checkpointSize) != proof.Size {
		return nil, "", 0, 0, rangeProof{}, false
	}
	return root, logID, first, last, proof, true
}

type rangeProof struct {
	FromSeq, ToSeq int64
	Size           uint64
	Proof          mmr.RangeProof
}

// verifyRange checks CLL #13 per-record range membership: every leaf in
// [first, last] participates (via the ordered body_digests plus the flat
// witness), so an altered/deleted/replaced interior leaf is caught here, not
// only at the two endpoints.
func verifyRange(root []byte, first, last int64, certificate map[string]interface{}, proof rangeProof) bool {
	if proof.FromSeq != first || proof.ToSeq != last ||
		proof.Proof.FromIndex != uint64(first-1) || proof.Proof.ToIndex != uint64(last-1) {
		return false
	}
	// The interval must end at the checkpointed tip: leaf_count(size) == last.
	// CLL's index-level verify_range enforces this (the Python bundle verifier
	// uses it); the core verify_range does not, so bind it here — otherwise a
	// sub-tip range would let records after `last` be silently omitted.
	if leaves, okLeaves := mmr.LeafCount(proof.Size); !okLeaves || leaves != uint64(last) {
		return false
	}
	raw, ok := certificate["body_digests"].([]interface{})
	if !ok || int64(len(raw)) != last-first+1 {
		return false
	}
	bodyDigests, err := hashes(certificate["body_digests"])
	if err != nil {
		return false
	}
	return mmr.VerifyRange(root, proof.Size, proof.Proof.FromIndex, proof.Proof.ToIndex, bodyDigests, proof.Proof)
}

func verifyMemberships(root []byte, logID string, first, last int64, raw interface{}, records map[string]map[string]interface{}, completeness interface{}) []string {
	members, ok := raw.(map[string]interface{})
	if !ok {
		return []string{"memberships_absent"}
	}
	bySeq := make(map[int64]string)
	boundRecords := make(map[string]bool)
	var findings []string
	for id, rawMember := range members {
		record := records[id]
		member, memberOK := rawMember.(map[string]interface{})
		if !hex64RE.MatchString(id) || record == nil || !memberOK {
			findings = append(findings, "membership_record_unknown:"+id)
			continue
		}
		coordinates, coordinatesOK := member["log_coordinates"].(map[string]interface{})
		if !coordinatesOK {
			findings = append(findings, "membership_coordinates_missing:"+id)
			continue
		}
		seq, seqOK := integer(coordinates["seq"])
		leaf, leafOK := integer(coordinates["leaf_index"])
		if coordinates["log_id"] != logID || !seqOK || !leafOK || seq < first || seq > last || leaf != seq-1 {
			findings = append(findings, "membership_coordinates_invalid:"+id)
			continue
		}
		if _, duplicate := bySeq[seq]; duplicate {
			findings = append(findings, fmt.Sprintf("membership_seq_duplicate:%d", seq))
			continue
		}
		bySeq[seq] = id
		boundRecords[id] = true
		proof, err := parseInclusionProof(member["inclusion_proof"])
		if err != nil || !mmr.VerifyHexInclusion(root, proof.Size, uint64(leaf), id, proof) {
			findings = append(findings, "membership_proof_invalid:"+id)
		}
	}
	for seq := first; seq <= last; seq++ {
		if _, ok := bySeq[seq]; !ok {
			findings = append(findings, fmt.Sprintf("membership_record_missing:%d", seq))
		}
	}
	declaredMissing := make(map[string]bool)
	if complete, ok := completeness.(map[string]interface{}); ok {
		if missing, ok := complete["missing"].([]interface{}); ok {
			for _, value := range missing {
				if id, ok := value.(string); ok {
					declaredMissing[id] = true
				}
			}
		}
	}
	for id := range records {
		if !boundRecords[id] && !declaredMissing[id] {
			findings = append(findings, "membership_record_unbound:"+id)
		}
	}
	return findings
}

func parseRangeProof(raw interface{}) (rangeProof, error) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return rangeProof{}, fmt.Errorf("range proof must be an object")
	}
	fromSeq, fromOK := integer(m["from_seq"])
	toSeq, toOK := integer(m["to_seq"])
	size, sizeOK := integer(m["size"])
	fromIndex, fiOK := integer(m["from_index"])
	toIndex, tiOK := integer(m["to_index"])
	witness, werr := hashes(m["witness"])
	if !fromOK || !toOK || !sizeOK || !fiOK || !tiOK || fromSeq < 1 || toSeq < fromSeq ||
		size < 0 || fromIndex < 0 || toIndex < fromIndex || werr != nil {
		return rangeProof{}, fmt.Errorf("invalid range proof")
	}
	// The cert carries the index-shaped range proof (no v/kind); construct the
	// core mmr.RangeProof (v=1, kind="range") the verifier consumes.
	return rangeProof{
		FromSeq: fromSeq, ToSeq: toSeq, Size: uint64(size),
		Proof: mmr.RangeProof{V: 1, Kind: "range", Size: uint64(size), FromIndex: uint64(fromIndex), ToIndex: uint64(toIndex), Witness: witness},
	}, nil
}

func parseInclusionProof(raw interface{}) (mmr.InclusionProof, error) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return mmr.InclusionProof{}, fmt.Errorf("inclusion proof must be an object")
	}
	v, vok := integer(m["v"])
	size, sok := integer(m["size"])
	index, iok := integer(m["leaf_index"])
	kind, kok := m["kind"].(string)
	witness, werr := hashes(m["witness"])
	left, lerr := hashes(m["peaks_left"])
	right, rerr := hashes(m["peaks_right"])
	if !vok || !sok || !iok || !kok || v != 1 || kind != "inclusion" || size < 0 || index < 0 || werr != nil || lerr != nil || rerr != nil {
		return mmr.InclusionProof{}, fmt.Errorf("invalid inclusion proof")
	}
	return mmr.InclusionProof{V: uint64(v), Kind: kind, Size: uint64(size), LeafIndex: uint64(index), Witness: witness, PeaksLeft: left, PeaksRight: right}, nil
}

func hashes(raw interface{}) ([][]byte, error) {
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("hash list must be an array")
	}
	result := make([][]byte, len(list))
	for i, rawHash := range list {
		encoded, ok := rawHash.(string)
		if !ok {
			return nil, fmt.Errorf("hash must be a string")
		}
		decoded, err := hex.DecodeString(encoded)
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("invalid hash")
		}
		result[i] = decoded
	}
	return result, nil
}

func disclosures(raw interface{}, records map[string]map[string]interface{}) []DisclosureResult {
	overlay, ok := raw.(map[string]interface{})
	if !ok {
		return []DisclosureResult{{Status: disclosure.Mismatch}}
	}
	var result []DisclosureResult
	ids := sortedRecordIDs(records)
	for _, id := range ids {
		rawSupplied, present := overlay[id]
		supplied, suppliedOK := rawSupplied.(map[string]interface{})
		if present && !suppliedOK {
			continue
		}
		if !present {
			supplied = map[string]interface{}{}
		}
		for member, path := range registries.DisclosureEligibleFields {
			if _, exists := supplied[member]; !exists {
				if _, committed := committedDigest(records[id], path); committed {
					result = append(result, DisclosureResult{CapsuleID: id, Member: member, Status: "withheld"})
				}
			}
		}
	}
	keys := make([]string, 0, len(overlay))
	for id := range overlay {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		members, membersOK := overlay[id].(map[string]interface{})
		record := records[id]
		if !membersOK || record == nil {
			result = append(result, DisclosureResult{CapsuleID: id, Status: disclosure.Mismatch})
			continue
		}
		memberNames := make([]string, 0, len(members))
		for member := range members {
			memberNames = append(memberNames, member)
		}
		sort.Strings(memberNames)
		for _, member := range memberNames {
			path, eligible := registries.DisclosureEligibleFields[member]
			if !eligible {
				result = append(result, DisclosureResult{id, member, disclosure.Ineligible})
				continue
			}
			stored, committed := committedDigest(record, path)
			if !committed || !hex64RE.MatchString(stored) {
				result = append(result, DisclosureResult{id, member, disclosure.NoCommittedDigest})
				continue
			}
			computed, err := canonical.JSONDigest(members[member])
			status := disclosure.Mismatch
			if err == nil && computed == stored {
				status = disclosure.Match
			}
			result = append(result, DisclosureResult{id, member, status})
		}
	}
	return result
}

func committedDigest(value map[string]interface{}, path string) (string, bool) {
	current := value
	parts := strings.Split(path, ".")
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]interface{})
		if !ok {
			return "", false
		}
		current = next
	}
	digest, ok := current[parts[len(parts)-1]].(string)
	return digest, ok
}
func sortedRecordIDs(records map[string]map[string]interface{}) []string {
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
func extensions(raw interface{}) []ExtensionResult {
	values, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	kinds := make([]string, 0, len(values))
	for kind := range values {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	result := make([]ExtensionResult, len(kinds))
	for i, kind := range kinds {
		result[i] = ExtensionResult{Kind: kind, Status: "uninterpreted", IntegrityCovered: true}
	}
	return result
}
func integer(value interface{}) (int64, bool) {
	// Native numeric inputs must reject values outside ±MaxSafeInteger just as the
	// json.Number path does, so a natively-constructed bundle cannot be accepted
	// with an integer that the JSON wire form (and the Python/TS verifiers) reject.
	safe := func(v int64) (int64, bool) {
		if v > canonical.MaxSafeInteger || v < -canonical.MaxSafeInteger {
			return 0, false
		}
		return v, true
	}
	switch value := value.(type) {
	case json.Number:
		if canonical.IsFloat(value) || canonical.IsUnsafeInt(value) {
			return 0, false
		}
		parsed, err := value.Int64()
		if err != nil {
			return 0, false
		}
		return parsed, true
	case int:
		return safe(int64(value))
	case int8:
		return safe(int64(value))
	case int16:
		return safe(int64(value))
	case int32:
		return safe(int64(value))
	case int64:
		return safe(value)
	case uint:
		if uint64(value) > math.MaxInt64 {
			return 0, false
		}
		return safe(int64(value))
	case uint8:
		return safe(int64(value))
	case uint16:
		return safe(int64(value))
	case uint32:
		return safe(int64(value))
	case uint64:
		if value > math.MaxInt64 {
			return 0, false
		}
		return safe(int64(value))
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < math.MinInt64 || value > math.MaxInt64 {
			return 0, false
		}
		return safe(int64(value))
	default:
		return 0, false
	}
}
