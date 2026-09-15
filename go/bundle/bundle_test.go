// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/cll-go/mmr"
	"github.com/stretchr/testify/require"
)

// testdata/vectors.json is a pinned copy of vectors/bundle/vectors.json.
// The source manifest records the shared six-case outcome matrix; the Go test
// constructs its portable proof material exactly as the Python reference does.
func TestBundleVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	require.NoError(t, err)
	var manifest struct {
		Count int `json:"count"`
		Cases []struct {
			Name     string `json:"name"`
			Expected struct {
				GraphClosure        string    `json:"graph_closure"`
				IntervalCoverage    string    `json:"interval_coverage"`
				PerRecordMembership string    `json:"per_record_membership"`
				Disclosures         *[]string `json:"disclosures"`
				IntervalFindings    *[]string `json:"interval_findings"`
				MembershipFindings  *[]string `json:"membership_findings"`
			} `json:"expected"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, 12, manifest.Count)
	require.Len(t, manifest.Cases, manifest.Count)

	for _, vector := range manifest.Cases {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			input := testCase(t, vector.Name)
			wire, err := json.Marshal(input)
			require.NoError(t, err)
			fragment := base64.RawURLEncoding.EncodeToString(wire)
			decoded, err := DecodeFragment(fragment)
			require.NoError(t, err)

			result := VerifyBundle(input)
			decodedResult := VerifyBundle(decoded)
			require.Equal(t, result.GraphClosure, decodedResult.GraphClosure)
			require.Equal(t, result.IntervalCoverage, decodedResult.IntervalCoverage)
			require.Equal(t, result.PerRecordMembership, decodedResult.PerRecordMembership)
			require.Equal(t, vector.Expected.GraphClosure, result.GraphClosure.Status)
			require.Equal(t, vector.Expected.IntervalCoverage, result.IntervalCoverage.Status)
			require.Equal(t, vector.Expected.PerRecordMembership, result.PerRecordMembership.Status)
			if vector.Expected.Disclosures != nil {
				actualDisclosures := make([]string, len(result.Disclosures))
				for i, item := range result.Disclosures {
					actualDisclosures[i] = item.Status
				}
				sort.Strings(actualDisclosures)
				expectedDisclosures := append([]string(nil), (*vector.Expected.Disclosures)...)
				sort.Strings(expectedDisclosures)
				require.Equal(t, expectedDisclosures, actualDisclosures)
			}
			if vector.Expected.IntervalFindings != nil {
				require.Equal(t, *vector.Expected.IntervalFindings, result.IntervalCoverage.Findings)
			}
			if vector.Expected.MembershipFindings != nil {
				require.Equal(t, *vector.Expected.MembershipFindings, result.PerRecordMembership.Findings)
			}
		})
	}
}

func TestFragmentCodecAndDigest(t *testing.T) {
	bundle := map[string]interface{}{
		"b": json.Number("1"),
		"a": "value",
		"countersignatures": []interface{}{
			map[string]interface{}{"type": "cose-sign1", "signature": "ignored-by-digest"},
		},
	}
	fragment, err := EncodeFragment(bundle)
	require.NoError(t, err)
	require.Equal(t, "eyJhIjoidmFsdWUiLCJiIjoxLCJjb3VudGVyc2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiaWdub3JlZC1ieS1kaWdlc3QiLCJ0eXBlIjoiY29zZS1zaWduMSJ9XX0", fragment)
	decoded, err := DecodeFragment(fragment)
	require.NoError(t, err)
	require.Equal(t, bundle, decoded)
	digest, err := BundleDigest(bundle)
	require.NoError(t, err)
	require.Equal(t, "04a0f2c6e056b32f5659fdec506f9f6d6a0b250227004b0fd7ed43d0b77035a5", digest)
	_, err = DecodeFragment(base64.RawURLEncoding.EncodeToString([]byte("{}{}")))
	require.Error(t, err)
	result := VerifyBundle(map[string]interface{}{
		"countersignatures": []interface{}{"reserved"},
		"verification":      map[string]interface{}{"producer": "claimed"},
	})
	require.Equal(t, []CountersignatureResult{{Value: "reserved", Status: "unverified"}}, result.Countersignatures)
	require.Equal(t, &ProducerSelfReport{Value: map[string]interface{}{"producer": "claimed"}, Status: "producer_self_report"}, result.Verification)
}

func TestNativeFloatBundleMatchesDecodedNumbers(t *testing.T) {
	native := testCase(t, "pos-valid-bundle")
	floatBundle := floatNumbers(native).(map[string]interface{})
	encoded, err := json.Marshal(native)
	require.NoError(t, err)
	decoded, err := DecodeFragment(base64.RawURLEncoding.EncodeToString(encoded))
	require.NoError(t, err)
	require.Equal(t, VerifyBundle(decoded).GraphClosure, VerifyBundle(floatBundle).GraphClosure)
	require.Equal(t, VerifyBundle(decoded).IntervalCoverage, VerifyBundle(floatBundle).IntervalCoverage)
	require.Equal(t, VerifyBundle(decoded).PerRecordMembership, VerifyBundle(floatBundle).PerRecordMembership)
}

func floatNumbers(value interface{}) interface{} {
	switch value := value.(type) {
	case int:
		return float64(value)
	case map[string]interface{}:
		result := make(map[string]interface{}, len(value))
		for key, member := range value {
			result[key] = floatNumbers(member)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(value))
		for i, member := range value {
			result[i] = floatNumbers(member)
		}
		return result
	default:
		return value
	}
}

func testCase(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	output := map[string]interface{}{"answer": map[string]interface{}{"steps": []interface{}{"check", "approve"}, "total": "42"}}
	input := map[string]interface{}{"request": map[string]interface{}{"account": "A-17", "amount": "42.00"}}
	first := testCapsule(t, 1, output, nil, nil)
	middle := testCapsule(t, 2, nil, input, nil)
	root := testCapsule(t, 3, nil, nil, nil)
	bundle := testBundle(t, []map[string]interface{}{first, middle, root}, root, map[string]interface{}{first["capsule_id"].(string): map[string]interface{}{"agent_output": output}}, nil)

	switch name {
	case "neg-deleted-interior-record":
		bundle["records"] = []interface{}{first, root}
		delete(memberships(bundle), middle["capsule_id"].(string))
	case "neg-replaced-interior-record":
		replacement := testCapsule(t, 9, nil, input, nil)
		proof := memberships(bundle)[middle["capsule_id"].(string)]
		delete(memberships(bundle), middle["capsule_id"].(string))
		bundle["records"] = []interface{}{first, replacement, root}
		memberships(bundle)[replacement["capsule_id"].(string)] = proof
	case "neg-dangling-citation", "pos-declared-missing-citation":
		absent := strings.Repeat("f", 64)
		citedRoot := testCapsule(t, 4, nil, nil, map[string]interface{}{"parent_capsule_id": absent, "relation": "derived_from"})
		var missing []string
		if name == "pos-declared-missing-citation" {
			missing = []string{absent}
		}
		bundle = testBundle(t, []map[string]interface{}{first, middle, citedRoot}, citedRoot, nil, missing)
	case "pos-valid-bundle", "neg-disclosure-mismatch-nested-match":
		if name == "neg-disclosure-mismatch-nested-match" {
			bundle["disclosures"].(map[string]interface{})[middle["capsule_id"].(string)] = map[string]interface{}{"agent_input": map[string]interface{}{"request": map[string]interface{}{"account": "A-17", "amount": "99.00"}}}
		}
	case "neg-supplied-record-unbound":
		bundle["records"] = append(bundle["records"].([]interface{}), testCapsule(t, 9, nil, nil, nil))
	case "neg-membership-proof-coordinate-mismatch":
		memberships(bundle)[middle["capsule_id"].(string)].(map[string]interface{})["inclusion_proof"].(map[string]interface{})["leaf_index"] = 0
	case "neg-producer-asserted-checkpoint":
		// The default fixture deliberately has no independently verifiable checkpoint receipt.
	case "pos-default-completeness-values":
		delete(bundle["completeness"].(map[string]interface{}), "closure_depth")
		delete(bundle["completeness"].(map[string]interface{}), "missing")
	case "neg-portable-proof-version-kind":
		proof := memberships(bundle)[middle["capsule_id"].(string)].(map[string]interface{})["inclusion_proof"].(map[string]interface{})
		proof["v"] = 2
		proof["kind"] = "not-inclusion"
	case "neg-boolean-proof-integer":
		memberships(bundle)[middle["capsule_id"].(string)].(map[string]interface{})["inclusion_proof"].(map[string]interface{})["v"] = true
	default:
		t.Fatalf("unknown vector %q", name)
	}
	return bundle
}

func testCapsule(t *testing.T, number int, output, input, chain map[string]interface{}) map[string]interface{} {
	t.Helper()
	capsule := map[string]interface{}{
		"spec_version":        "draft-mih-scitt-agent-action-capsule-04",
		"format_version":      "4",
		"canonicalization_id": "jcs",
		"action_id":           "bundle-" + strconv.Itoa(number),
		"action_type":         "decide",
		"operator":            "ACME-CO",
		"developer":           "agent@v1",
		"timestamp":           "2026-09-14T00:00:0" + strconv.Itoa(number) + "Z",
		"assurance":           map[string]interface{}{"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "standalone"},
		"disposition":         map[string]interface{}{"verdict_class": "blocked", "decision": "reject", "approver": "policy", "human_disposed": false},
	}
	if output != nil {
		capsule["model_attestation"] = map[string]interface{}{"compute_attestation": map[string]interface{}{"agent_output_digest": testDigest(t, output)}}
	}
	if input != nil {
		capsule["model_attestation"] = map[string]interface{}{"compute_attestation": map[string]interface{}{"agent_input_digest": testDigest(t, input)}}
	}
	if chain != nil {
		capsule["chain"] = chain
	}
	id, err := canonical.ComputeCapsuleID(capsule)
	require.NoError(t, err)
	capsule["capsule_id"] = id
	return capsule
}

func testDigest(t *testing.T, value interface{}) string {
	t.Helper()
	valueDigest, err := canonical.JSONDigest(value)
	require.NoError(t, err)
	return valueDigest
}

func testBundle(t *testing.T, records []map[string]interface{}, root map[string]interface{}, overlay map[string]interface{}, missing []string) map[string]interface{} {
	t.Helper()
	tree, err := mmr.New(nil)
	require.NoError(t, err)
	for _, record := range records {
		_, err := tree.AppendHexIdentity(record["capsule_id"].(string))
		require.NoError(t, err)
	}
	size := tree.Size()
	rootHash, err := tree.Root()
	require.NoError(t, err)
	proofs := make([]mmr.InclusionProof, len(records))
	for i := range records {
		proofs[i], err = tree.InclusionProof(uint64(i), size)
		require.NoError(t, err)
	}
	members := make(map[string]interface{}, len(records))
	for index, record := range records {
		members[record["capsule_id"].(string)] = map[string]interface{}{"log_coordinates": map[string]interface{}{"log_id": "bundle-log", "seq": index + 1, "leaf_index": index}, "inclusion_proof": proofObject(proofs[index])}
	}
	// CLL #13 range proof over the whole interval + the ordered body digests.
	rangeP, err := tree.RangeProof(0, uint64(len(records)-1), size)
	require.NoError(t, err)
	bodyDigests := make([]interface{}, len(records))
	for i, record := range records {
		bodyDigests[i] = record["capsule_id"]
	}
	if overlay == nil {
		overlay = map[string]interface{}{}
	}
	mode := "complete"
	if len(missing) != 0 {
		mode = "declared_incomplete"
	}
	missingValues := make([]interface{}, len(missing))
	for i, id := range missing {
		missingValues[i] = id
	}
	return map[string]interface{}{
		"bundle_version": "2", "bundle_kind": "evidence-bundle/v2", "root": root["capsule_id"],
		"records":                  recordsAsValues(records),
		"completeness":             map[string]interface{}{"closure_depth": 2, "records_mode": mode, "payloads_mode": "selected", "suppressed_fields": []interface{}{"agent_input"}, "missing": missingValues},
		"disclosures":              overlay,
		"completeness_certificate": map[string]interface{}{"log_id": "bundle-log", "range_root": hex.EncodeToString(rootHash), "first_seq": 1, "last_seq": len(records), "body_digests": bodyDigests, "range_proof": map[string]interface{}{"from_seq": 1, "to_seq": len(records), "size": int(size), "from_index": int(rangeP.FromIndex), "to_index": int(rangeP.ToIndex), "witness": hashesObject(rangeP.Witness)}, "memberships": members},
		"checkpoint":               map[string]interface{}{"root": hex.EncodeToString(rootHash), "mmr_size": int(size)},
		"extensions":               map[string]interface{}{"example/unimplemented": map[string]interface{}{"note": "digest-covered only"}},
	}
}

func recordsAsValues(records []map[string]interface{}) []interface{} {
	values := make([]interface{}, len(records))
	for i := range records {
		values[i] = records[i]
	}
	return values
}
func memberships(bundle map[string]interface{}) map[string]interface{} {
	return bundle["completeness_certificate"].(map[string]interface{})["memberships"].(map[string]interface{})
}
func number(value int) json.Number { return json.Number(strconv.Itoa(value)) }

func proofObject(proof mmr.InclusionProof) map[string]interface{} {
	return map[string]interface{}{"v": int(proof.V), "kind": proof.Kind, "size": int(proof.Size), "leaf_index": int(proof.LeafIndex), "witness": hashesObject(proof.Witness), "peaks_left": hashesObject(proof.PeaksLeft), "peaks_right": hashesObject(proof.PeaksRight)}
}
func hashesObject(values [][]byte) []interface{} {
	result := make([]interface{}, len(values))
	for i, value := range values {
		result[i] = hex.EncodeToString(value)
	}
	return result
}

// TestRangeRejectsAlteredInteriorBodyDigest is the bundle-level negative for the
// CLL #13 every-leaf binding: a well-formed but wrong interior body digest must
// fail interval coverage (a two-endpoint check would miss it).
func TestRangeRejectsAlteredInteriorBodyDigest(t *testing.T) {
	bundle := testCase(t, "pos-valid-bundle")
	cert := bundle["completeness_certificate"].(map[string]interface{})
	body := cert["body_digests"].([]interface{})
	body[1] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result := VerifyBundle(bundle)
	require.Equal(t, "fail", result.IntervalCoverage.Status)
	require.Contains(t, result.IntervalCoverage.Findings, "range_proof_invalid")
}

// TestIntervalRejectsSubTipRange pins the F1 tip bind: a range [1,3] proved
// against a 4-leaf tree (a valid core range proof + root) must be rejected
// because leaf_count(size) != last, or records after last could be omitted.
func TestIntervalRejectsSubTipRange(t *testing.T) {
	caps := []map[string]interface{}{
		testCapsule(t, 1, nil, nil, nil), testCapsule(t, 2, nil, nil, nil),
		testCapsule(t, 3, nil, nil, nil), testCapsule(t, 4, nil, nil, nil),
	}
	tree, err := mmr.New(nil)
	require.NoError(t, err)
	for _, c := range caps {
		_, err := tree.AppendHexIdentity(c["capsule_id"].(string))
		require.NoError(t, err)
	}
	size := tree.Size()
	rootHash, err := tree.Root()
	require.NoError(t, err)
	rangeP, err := tree.RangeProof(0, 2, size)
	require.NoError(t, err)
	records := caps[:3]
	members := make(map[string]interface{}, len(records))
	for i, c := range records {
		proof, e := tree.InclusionProof(uint64(i), size)
		require.NoError(t, e)
		members[c["capsule_id"].(string)] = map[string]interface{}{
			"log_coordinates": map[string]interface{}{"log_id": "bundle-log", "seq": i + 1, "leaf_index": i},
			"inclusion_proof": proofObject(proof),
		}
	}
	bundle := map[string]interface{}{
		"bundle_version": "2", "bundle_kind": "evidence-bundle/v2", "root": records[len(records)-1]["capsule_id"],
		"records":      recordsAsValues(records),
		"completeness": map[string]interface{}{"records_mode": "complete", "missing": []interface{}{}},
		"completeness_certificate": map[string]interface{}{
			"log_id": "bundle-log", "range_root": hex.EncodeToString(rootHash), "first_seq": 1, "last_seq": 3,
			"body_digests": []interface{}{records[0]["capsule_id"], records[1]["capsule_id"], records[2]["capsule_id"]},
			"range_proof":  map[string]interface{}{"from_seq": 1, "to_seq": 3, "size": int(size), "from_index": int(rangeP.FromIndex), "to_index": int(rangeP.ToIndex), "witness": hashesObject(rangeP.Witness)},
			"memberships":  members,
		},
		"checkpoint": map[string]interface{}{"root": hex.EncodeToString(rootHash), "mmr_size": int(size)},
	}
	result := VerifyBundle(bundle)
	require.Equal(t, "fail", result.IntervalCoverage.Status)
	require.Contains(t, result.IntervalCoverage.Findings, "range_proof_invalid")
}
