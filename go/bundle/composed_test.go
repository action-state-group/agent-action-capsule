// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

type composedCase struct {
	ID        string                 `json:"id"`
	Container map[string]interface{} `json:"container"`
	Expect    map[string]interface{} `json:"expect"`
}

// composedCases reads vectors/bundle/composed/vectors.json byte for byte from
// the repository's shared corpus (numbers kept as json.Number).
func composedCases(t *testing.T) map[string]composedCase {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", "composed", "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var file struct {
		Count json.Number    `json:"count"`
		Cases []composedCase `json:"cases"`
	}
	require.NoError(t, decoder.Decode(&file))
	require.Equal(t, json.Number("3"), file.Count)
	cases := map[string]composedCase{}
	for _, c := range file.Cases {
		cases[c.ID] = c
	}
	require.Len(t, cases, 3)
	return cases
}

func composedBlockOf(container map[string]interface{}) map[string]interface{} {
	return container["extensions"].(map[string]interface{})[ComposedKind].(map[string]interface{})
}

func composedResultOf(t *testing.T, result VerificationResult) *ComposedResult {
	t.Helper()
	require.Len(t, result.Extensions, 1)
	require.Equal(t, ComposedKind, result.Extensions[0].Kind)
	require.True(t, result.Extensions[0].IntegrityCovered)
	require.NotNil(t, result.Extensions[0].Composed)
	require.Equal(t, result.Extensions[0].Composed.Status, result.Extensions[0].Status)
	return result.Extensions[0].Composed
}

// expectShape renders a ComposedResult in the vectors' `expect` vocabulary.
func expectShape(result *ComposedResult) map[string]interface{} {
	members := map[string]interface{}{}
	for _, m := range result.Members {
		var claims interface{}
		if m.Bundle != nil {
			claims = map[string]interface{}{
				"graph_closure":         m.Bundle.GraphClosure.Status,
				"interval_coverage":     m.Bundle.IntervalCoverage.Status,
				"per_record_membership": m.Bundle.PerRecordMembership.Status,
			}
		}
		members[m.ID] = map[string]interface{}{"outcome": m.Outcome, "body": m.Body, "digest": m.Digest, "claims": claims}
	}
	closure := map[string]interface{}{"status": result.CompositionClosure.Status, "missing": stringValues(result.CompositionClosure.Missing)}
	if result.CompositionClosure.Status == "withheld" {
		closure["finding"] = result.CompositionClosure.Findings[0]
	}
	joins := []interface{}{}
	for _, j := range result.Joins {
		var derived interface{}
		if j.Derived != "" {
			derived = j.Derived
		}
		joins = append(joins, map[string]interface{}{
			"members": stringValues(j.Members[:]), "declared": j.Declared, "derived": derived, "result": j.Result,
		})
	}
	corroboration := []interface{}{}
	for _, c := range result.Corroboration {
		value := map[string]interface{}{"members": stringValues(c.Members[:]), "result": c.Result}
		for key, field := range map[string]string{"reason": c.Reason, "report": c.Report, "qualifier": c.Qualifier} {
			if field != "" {
				value[key] = field
			}
		}
		corroboration = append(corroboration, value)
	}
	return map[string]interface{}{
		"composed_digest":     result.ComposedDigest.Recomputed,
		"members":             members,
		"composition_closure": closure,
		"joins":               joins,
		"corroboration":       corroboration,
	}
}

func stringValues(values []string) []interface{} {
	out := make([]interface{}, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func TestComposedVectors(t *testing.T) {
	cases := composedCases(t)
	wantStatus := map[string]string{"agree": "pass", "one-member-missing": "withheld", "same-custody-redundant": "pass"}
	for id, c := range cases {
		c := c
		t.Run(id, func(t *testing.T) {
			block := composedBlockOf(c.Container)
			preimage, err := ComposedDigestPreimage(block)
			require.NoError(t, err)
			require.Equal(t, c.Expect["canonical_preimage"], string(preimage))
			digest, err := ComposedDigest(block)
			require.NoError(t, err)
			require.Equal(t, c.Expect["composed_digest"], digest)
			require.Equal(t, block["composed_digest"], digest)

			result := VerifyBundle(c.Container)
			require.Equal(t, "pass", result.GraphClosure.Status)
			composed := composedResultOf(t, result)
			require.Equal(t, wantStatus[id], composed.Status, composed.Findings)
			require.True(t, composed.ComposedDigest.Matches)
			require.NotEqual(t, *result.BundleDigest, composed.ComposedDigest.Recomputed)

			want := map[string]interface{}{}
			for key, value := range c.Expect {
				if key != "canonical_preimage" && key != "composed_digest_equals_case" {
					want[key] = value
				}
			}
			require.Equal(t, want, expectShape(composed))

			for _, member := range composed.Members {
				if member.Bundle != nil {
					raw := memberByID(block, member.ID)["bundle"]
					require.Equal(t, memberByID(block, member.ID)["digest"], *member.Bundle.BundleDigest)
					require.Equal(t, VerifyBundle(raw).GraphClosure, member.Bundle.GraphClosure)
				}
			}
		})
	}
	require.Equal(t, cases["agree"].Expect["composed_digest"], cases["one-member-missing"].Expect["composed_digest"])
	require.Equal(t, "agree", cases["one-member-missing"].Expect["composed_digest_equals_case"])
}

func memberByID(block map[string]interface{}, id string) map[string]interface{} {
	for _, raw := range block["members"].([]interface{}) {
		if m := raw.(map[string]interface{}); m["id"] == id {
			return m
		}
	}
	return nil
}

// cloneCase returns a deep copy of a vector container and its composed block.
func cloneCase(t *testing.T, c composedCase) (map[string]interface{}, map[string]interface{}) {
	t.Helper()
	data, err := json.Marshal(c.Container)
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var container map[string]interface{}
	require.NoError(t, decoder.Decode(&container))
	return container, composedBlockOf(container)
}

// reseal recomputes every carried member digest and the composed digest, so a
// test isolates the one check it targets.
func reseal(t *testing.T, block map[string]interface{}) {
	t.Helper()
	for _, raw := range block["members"].([]interface{}) {
		m := raw.(map[string]interface{})
		if body, ok := m["bundle"]; ok {
			digest, err := BundleDigest(body)
			require.NoError(t, err)
			m["digest"] = digest
		}
		for _, key := range []string{"refusal", "absence"} {
			if body, ok := m[key]; ok {
				digest, err := canonical.JSONDigest(body)
				require.NoError(t, err)
				m["digest"] = digest
			}
		}
	}
	digest, err := ComposedDigest(block)
	require.NoError(t, err)
	block["composed_digest"] = digest
}

func verifyBlock(t *testing.T, container map[string]interface{}, opts Options) *ComposedResult {
	t.Helper()
	return composedResultOf(t, VerifyBundleWithOptions(container, opts))
}

func TestComposedTamperedMemberDigestFails(t *testing.T) {
	container, block := cloneCase(t, composedCases(t)["agree"])
	bundle := memberByID(block, "responder-a")["bundle"].(map[string]interface{})
	bundle["verification"] = map[string]interface{}{"note": "added after sealing"}

	result := verifyBlock(t, container, Options{})
	require.Equal(t, "fail", result.Status)
	require.True(t, result.ComposedDigest.Matches, "bodies are outside the composed digest")
	require.Equal(t, "mismatch", result.Members[0].Digest)
	require.Equal(t, "fail", result.CompositionClosure.Status)
	require.Equal(t, []string{"member_digest_mismatch:responder-a"}, result.CompositionClosure.Findings)
}

func TestComposedDeclaredJoinStateWrongFails(t *testing.T) {
	container, block := cloneCase(t, composedCases(t)["agree"])
	block["joins"].([]interface{})[0].(map[string]interface{})["state"] = "mismatch"
	reseal(t, block)

	result := verifyBlock(t, container, Options{})
	require.Equal(t, "fail", result.Status)
	require.True(t, result.ComposedDigest.Matches)
	require.Equal(t, "pass", result.CompositionClosure.Status)
	require.Equal(t, "agree", result.Joins[0].Derived)
	require.Equal(t, "join_state_mismatch", result.Joins[0].Result)
	require.Contains(t, result.Findings, "join_state_mismatch:responder-a,responder-b")
}

func TestComposedUndeclaredMissingMemberFailsClosure(t *testing.T) {
	container, block := cloneCase(t, composedCases(t)["one-member-missing"])
	delete(block, "missing")

	result := verifyBlock(t, container, Options{})
	require.Equal(t, "fail", result.Status)
	require.True(t, result.ComposedDigest.Matches, "missing is outside the composed digest")
	require.Equal(t, "fail", result.CompositionClosure.Status)
	require.Equal(t, []string{"member_body_absent:responder-b"}, result.CompositionClosure.Findings)
	require.Equal(t, "absent", result.Members[1].Body)
	require.Equal(t, "not_derivable", result.Joins[0].Result)
}

func TestComposedClosureFailures(t *testing.T) {
	cases := composedCases(t)
	container, block := cloneCase(t, cases["agree"])
	block["missing"] = []interface{}{"responder-a"}
	result := verifyBlock(t, container, Options{})
	require.Equal(t, "fail", result.CompositionClosure.Status)
	require.Equal(t, []string{"missing_member_carries_body:responder-a"}, result.CompositionClosure.Findings)

	container, block = cloneCase(t, cases["one-member-missing"])
	block["missing"] = []interface{}{"responder-b", "responder-z"}
	result = verifyBlock(t, container, Options{})
	require.Equal(t, "fail", result.CompositionClosure.Status)
	require.Equal(t, []string{"missing_names_undeclared_member:responder-z"}, result.CompositionClosure.Findings)
}

func TestComposedDigestMismatchFails(t *testing.T) {
	container, block := cloneCase(t, composedCases(t)["agree"])
	block["observers"].([]interface{})[1].(map[string]interface{})["custody_domain"] = "custody-a.example"

	result := verifyBlock(t, container, Options{})
	require.Equal(t, "fail", result.Status)
	require.False(t, result.ComposedDigest.Matches)
	require.Contains(t, result.Findings, "composed_digest_mismatch")
	// Declared custody still downgrades, even on a block that fails.
	require.Equal(t, "redundant", result.Corroboration[0].Result)
	require.Equal(t, "same_custody_domain", result.Corroboration[0].Reason)
}

func TestComposedMalformedBlockReportsNoComposition(t *testing.T) {
	cases := composedCases(t)
	for name, mutate := range map[string]func(map[string]interface{}){
		"join members not ascending": func(b map[string]interface{}) {
			b["joins"].([]interface{})[0].(map[string]interface{})["members"] = []interface{}{"responder-b", "responder-a"}
		},
		"undeclared observer": func(b map[string]interface{}) {
			b["members"].([]interface{})[0].(map[string]interface{})["observer"] = "obs-z"
		},
		"not_requested names a member": func(b map[string]interface{}) { b["not_requested"] = []interface{}{"responder-a"} },
		"unknown outcome": func(b map[string]interface{}) {
			b["members"].([]interface{})[0].(map[string]interface{})["outcome"] = "timeout"
		},
		"duplicate member id": func(b map[string]interface{}) {
			b["members"].([]interface{})[1].(map[string]interface{})["id"] = "responder-a"
		},
		"refusal body on an artifact": func(b map[string]interface{}) {
			b["members"].([]interface{})[0].(map[string]interface{})["refusal"] = map[string]interface{}{}
		},
	} {
		container, block := cloneCase(t, cases["agree"])
		mutate(block)
		result := verifyBlock(t, container, Options{})
		require.Equal(t, "fail", result.Status, name)
		require.True(t, result.Malformed, name)
		require.Nil(t, result.ComposedDigest, name)
		require.Nil(t, result.CompositionClosure, name)
		require.Empty(t, result.Members, name)
		require.Empty(t, result.Joins, name)
		_, err := ComposedDigest(block)
		require.Error(t, err, name)
	}
}

func TestComposedDerivedMismatchNamesNoWinner(t *testing.T) {
	container, block := cloneCase(t, composedCases(t)["agree"])
	join := block["joins"].([]interface{})[0].(map[string]interface{})
	join["compare"] = []interface{}{"/model_attestation/compute_attestation/x-example-exchange-v1/transcript_digest", "/action_id"}
	join["state"] = "mismatch"
	reseal(t, block)

	result := verifyBlock(t, container, Options{})
	require.Equal(t, "pass", result.Status, result.Findings)
	require.Equal(t, "mismatch", result.Joins[0].Derived)
	require.Equal(t, "derived_matches", result.Joins[0].Result)
	require.Equal(t, []JoinDifference{{Pointer: "/action_id", Values: []JoinValue{
		{Member: "responder-a", Resolved: true, Value: "example-run-0001/responder-a"},
		{Member: "responder-b", Resolved: true, Value: "example-run-0001/responder-b"},
	}}}, result.Joins[0].Differences)
	require.Equal(t, "not_applicable", result.Corroboration[0].Result)
}

func TestComposedUnlinkedAndReservedBases(t *testing.T) {
	cases := composedCases(t)
	container, block := cloneCase(t, cases["agree"])
	join := block["joins"].([]interface{})[0].(map[string]interface{})
	join["identifier_digest"] = strings.Repeat("0", 64)
	join["state"] = "unjoined"
	reseal(t, block)
	result := verifyBlock(t, container, Options{})
	require.Equal(t, "unjoined", result.Joins[0].Derived)
	require.Equal(t, "pass", result.Status, result.Findings)

	container, block = cloneCase(t, cases["agree"])
	join = block["joins"].([]interface{})[0].(map[string]interface{})
	join["basis"] = "shared_artifact_digest"
	join["pointer"] = "/model_attestation/compute_attestation/x-example-exchange-v1/transcript_digest"
	delete(join, "identifier_digest")
	delete(join, "compare")
	reseal(t, block)
	result = verifyBlock(t, container, Options{})
	require.Equal(t, "agree", result.Joins[0].Derived)
	require.Equal(t, "corroborating", result.Corroboration[0].Result)

	for _, basis := range []string{"issued_receipt", "same_interval"} {
		container, block = cloneCase(t, cases["agree"])
		block["joins"].([]interface{})[0].(map[string]interface{})["basis"] = basis
		reseal(t, block)
		result = verifyBlock(t, container, Options{})
		require.Equal(t, "not_derivable", result.Joins[0].Result, basis)
		require.Equal(t, "", result.Joins[0].Derived, basis)
		require.Equal(t, "not_applicable", result.Corroboration[0].Result, basis)
		require.Equal(t, "withheld", result.Status, basis)
		require.Contains(t, result.Findings, "join_not_derivable:responder-a,responder-b")
	}
}

func TestComposedRedundancyReasons(t *testing.T) {
	cases := composedCases(t)
	container, block := cloneCase(t, cases["agree"])
	block["members"].([]interface{})[1].(map[string]interface{})["observer"] = "obs-a"
	reseal(t, block)
	result := verifyBlock(t, container, Options{})
	require.Equal(t, "redundant", result.Corroboration[0].Result)
	require.Equal(t, []string{"same_observer", "same_custody_domain"}, result.Corroboration[0].Reasons)
	require.Equal(t, "redundant, not corroborating", result.Corroboration[0].Report)

	// Same key on both root records, distinct custody labels: still redundant.
	container, block = cloneCase(t, cases["agree"])
	root := func(id string) map[string]interface{} {
		bundle := memberByID(block, id)["bundle"].(map[string]interface{})
		return bundle["records"].([]interface{})[0].(map[string]interface{})
	}
	root("responder-b")["key_id"] = root("responder-a")["key_id"]
	reseal(t, block)
	result = verifyBlock(t, container, Options{})
	require.Equal(t, "redundant", result.Corroboration[0].Result)
	require.Equal(t, "same_key_id", result.Corroboration[0].Reason)
}

func refusalAndAbsenceCase(t *testing.T) (map[string]interface{}, map[string]interface{}) {
	t.Helper()
	container, block := cloneCase(t, composedCases(t)["agree"])
	a := memberByID(block, "responder-a")
	b := memberByID(block, "responder-b")
	delete(b, "bundle")
	b["outcome"] = "refusal"
	b["refusal"] = map[string]interface{}{"request_digest": b["request_digest"], "reason": "policy_declined", "issued_at": "2026-10-02T12:00:00Z"}
	members := block["members"].([]interface{})
	block["members"] = append(members, map[string]interface{}{
		"id": "responder-c", "observer": "obs-b", "request_digest": a["request_digest"], "outcome": "absence", "digest": strings.Repeat("0", 64),
		"absence": map[string]interface{}{"request_digest": a["request_digest"], "window": map[string]interface{}{"from": "2026-10-02T12:00:00Z", "to": "2026-10-02T13:00:00Z"}},
	})
	block["joins"].([]interface{})[0].(map[string]interface{})["state"] = "one_sided"
	reseal(t, block)
	return container, block
}

func TestComposedRefusalAndAbsenceMembers(t *testing.T) {
	container, _ := refusalAndAbsenceCase(t)
	result := verifyBlock(t, container, Options{})
	require.Equal(t, "withheld", result.Status)
	require.Equal(t, []string{"refusal_signature_unverified:responder-b"}, result.Findings)
	require.Equal(t, "pass", result.CompositionClosure.Status)
	require.Equal(t, "one_sided", result.Joins[0].Derived)
	require.Equal(t, "derived_matches", result.Joins[0].Result)
	refusal, absence := result.Members[1], result.Members[2]
	require.Equal(t, ComposedMemberResult{ID: "responder-b", Observer: "obs-b", Outcome: "refusal", Body: "carried", Digest: "reproduced", RefusalSignature: RefusalSignatureUnverified}, refusal)
	require.Equal(t, ComposedMemberResult{ID: "responder-c", Observer: "obs-b", Outcome: "absence", Body: "carried", Digest: "reproduced"}, absence)

	verified := verifyBlock(t, container, Options{RefusalSignature: func(map[string]interface{}) string { return RefusalSignatureVerified }})
	require.Equal(t, "pass", verified.Status, verified.Findings)
	require.Equal(t, RefusalSignatureVerified, verified.Members[1].RefusalSignature)

	invalid := verifyBlock(t, container, Options{RefusalSignature: func(map[string]interface{}) string { return RefusalSignatureInvalid }})
	require.Equal(t, "fail", invalid.Status)
	require.Equal(t, []string{"refusal_signature_invalid"}, invalid.Members[1].Findings)
}

func TestComposedRefusalRequestDigestMustMatch(t *testing.T) {
	container, block := refusalAndAbsenceCase(t)
	memberByID(block, "responder-b")["refusal"].(map[string]interface{})["request_digest"] = strings.Repeat("1", 64)
	reseal(t, block)
	result := verifyBlock(t, container, Options{})
	require.Equal(t, "fail", result.Status)
	require.Contains(t, result.Members[1].Findings, "request_digest_mismatch")
	require.Contains(t, result.Findings, "member_request_digest_mismatch:responder-b")
}

func TestResolvePointer(t *testing.T) {
	doc := map[string]interface{}{"a/b": map[string]interface{}{"m~n": []interface{}{"x", "y"}}, "": "empty"}
	for pointer, want := range map[string]interface{}{"/a~1b/m~0n/1": "y", "/": "empty", "/a~1b/m~0n/0": "x"} {
		got, ok := resolvePointer(doc, pointer)
		require.True(t, ok, pointer)
		require.Equal(t, want, got, pointer)
	}
	for _, pointer := range []string{"a", "/a~1b/m~0n/01", "/a~1b/m~0n/2", "/a~1b/m~0n/-", "/missing", "/a~2b"} {
		_, ok := resolvePointer(doc, pointer)
		require.False(t, ok, pointer)
	}
}
