// SPDX-License-Identifier: BSD-3-Clause
package bundle

// The producer's optional LeafContent capability (Evidence Bundle -02): with
// CarryNonRecordLeaves a range covers padding leaves, carried in
// completeness_certificate.non_record_leaves; a source without the
// capability, or a build without the option, is unchanged.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

func testPadding(t *testing.T, label string) map[string]interface{} {
	t.Helper()
	nonce, err := canonical.JSONDigest(label)
	require.NoError(t, err)
	body := map[string]interface{}{"record_type": "padding", "epistemic_type": "producer_claim", "store_nonce": nonce}
	id, err := canonical.JSONDigest(body)
	require.NoError(t, err)
	body["capsule_id"] = id
	return body
}

// withContent is a ProofSource with the optional LeafContent capability over
// another.
type withContent struct {
	ProofSource
	contents map[uint64]map[string]interface{}
}

func (w withContent) LeafContent(_ context.Context, seq uint64) (map[string]interface{}, error) {
	content := w.contents[seq]
	if content == nil {
		return nil, nil
	}
	copied := make(map[string]interface{}, len(content))
	for name, value := range content {
		copied[name] = value
	}
	return copied, nil
}

// paddedLog is records at seq 1 and 3, padding at 2 and at the tip, 4.
func paddedLog(t *testing.T) (ProofSource, [2]map[string]interface{}, map[uint64]map[string]interface{}) {
	t.Helper()
	records := newRecords()
	a := producerCapsule(t, "a", capsuleOptions{})
	b := producerCapsule(t, "b", capsuleOptions{})
	records.put(t, a, true)
	records.put(t, b, true)
	pads := map[uint64]map[string]interface{}{2: testPadding(t, "2"), 4: testPadding(t, "4")}
	source := makeLog(t, []string{cid(a), cid(pads[2]), cid(b), cid(pads[4])}, records, -1)
	return source, [2]map[string]interface{}{a, b}, pads
}

func nonRecordLeavesOf(t *testing.T, bundle map[string]interface{}) interface{} {
	t.Helper()
	data, err := json.Marshal(bundle["completeness_certificate"].(map[string]interface{})["non_record_leaves"])
	require.NoError(t, err)
	var out interface{}
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

func TestBuildCarriesPaddingWhenAsked(t *testing.T) {
	source, ab, pads := paddedLog(t)
	stored := map[uint64]map[string]interface{}{}
	for seq, pad := range pads {
		withEnvelope := map[string]interface{}{"signature": "00", "key_id": "11"} // dropped
		for name, value := range pad {
			withEnvelope[name] = value
		}
		stored[seq] = withEnvelope
	}
	bundle, err := BuildEvidenceBundle(t.Context(), withContent{source, stored}, BuildOptions{Root: cid(ab[1]), IntervalFrom: 1, CarryNonRecordLeaves: true})
	require.NoError(t, err)
	want := []interface{}{
		map[string]interface{}{"seq": float64(2), "content": pads[2]},
		map[string]interface{}{"seq": float64(4), "content": pads[4]},
	}
	require.Equal(t, want, nonRecordLeavesOf(t, bundle))
	require.Equal(t, ids(ab[0], ab[1]), carriedIDs(bundle))
	require.Equal(t, VerdictValid, strictVerdictOf(bundle))
}

func TestCarryingNonRecordLeavesIsOffByDefault(t *testing.T) {
	source, ab, pads := paddedLog(t)
	_, err := BuildEvidenceBundle(t.Context(), withContent{source, pads}, BuildOptions{Root: cid(ab[1]), IntervalFrom: 1})
	requireRefusal(t, err, "seq 2 in the interval is not a record")
}

func TestAnOldSourceIsUnchanged(t *testing.T) {
	source, ab, pads := paddedLog(t)
	_, hasCapability := source.(LeafContentSource)
	require.False(t, hasCapability)
	_, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(ab[1]), IntervalFrom: 1, CarryNonRecordLeaves: true})
	requireRefusal(t, err, "seq 2 in the interval is not a record")
	old, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(ab[1]), NoRange: true, ClosureDepth: depth(0)})
	require.NoError(t, err)
	carried, err := BuildEvidenceBundle(t.Context(), withContent{source, pads}, BuildOptions{Root: cid(ab[1]), NoRange: true, ClosureDepth: depth(0), CarryNonRecordLeaves: true})
	require.NoError(t, err)
	require.Equal(t, old, carried)
	require.NotContains(t, carried["completeness_certificate"], "non_record_leaves")
}

func TestNoPaddingInTheIntervalMeansNoMember(t *testing.T) {
	source, ab, pads := paddedLog(t)
	_, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(ab[1]), IntervalFrom: 3})
	requireRefusal(t, err, "seq 4")
	bundle, err := BuildEvidenceBundle(t.Context(), withContent{source, pads}, BuildOptions{Root: cid(ab[1]), IntervalFrom: 3, CarryNonRecordLeaves: true})
	require.NoError(t, err)
	require.Equal(t, []interface{}{map[string]interface{}{"seq": float64(4), "content": pads[4]}}, nonRecordLeavesOf(t, bundle))
}

func TestLeafContentThatIsNotThatPaddingIsRefused(t *testing.T) {
	source, ab, pads := paddedLog(t)
	wrongNonce := map[string]interface{}{}
	noID := map[string]interface{}{}
	for name, value := range pads[2] {
		wrongNonce[name] = value
		if name != "capsule_id" {
			noID[name] = value
		}
	}
	wrongNonce["store_nonce"] = strings.Repeat("00", 32)
	for _, c := range []struct {
		content map[string]interface{}
		message string
	}{
		{map[string]interface{}{"record_type": "checkpoint_stamp"}, "not a padding record"},
		{map[string]interface{}{"record_type": []interface{}{"padding"}}, "not a padding record"},
		{wrongNonce, "does not hash to the leaf"},
		{noID, "does not hash to the leaf"},
		{map[string]interface{}{"record_type": "padding", "weight": 0.5}, "no canonical digest"},
	} {
		contents := map[uint64]map[string]interface{}{2: c.content, 4: pads[4]}
		_, err := BuildEvidenceBundle(t.Context(), withContent{source, contents}, BuildOptions{Root: cid(ab[1]), IntervalFrom: 1, CarryNonRecordLeaves: true})
		requireRefusal(t, err, c.message)
	}
}

func TestAMalformedPaddingShapeIsRefusedByTheSelfCheck(t *testing.T) {
	body := map[string]interface{}{"record_type": "padding", "epistemic_type": "producer_claim", "store_nonce": strings.Repeat("AB", 32)}
	id, err := canonical.JSONDigest(body)
	require.NoError(t, err)
	body["capsule_id"] = id
	records := newRecords()
	a := producerCapsule(t, "a", capsuleOptions{})
	records.put(t, a, true)
	source := makeLog(t, []string{cid(a), id}, records, -1)
	_, err = BuildEvidenceBundle(t.Context(), withContent{source, map[uint64]map[string]interface{}{2: body}}, BuildOptions{Root: cid(a), IntervalFrom: 1, CarryNonRecordLeaves: true})
	requireRefusal(t, err, "non_record_leaf_malformed:2")
}

func TestCarryingOverARangeWithoutPaddingAddsNoMember(t *testing.T) {
	source, _, _ := testChain(t)
	leaves, err := source.Leaves(t.Context())
	require.NoError(t, err)
	root := hex.EncodeToString(leaves[len(leaves)-1])
	bundle, err := BuildEvidenceBundle(t.Context(), withContent{source, nil}, BuildOptions{Root: root, IntervalFrom: 1, CarryNonRecordLeaves: true})
	require.NoError(t, err)
	require.NotContains(t, bundle["completeness_certificate"], "non_record_leaves")
}
