// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Evidence Bundle -02 "Empty-History Bundles". The Bundles are the
// empty-history members of vectors/bundle/composed-controller-binding/.

func emptyCase(t *testing.T, id string) (map[string]interface{}, map[string]interface{}, bindingCase) {
	t.Helper()
	c := bindingCases(t)[id]
	container := cloneJSON(t, c.Container)
	return container, composedBlockOf(container), c
}

func emptyMemberBundle(t *testing.T, id string) map[string]interface{} {
	t.Helper()
	_, block, _ := emptyCase(t, id)
	return memberByID(block, "responder-b")["bundle"].(map[string]interface{})
}

func claimStatuses(result VerificationResult) []string {
	return []string{result.GraphClosure.Status, result.IntervalCoverage.Status, result.PerRecordMembership.Status}
}

func TestEmptyHistoryBundleShowsNoHistory(t *testing.T) {
	checkpointed := emptyMemberBundle(t, "controller-binding-empty-member-linked")
	result := VerifyBundle(checkpointed)
	require.Equal(t, []string{"pass", "withheld", "withheld"}, claimStatuses(result))
	require.Equal(t, []string{"no_records"}, result.IntervalCoverage.Findings)
	require.Equal(t, []string{"no_records"}, result.PerRecordMembership.Findings)
	require.NotNil(t, result.History)
	require.Equal(t, "none", result.History.State)
	require.Equal(t, checkpointed["checkpoint"].(map[string]interface{})["timestamp"], *result.History.Since)

	// A stream never started has no checkpoint: no history, with no date.
	unstarted := VerifyBundle(emptyMemberBundle(t, "controller-binding-empty-member-no-checkpoint"))
	require.Equal(t, []string{"pass", "withheld", "withheld"}, claimStatuses(unstarted))
	require.Equal(t, "none", unstarted.History.State)
	require.Nil(t, unstarted.History.Since)

	// A checkpoint that does not verify gives no date.
	broken := emptyMemberBundle(t, "controller-binding-empty-member-linked")
	cp := broken["checkpoint"].(map[string]interface{})
	cp["cose"] = cp["cose"].(string)[:len(cp["cose"].(string))-4] + "AAAA"
	require.Nil(t, VerifyBundle(broken).History.Since)
}

func TestEmptyHistoryBundleMalformed(t *testing.T) {
	changes := map[string]func(b map[string]interface{}){
		"empty_history_completeness_invalid/payloads_mode": func(b map[string]interface{}) {
			b["completeness"].(map[string]interface{})["payloads_mode"] = "all"
		},
		"empty_history_completeness_invalid/records_mode": func(b map[string]interface{}) {
			b["completeness"].(map[string]interface{})["records_mode"] = "declared_incomplete"
		},
		"empty_history_completeness_invalid/missing": func(b map[string]interface{}) {
			b["completeness"].(map[string]interface{})["missing"] = []interface{}{"00"}
		},
		"empty_history_completeness_invalid/missing not a list": func(b map[string]interface{}) {
			b["completeness"].(map[string]interface{})["missing"] = "none"
		},
		"empty_history_completeness_invalid/completeness": func(b map[string]interface{}) { b["completeness"] = "complete" },
		"empty_history_carries:completeness_certificate":  func(b map[string]interface{}) { b["completeness_certificate"] = map[string]interface{}{} },
		"empty_history_carries:disclosures":               func(b map[string]interface{}) { b["disclosures"] = map[string]interface{}{} },
		"empty_history_carries:disclosure_record":         func(b map[string]interface{}) { b["disclosure_record"] = "00" },
		"bundle_version_or_kind_invalid":                  func(b map[string]interface{}) { b["bundle_kind"] = "evidence-bundle/v1" },
	}
	for name, change := range changes {
		bundle := emptyMemberBundle(t, "controller-binding-empty-member-linked")
		change(bundle)
		result := VerifyBundle(bundle)
		require.Equal(t, "fail", result.GraphClosure.Status, name)
		require.Contains(t, result.GraphClosure.Findings, name[:len(name)-len(after(name))], name)
		require.Nil(t, result.History, name)
	}

	// An empty missing list is allowed.
	bundle := emptyMemberBundle(t, "controller-binding-empty-member-no-checkpoint")
	bundle["completeness"].(map[string]interface{})["missing"] = []interface{}{}
	require.NotNil(t, VerifyBundle(bundle).History)

	// A root with no records is not an empty-history Bundle.
	rooted := emptyMemberBundle(t, "controller-binding-empty-member-no-checkpoint")
	rooted["root"] = "00"
	require.False(t, EmptyHistory(rooted))
	result := VerifyBundle(rooted)
	require.Equal(t, []string{"root_not_supplied_with_matching_identity"}, result.GraphClosure.Findings)
	require.Nil(t, result.History)
}

// after returns the "/detail" suffix of a test name, or "".
func after(name string) string {
	for i := range name {
		if name[i] == '/' {
			return name[i:]
		}
	}
	return ""
}

// Only controller_binding derives against an empty member; another basis has
// no root record to point into, so the join is one_sided.
func TestEmptyMemberOtherBasisIsOneSided(t *testing.T) {
	for _, basis := range []string{"pre_agreed_identifier", "shared_artifact_digest"} {
		container, block, _ := emptyCase(t, "controller-binding-empty-member-linked")
		join := block["joins"].([]interface{})[0].(map[string]interface{})
		join["basis"] = basis
		result := verifyBlock(t, container, Options{})
		require.Equal(t, "one_sided", result.Joins[0].Derived, basis)
	}
}

// Two members without records are unjoined, whatever binds their keys.
func TestEmptyMembersOnBothSidesAreUnjoined(t *testing.T) {
	container, block, c := emptyCase(t, "controller-binding-empty-member-linked")
	memberByID(block, "responder-a")["bundle"] = cloneJSON(t, memberByID(block, "responder-b")["bundle"].(map[string]interface{}))
	result := verifyBlock(t, container, bindingOptions(c))
	require.Equal(t, "unjoined", result.Joins[0].Derived)
}

// The empty member's key is the one that signed its checkpoint: a binding
// over other keys does not link it.
func TestEmptyMemberCheckpointKeyMustBeBound(t *testing.T) {
	container, block, _ := emptyCase(t, "controller-binding-empty-member-linked")
	other := bindingCases(t)["controller-binding-other-keys"]
	otherJoin := composedBlockOf(other.Container)["joins"].([]interface{})[0].(map[string]interface{})
	block["joins"].([]interface{})[0].(map[string]interface{})["identifier_digest"] = otherJoin["identifier_digest"]
	result := verifyBlock(t, container, bindingOptions(other))
	require.Equal(t, "unjoined", result.Joins[0].Derived)
}

// The member with records still needs its pointer and its body.
func TestEmptyMemberJoinNeedsTheOtherRootRecord(t *testing.T) {
	container, block, c := emptyCase(t, "controller-binding-empty-member-linked")
	delete(block["joins"].([]interface{})[0].(map[string]interface{}), "pointer")
	require.Equal(t, "not_derivable", verifyBlock(t, container, bindingOptions(c)).Joins[0].Result)

	// Declared missing (listed, no body), the member with records does not
	// derive.
	container, block, c = emptyCase(t, "controller-binding-empty-member-linked")
	block["missing"] = []interface{}{"responder-a"}
	delete(memberByID(block, "responder-a"), "bundle")
	require.Equal(t, "not_derivable", verifyBlock(t, container, bindingOptions(c)).Joins[0].Result)

	// Listed but still carrying its body, it is not declared missing (a
	// composition-closure failure of its own), so the join derives.
	container, block, c = emptyCase(t, "controller-binding-empty-member-linked")
	block["missing"] = []interface{}{"responder-a"}
	result := verifyBlock(t, container, bindingOptions(c))
	require.Equal(t, "fail", result.CompositionClosure.Status)
	require.Equal(t, "one_sided", result.Joins[0].Derived)

	container, block, c = emptyCase(t, "controller-binding-empty-member-linked")
	bundle := memberByID(block, "responder-a")["bundle"].(map[string]interface{})
	bundle["root"] = "00"
	require.Equal(t, "not_derivable", verifyBlock(t, container, bindingOptions(c)).Joins[0].Result)
}
