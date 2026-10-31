// SPDX-License-Identifier: BSD-3-Clause
package bundle_test

import (
	strs "strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// claims is what the gate reads of a result's completeness claims, without
// their findings: the plain checks list some findings in map order, so a
// Bundle's findings can differ between two runs while the statuses agree.
func claims(result bundle.VerificationResult) [3]string {
	return [3]string{result.GraphClosure.Status, result.IntervalCoverage.Status, result.PerRecordMembership.Status}
}

// The producer-selected strict cases (vectors/bundle/strict) read for a page
// as the TypeScript context reads them: the valid selection verifies, and
// every selection the strict checks call INVALID is refused.
func TestVerifyBundleForPageProducerSelection(t *testing.T) {
	vectors := loadStrictVectors(t)
	seen := map[string]bool{}
	for _, c := range vectors.Cases {
		if !strs.Contains(c.ID, "producer-selected") {
			continue
		}
		seen[c.ID] = true
		result := bundle.VerifyBundleForPage(c.Bundle)
		switch {
		case c.ID == "incomplete-producer-selected":
			assert.True(t, bundle.Verified(result), c.ID)
			assert.Equal(t, "withheld", result.IntervalCoverage.Status, c.ID)
			assert.Contains(t, result.IntervalCoverage.Findings, "selection_not_checkable", c.ID)
		case strs.HasPrefix(c.ID, "neg-producer-selected-"):
			require.Equal(t, "INVALID", c.Expect["verdict"], c.ID)
			assert.False(t, bundle.Verified(result), c.ID)
			// Bundle -02's plain checks read the selection too; the page
			// keeps their other claims and fails per-record membership.
			plain := claims(bundle.VerifyBundle(c.Bundle))
			plain[2] = "fail"
			assert.Equal(t, plain, claims(result), "%s keeps the plain reading", c.ID)
		default:
			t.Fatalf("unexpected producer-selected case %s", c.ID)
		}
	}
	assert.True(t, seen["incomplete-producer-selected"])
	assert.Len(t, seen, 9)
}

// A Bundle that is not a producer selection reads exactly as VerifyBundle
// reads it.
func TestVerifyBundleForPageKeepsPlainReading(t *testing.T) {
	vectors := loadStrictVectors(t)
	checked := 0
	for _, c := range vectors.Cases {
		if strs.Contains(c.ID, "producer-selected") {
			continue
		}
		plain, page := bundle.VerifyBundle(c.Bundle), bundle.VerifyBundleForPage(c.Bundle)
		assert.Equal(t, claims(plain), claims(page), c.ID)
		assert.Equal(t, bundle.Verified(plain), bundle.Verified(page), c.ID)
		checked++
	}
	assert.Greater(t, checked, 40)
}

// The gate: per-record membership may fail only by records bound to no log
// position; a rejected entry, a failed closure, a failed record or a
// mismatched disclosure refuses the page.
func TestVerifiedGate(t *testing.T) {
	pass := bundle.ClaimResult{Status: "pass"}
	base := func() bundle.VerificationResult {
		return bundle.VerificationResult{
			GraphClosure:        pass,
			IntervalCoverage:    pass,
			PerRecordMembership: pass,
			CapsuleResults:      map[string]verify.VerificationResult{"a": {OK: true}},
			Disclosures:         []bundle.DisclosureResult{{Status: "withheld"}, {Status: "disclosure_match"}},
		}
	}
	assert.True(t, bundle.Verified(base()))

	unbound := base()
	unbound.PerRecordMembership = bundle.ClaimResult{Status: "fail", Findings: []string{"membership_record_unbound:b"}}
	assert.True(t, bundle.Verified(unbound), "an unbound record is coverage, not a broken proof")

	rejected := base()
	rejected.PerRecordMembership = bundle.ClaimResult{Status: "fail", Findings: []string{
		"membership_proof_invalid:b", "membership_record_unbound:b",
	}}
	assert.False(t, bundle.Verified(rejected), "a rejected entry's unbound twin does not count as unbound")

	empty := base()
	empty.PerRecordMembership = bundle.ClaimResult{Status: "fail"}
	assert.False(t, bundle.Verified(empty))

	closure := base()
	closure.GraphClosure = bundle.ClaimResult{Status: "withheld"}
	assert.False(t, bundle.Verified(closure))

	interval := base()
	interval.IntervalCoverage = bundle.ClaimResult{Status: "withheld", Findings: []string{"checkpoint_unverified"}}
	assert.False(t, bundle.Verified(interval), "only a producer selection exempts interval coverage")
	interval.IntervalCoverage.Findings = []string{"selection_not_checkable"}
	assert.True(t, bundle.Verified(interval))

	record := base()
	record.CapsuleResults["a"] = verify.VerificationResult{OK: false}
	assert.False(t, bundle.Verified(record))

	mismatch := base()
	mismatch.Disclosures = append(mismatch.Disclosures, bundle.DisclosureResult{Status: "disclosure_mismatch"})
	assert.False(t, bundle.Verified(mismatch))
}
