// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"regexp"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/disclosure"
)

// The verification a page states (spec/verification-display-v0.md): the
// reading of a Bundle a page is drawn from, and its gate. The TypeScript
// twins are bundle.ts buildVerifiedBundleContext and verification-page.ts
// bundleVerified, so both languages give the same Bundle the same page.

var invalidMembershipRE = regexp.MustCompile(`^membership_(?:proof_invalid|coordinates_missing|coordinates_invalid|record_unknown):(.+)$`)

const unboundPrefix = "membership_record_unbound:"

// unboundRecords counts the per-record membership findings that are a
// supplied record bound to no log position, leaving out one whose supplied
// entry was rejected (that record is named by the rejecting finding).
func unboundRecords(result VerificationResult) int {
	invalid := map[string]bool{}
	for _, finding := range result.PerRecordMembership.Findings {
		if match := invalidMembershipRE.FindStringSubmatch(finding); match != nil {
			invalid[match[1]] = true
		}
	}
	count := 0
	for _, finding := range result.PerRecordMembership.Findings {
		if id, ok := strings.CutPrefix(finding, unboundPrefix); ok && !invalid[id] {
			count++
		}
	}
	return count
}

// Verified is the viewer's verification gate: what "verified" means for a
// page (spec/verification-display-v0.md section 1). Every completeness claim
// passes (per-record membership may fail solely because some supplied
// records sit outside any checkpoint), every record's identity verifies, and
// every disclosure matches or is withheld.
//
// A producer-selected Bundle, as VerifyBundleForPage reads it, has no
// interval to check, so its interval coverage is exempt; each record's own
// inclusion proof is gated like any Bundle's membership. This is the
// TypeScript gate (bundleVerified), so both languages decide the same Bundle
// the same way.
func Verified(result VerificationResult) bool {
	membership := result.PerRecordMembership
	if result.GraphClosure.Status != "pass" ||
		(result.IntervalCoverage.Status != "pass" && !producerSelection(result)) {
		return false
	}
	if membership.Status != "pass" &&
		!(membership.Status == "fail" && len(membership.Findings) > 0 && len(membership.Findings) == unboundRecords(result)) {
		return false
	}
	for _, capsule := range result.CapsuleResults {
		if !capsule.OK {
			return false
		}
	}
	for _, d := range result.Disclosures {
		if d.Status != disclosure.Match && d.Status != "withheld" {
			return false
		}
	}
	return true
}

// VerifyBundleForPage verifies value as the TypeScript context does (bundle.ts
// buildVerifiedBundleContext): the plain result of VerifyBundle, except that
// for a producer selection the strict checks did not reject, interval
// coverage and per-record membership are the strict readings (VerifyStrict).
// The plain checks do not know a producer selection and read it as an
// interval; an INVALID selection keeps the plain reading, so Verified stays
// false for it.
func VerifyBundleForPage(value interface{}) VerificationResult {
	result := VerifyBundle(value)
	if strict := VerifyStrict(value, StrictOptions{}); strict.Verdict != VerdictInvalid &&
		producerSelection(strict.VerificationResult) {
		result.IntervalCoverage = strict.IntervalCoverage
		result.PerRecordMembership = strict.PerRecordMembership
	}
	return result
}

// producerSelection reports whether result reads its Bundle as a producer
// selection: interval coverage is withheld as not checkable (TypeScript
// isProducerSelection).
func producerSelection(result VerificationResult) bool {
	if result.IntervalCoverage.Status != "withheld" {
		return false
	}
	for _, finding := range result.IntervalCoverage.Findings {
		if finding == "selection_not_checkable" {
			return true
		}
	}
	return false
}
