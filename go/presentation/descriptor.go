// SPDX-License-Identifier: BSD-3-Clause
package presentation

import (
	"regexp"
	"sort"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/action-state-group/agent-action-capsule/go/disclosure"
)

// ResultVersion is the Evidence Result v0 document version.
const ResultVersion = "evidence-result-v0"

// ResultRecordType is the record_type of an Evidence Result book record header.
const ResultRecordType = "evidence_result"

// Descriptor is the resolution input of spec section 4.2. It never carries
// the audience or the format.
type Descriptor struct {
	// Verified is whether the bundle passed the verification gate.
	Verified bool `json:"verified"`
	// BundleKind is the bundle's bundle_kind string; nil when it has none.
	BundleKind *string `json:"bundle_kind"`
	// Profiles is the root's profile tokens, sorted.
	Profiles []string `json:"profiles"`
	// Extensions is the engaged extension kinds, sorted.
	Extensions []string `json:"extensions"`
}

var invalidMembershipRE = regexp.MustCompile(`^membership_(?:proof_invalid|coordinates_missing|coordinates_invalid|record_unknown):(.+)$`)

const unboundPrefix = "membership_record_unbound:"

// unboundRecords counts the per-record membership findings that are a
// supplied record bound to no log position, leaving out one whose supplied
// entry was rejected (that record is named by the rejecting finding).
func unboundRecords(result bundle.VerificationResult) int {
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

// Verified is the viewer's verification gate: what "verified" means for
// resolution. Every completeness claim passes (per-record membership may
// fail solely because some supplied records sit outside any checkpoint),
// every record's identity verifies, and every disclosure matches or is
// withheld.
func Verified(result bundle.VerificationResult) bool {
	membership := result.PerRecordMembership
	if result.GraphClosure.Status != "pass" || result.IntervalCoverage.Status != "pass" {
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

// extensionReaders are the extension kinds whose core reader can decline a
// present block (section 4.2). A kind not listed is engaged when present.
var extensionReaders = map[string]func(block interface{}) bool{
	"outcome-report/v1":       outcomeReportEngaged,
	"eu-ai-act-compliance/v1": complianceEngaged,
}

// outcomeReportEngaged: the outcome-report/v1 reader accepts a block whose
// enabled is true.
func outcomeReportEngaged(block interface{}) bool {
	value, ok := object(block)
	return ok && value["enabled"] == true
}

// complianceEngaged: the eu-ai-act-compliance/v1 reader accepts a block
// whose enabled is true and that carries at least one recognizable
// obligation (string key, article, title, plain and method, and an
// applicability of status in_force or future with a string note).
func complianceEngaged(block interface{}) bool {
	value, ok := object(block)
	if !ok || value["enabled"] != true {
		return false
	}
	obligations, _ := value["obligations"].([]interface{})
	for _, raw := range obligations {
		if obligationRecognizable(raw) {
			return true
		}
	}
	return false
}

func obligationRecognizable(raw interface{}) bool {
	obligation, ok := object(raw)
	if !ok {
		return false
	}
	for _, member := range []string{"key", "article", "title", "plain", "method"} {
		if _, isString := obligation[member].(string); !isString {
			return false
		}
	}
	applicability, ok := object(obligation["applicability"])
	if !ok {
		return false
	}
	status := applicability["status"]
	_, note := applicability["note"].(string)
	return (status == "in_force" || status == "future") && note
}

// verifiedContext is the part of the TypeScript VerifiedBundleContext the
// descriptor reads: the records whose identity verified and each member's
// disclosure as the verifier classified it.
type verifiedContext struct {
	overlay map[string]interface{}
	records map[string]bool
	status  map[[2]string]string
}

func newVerifiedContext(top map[string]interface{}, result bundle.VerificationResult) verifiedContext {
	ctx := verifiedContext{records: map[string]bool{}, status: map[[2]string]string{}}
	ctx.overlay, _ = object(top["disclosures"])
	records, _ := top["records"].([]interface{})
	for _, raw := range records {
		record, ok := object(raw)
		if !ok {
			continue
		}
		id, ok := record["capsule_id"].(string)
		if !ok || ctx.records[id] {
			continue
		}
		capsule, present := result.CapsuleResults[id]
		if present && capsule.OK && capsule.CapsuleID != nil && *capsule.CapsuleID == id {
			ctx.records[id] = true
		}
	}
	for _, d := range result.Disclosures {
		ctx.status[[2]string{d.CapsuleID, d.Member}] = d.Status
	}
	return ctx
}

// payload is a member's verified payload: present only when the record's
// identity verified, the verifier classified the member a match, and the
// overlay carries it.
func (c verifiedContext) payload(id, member string) (interface{}, bool) {
	if !c.records[id] || c.status[[2]string{id, member}] != disclosure.Match {
		return nil, false
	}
	entry, ok := object(c.overlay[id])
	if !ok {
		return nil, false
	}
	value, present := entry[member]
	return value, present
}

// carriesResult is the Result-root test: a disclosed member of the root that
// carries an Evidence Result v0, in payload form (result_version) in
// agent_output or agent_input, or in book form (an agent_input record header
// of record_type evidence_result).
func (c verifiedContext) carriesResult(root string) bool {
	for _, member := range []string{"agent_output", "agent_input"} {
		value, _ := c.payload(root, member)
		document, ok := object(value)
		if !ok {
			continue
		}
		if document["result_version"] == ResultVersion {
			return true
		}
		if member == "agent_input" && document["record_type"] == ResultRecordType {
			return true
		}
	}
	return false
}

// Describe is the descriptor of spec section 4.2 for value, the bundle as
// decoded (with json.Number numbers, as bundle.DecodeFragment decodes it),
// and result, bundle.VerifyBundle's result for that same value.
//
//   - Profiles: spec_version:<v> when the root's agent_input is disclosed and
//     carries a string spec_version; result_version:evidence-result-v0 when
//     the root carries an Evidence Result v0 in a disclosed member.
//   - Extensions: every member of the bundle's extensions object the core's
//     reader accepts (outcome-report/v1 and eu-ai-act-compliance/v1 can
//     decline; every other kind is engaged when present).
//
// Nothing in an unverified bundle is read beyond its bundle_kind.
func Describe(value interface{}, result bundle.VerificationResult) Descriptor {
	top, _ := object(value)
	d := Descriptor{Verified: Verified(result), Profiles: []string{}, Extensions: []string{}}
	if kind, ok := top["bundle_kind"].(string); ok {
		d.BundleKind = &kind
	}
	if !d.Verified {
		return d
	}
	ctx := newVerifiedContext(top, result)
	if root, ok := top["root"].(string); ok && ctx.records[root] {
		input, _ := ctx.payload(root, "agent_input")
		if document, ok := object(input); ok {
			if version, ok := document["spec_version"].(string); ok {
				d.Profiles = append(d.Profiles, "spec_version:"+version)
			}
		}
		if ctx.carriesResult(root) {
			d.Profiles = append(d.Profiles, "result_version:"+ResultVersion)
		}
	}
	if extensions, ok := object(top["extensions"]); ok {
		for kind, block := range extensions {
			if reader, known := extensionReaders[kind]; !known || reader(block) {
				d.Extensions = append(d.Extensions, kind)
			}
		}
	}
	sort.Strings(d.Profiles)
	sort.Strings(d.Extensions)
	return d
}

// DescribeBundle verifies value with bundle.VerifyBundle and describes it.
func DescribeBundle(value interface{}) (Descriptor, bundle.VerificationResult) {
	result := bundle.VerifyBundle(value)
	return Describe(value, result), result
}
