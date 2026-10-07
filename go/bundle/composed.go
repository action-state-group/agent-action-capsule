// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

// ComposedKind is the registered extension kind this file interprets
// (draft-mih-zhang-agent-disclosure-bundle-01, "The composed/v1 Extension").
const ComposedKind = "composed/v1"

// Refusal signature states reported on a refusal member.
const (
	RefusalSignatureVerified   = "verified"
	RefusalSignatureInvalid    = "invalid"
	RefusalSignatureUnverified = "signature_unverified"
)

// RefusalSignatureVerifier checks a carried signed refusal under the
// deployment's signature profile. It returns RefusalSignatureVerified,
// RefusalSignatureInvalid, or RefusalSignatureUnverified when the refusal is
// not in a form the profile can check (for example, it carries no key). The
// draft leaves the signature format to the deployment, so the neutral core
// ships no profile: without a verifier every refusal is signature-unverified,
// which is neither failed nor absent.
type RefusalSignatureVerifier func(refusal map[string]interface{}) string

// Options configures VerifyBundleWithOptions.
type Options struct {
	RefusalSignature RefusalSignatureVerifier
}

// ComposedDigestResult is the recomputed composed digest beside the declared one.
type ComposedDigestResult struct {
	Declared   string
	Recomputed string
	Matches    bool
}

// ComposedMemberResult reports one member: its outcome, whether its body is
// carried or declared missing, whether the body reproduces its digest, and,
// for a carried artifact, the member Evidence Bundle's own verification. The
// member's claims are its own; they are never merged into another member's,
// the containing Bundle's, or composition closure.
type ComposedMemberResult struct {
	ID       string
	Observer string
	Outcome  string
	// Body is "carried", "declared_missing" or "absent" (neither carried nor
	// listed in missing, a composition-closure failure).
	Body string
	// Digest is "reproduced", "mismatch" or "not_shown" (no body carried).
	Digest   string
	Findings []string
	// Bundle is the member Evidence Bundle's verification (artifact, carried).
	Bundle *VerificationResult
	// RefusalSignature is set for a carried refusal.
	RefusalSignature string
}

// CompositionClosureResult is the fourth completeness claim.
type CompositionClosureResult struct {
	ClaimResult
	Missing []string
}

// JoinDifference is one compare pointer whose values differ on a derived
// mismatch: each member's value at that pointer (Resolved false when the
// pointer does not resolve in that member's root record). No winner is named.
type JoinDifference struct {
	Pointer string
	Values  []JoinValue
}

// JoinValue is one member's value at a compare pointer.
type JoinValue struct {
	Member   string
	Resolved bool
	Value    interface{}
}

// ComposedJoinResult reports a join: the declared state, the derived state
// (empty when not derivable), and whether they match.
type ComposedJoinResult struct {
	Members  [2]string
	Basis    string
	Declared string
	// Derived is empty when the state is not derivable.
	Derived string
	// Result is "derived_matches", "join_state_mismatch" or "not_derivable".
	Result      string
	Differences []JoinDifference
}

// CorroborationResult reports, per join, what a derived agreement is worth.
// Result is "corroborating" (always with Qualifier "custody_declared"),
// "redundant" (with Reason and Report "redundant, not corroborating") or
// "not_applicable" (the join did not derive agree). Results are never
// combined into a count or a score.
type CorroborationResult struct {
	Members   [2]string
	Result    string
	Reason    string
	Reasons   []string
	Report    string
	Qualifier string
}

// ComposedResult is the verification of one composed/v1 block. Status is the
// block's own result: "fail" when the block is malformed, the composed digest
// does not recompute, a member body fails its checks, composition closure
// fails or a declared join state does not match its derivation; "withheld"
// when nothing failed but something is not shown (a declared-missing member,
// a non-derivable join, an unverified refusal signature); otherwise "pass".
// Member bundles' own claims are reported on each member and do not enter
// Status.
type ComposedResult struct {
	Status   string
	Findings []string
	// Malformed is true when the block violates the draft's block rules; no
	// composition result is reported from a malformed block.
	Malformed          bool
	ComposedDigest     *ComposedDigestResult
	Members            []ComposedMemberResult
	CompositionClosure *CompositionClosureResult
	Joins              []ComposedJoinResult
	Corroboration      []CorroborationResult
}

var labelRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

var (
	composedOutcomes = map[string]string{"artifact": "bundle", "refusal": "refusal", "absence": "absence"}
	joinBases        = map[string]bool{"pre_agreed_identifier": true, "shared_artifact_digest": true, "issued_receipt": true, "same_interval": true}
	joinStates       = map[string]bool{"agree": true, "mismatch": true, "unjoined": true, "one_sided": true}
)

type composedMember struct {
	id, observer, requestDigest, outcome, digest string
	body                                         map[string]interface{}
}

type composedObserver struct{ id, role, custody string }

type composedJoin struct {
	members        [2]string
	basis, state   string
	pointer        *string
	identifier     *string
	compare        []string
	compareCarried bool
}

type composedBlock struct {
	members      []composedMember
	observers    []composedObserver
	joins        []composedJoin
	notRequested []string
	missing      []string
	digest       string
}

// VerifyComposed verifies a composed/v1 block as carried in a Bundle's
// extensions. Carried member bundles are verified recursively with opts.
func VerifyComposed(raw interface{}, opts Options) ComposedResult {
	block, reason := parseComposed(raw)
	if reason != "" {
		return ComposedResult{Status: "fail", Malformed: true, Findings: []string{"composed_block_malformed:" + reason}}
	}
	result := ComposedResult{}
	var failed, withheld []string

	recomputed, err := ComposedDigest(raw)
	digest := ComposedDigestResult{Declared: block.digest, Recomputed: recomputed, Matches: err == nil && recomputed == block.digest}
	result.ComposedDigest = &digest
	if !digest.Matches {
		failed = append(failed, "composed_digest_mismatch")
	}

	missing := make(map[string]bool, len(block.missing))
	declared := make(map[string]bool, len(block.members))
	for _, m := range block.members {
		declared[m.id] = true
	}
	var closureFindings []string
	for _, id := range block.missing {
		if missing[id] {
			closureFindings = append(closureFindings, "missing_duplicate:"+id)
		}
		missing[id] = true
		if !declared[id] {
			closureFindings = append(closureFindings, "missing_names_undeclared_member:"+id)
		}
	}

	byID := make(map[string]composedMember, len(block.members))
	for _, m := range block.members {
		byID[m.id] = m
		member, memberClosure, memberFailed, memberWithheld := verifyMember(m, missing[m.id], opts)
		result.Members = append(result.Members, member)
		closureFindings = append(closureFindings, memberClosure...)
		failed = append(failed, memberFailed...)
		withheld = append(withheld, memberWithheld...)
	}

	closure := CompositionClosureResult{Missing: sortedUnique(block.missing)}
	switch {
	case len(closureFindings) != 0:
		closure.ClaimResult = ClaimResult{Status: "fail", Findings: closureFindings}
		failed = append(failed, "composition_closure_fail")
	case len(block.missing) != 0:
		closure.ClaimResult = ClaimResult{Status: "withheld", Findings: []string{"declared_incomplete"}}
		withheld = append(withheld, "declared_incomplete")
	default:
		closure.ClaimResult = ClaimResult{Status: "pass"}
	}
	result.CompositionClosure = &closure

	observers := make(map[string]composedObserver, len(block.observers))
	for _, o := range block.observers {
		observers[o.id] = o
	}
	for _, j := range block.joins {
		joinResult := deriveJoin(j, byID, missing)
		result.Joins = append(result.Joins, joinResult)
		pair := j.members[0] + "," + j.members[1]
		switch joinResult.Result {
		case "join_state_mismatch":
			failed = append(failed, "join_state_mismatch:"+pair)
		case "not_derivable":
			withheld = append(withheld, "join_not_derivable:"+pair)
		}
		result.Corroboration = append(result.Corroboration, corroboration(j, joinResult.Derived, byID, observers))
	}

	switch {
	case len(failed) != 0:
		result.Status = "fail"
		result.Findings = append(failed, withheld...)
	case len(withheld) != 0:
		result.Status = "withheld"
		result.Findings = withheld
	default:
		result.Status = "pass"
	}
	return result
}

func verifyMember(m composedMember, declaredMissing bool, opts Options) (ComposedMemberResult, []string, []string, []string) {
	out := ComposedMemberResult{ID: m.id, Observer: m.observer, Outcome: m.outcome, Digest: "not_shown"}
	var closure, failed, withheld []string
	switch {
	case declaredMissing && m.body != nil:
		out.Body = "carried"
		closure = append(closure, "missing_member_carries_body:"+m.id)
	case declaredMissing:
		out.Body = "declared_missing"
		return out, nil, nil, nil
	case m.body == nil:
		out.Body = "absent"
		closure = append(closure, "member_body_absent:"+m.id)
		out.Findings = append(out.Findings, "member_body_absent")
		return out, closure, nil, nil
	default:
		out.Body = "carried"
	}

	var computed string
	var err error
	if m.outcome == "artifact" {
		computed, err = BundleDigest(m.body)
		verification := VerifyBundleWithOptions(m.body, opts)
		out.Bundle = &verification
	} else {
		computed, err = canonical.JSONDigest(m.body)
		if m.body["request_digest"] != m.requestDigest {
			out.Findings = append(out.Findings, "request_digest_mismatch")
			failed = append(failed, "member_request_digest_mismatch:"+m.id)
		}
	}
	if err == nil && computed == m.digest {
		out.Digest = "reproduced"
	} else {
		out.Digest = "mismatch"
		out.Findings = append(out.Findings, "member_digest_mismatch")
		closure = append(closure, "member_digest_mismatch:"+m.id)
	}
	if m.outcome == "refusal" {
		out.RefusalSignature = RefusalSignatureUnverified
		if opts.RefusalSignature != nil {
			switch state := opts.RefusalSignature(m.body); state {
			case RefusalSignatureVerified, RefusalSignatureInvalid:
				out.RefusalSignature = state
			}
		}
		switch out.RefusalSignature {
		case RefusalSignatureInvalid:
			out.Findings = append(out.Findings, "refusal_signature_invalid")
			failed = append(failed, "refusal_signature_invalid:"+m.id)
		case RefusalSignatureUnverified:
			withheld = append(withheld, "refusal_signature_unverified:"+m.id)
		}
	}
	return out, closure, failed, withheld
}

// rootRecord returns the carried member bundle's root record, or nil.
func rootRecord(m composedMember) map[string]interface{} {
	if m.body == nil {
		return nil
	}
	root, ok := m.body["root"].(string)
	if !ok {
		return nil
	}
	records, _ := m.body["records"].([]interface{})
	for _, raw := range records {
		if record, ok := raw.(map[string]interface{}); ok && record["capsule_id"] == root {
			return record
		}
	}
	return nil
}

func deriveJoin(j composedJoin, byID map[string]composedMember, missing map[string]bool) ComposedJoinResult {
	out := ComposedJoinResult{Members: j.members, Basis: j.basis, Declared: j.state}
	out.Derived, out.Differences = derivedState(j, byID, missing)
	switch {
	case out.Derived == "":
		out.Result = "not_derivable"
	case out.Derived == j.state:
		out.Result = "derived_matches"
	default:
		out.Result = "join_state_mismatch"
	}
	return out
}

func derivedState(j composedJoin, byID map[string]composedMember, missing map[string]bool) (string, []JoinDifference) {
	a, b := byID[j.members[0]], byID[j.members[1]]
	artifacts := 0
	for _, m := range []composedMember{a, b} {
		if m.outcome == "artifact" {
			artifacts++
		}
	}
	switch artifacts {
	case 0:
		return "unjoined", nil
	case 1:
		return "one_sided", nil
	}
	if missing[a.id] || missing[b.id] {
		return "", nil
	}
	ra, rb := rootRecord(a), rootRecord(b)
	if ra == nil || rb == nil {
		return "", nil
	}
	var linked bool
	switch j.basis {
	case "pre_agreed_identifier":
		linked = j.pointer != nil && j.identifier != nil &&
			identifierMatches(ra, *j.pointer, *j.identifier) && identifierMatches(rb, *j.pointer, *j.identifier)
	case "shared_artifact_digest":
		if j.pointer != nil {
			va, okA := resolvePointer(ra, *j.pointer)
			vb, okB := resolvePointer(rb, *j.pointer)
			sa, strA := va.(string)
			sb, strB := vb.(string)
			linked = okA && okB && strA && strB && sa == sb
		}
	default:
		return "", nil
	}
	if !linked {
		return "unjoined", nil
	}
	var differences []JoinDifference
	for _, pointer := range j.compare {
		va, okA := resolvePointer(ra, pointer)
		vb, okB := resolvePointer(rb, pointer)
		if okA && okB {
			ja, errA := canonical.JCS(va)
			jb, errB := canonical.JCS(vb)
			if errA == nil && errB == nil && string(ja) == string(jb) {
				continue
			}
		}
		differences = append(differences, JoinDifference{Pointer: pointer, Values: []JoinValue{
			{Member: a.id, Resolved: okA, Value: va},
			{Member: b.id, Resolved: okB, Value: vb},
		}})
	}
	if len(differences) != 0 {
		return "mismatch", differences
	}
	return "agree", nil
}

func identifierMatches(record map[string]interface{}, pointer, digest string) bool {
	value, ok := resolvePointer(record, pointer)
	identifier, isString := value.(string)
	if !ok || !isString {
		return false
	}
	sum := sha256.Sum256([]byte(identifier))
	return hex.EncodeToString(sum[:]) == digest
}

func corroboration(j composedJoin, derived string, byID map[string]composedMember, observers map[string]composedObserver) CorroborationResult {
	out := CorroborationResult{Members: j.members}
	if derived != "agree" {
		out.Result = "not_applicable"
		return out
	}
	a, b := byID[j.members[0]], byID[j.members[1]]
	if a.observer == b.observer {
		out.Reasons = append(out.Reasons, "same_observer")
	}
	if observers[a.observer].custody == observers[b.observer].custody {
		out.Reasons = append(out.Reasons, "same_custody_domain")
	}
	keyA, okA := rootRecord(a)["key_id"].(string)
	keyB, okB := rootRecord(b)["key_id"].(string)
	if okA && okB && keyA == keyB {
		out.Reasons = append(out.Reasons, "same_key_id")
	}
	if len(out.Reasons) != 0 {
		out.Result = "redundant"
		out.Reason = out.Reasons[0]
		out.Report = "redundant, not corroborating"
		return out
	}
	out.Result = "corroborating"
	out.Qualifier = "custody_declared"
	return out
}

// ComposedDigest recomputes a composed/v1 block's composed digest from its
// declarations alone: lowercase-hex SHA-256 of the JCS serialization of the
// digest input D = {kind, members, observers, joins, not_requested}, each
// array reduced to its declared fields and sorted. Member bodies, missing and
// composed_digest are excluded. It fails on a malformed block.
func ComposedDigest(raw interface{}) (string, error) {
	preimage, err := ComposedDigestPreimage(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

// ComposedDigestPreimage returns the UTF-8 JCS bytes of the digest input D.
func ComposedDigestPreimage(raw interface{}) ([]byte, error) {
	block, reason := parseComposed(raw)
	if reason != "" {
		return nil, &malformedError{reason}
	}
	members := append([]composedMember(nil), block.members...)
	sort.Slice(members, func(i, k int) bool { return members[i].id < members[k].id })
	memberValues := make([]interface{}, len(members))
	for i, m := range members {
		memberValues[i] = map[string]interface{}{
			"id": m.id, "observer": m.observer, "request_digest": m.requestDigest, "outcome": m.outcome, "digest": m.digest,
		}
	}
	observers := append([]composedObserver(nil), block.observers...)
	sort.Slice(observers, func(i, k int) bool { return observers[i].id < observers[k].id })
	observerValues := make([]interface{}, len(observers))
	for i, o := range observers {
		observerValues[i] = map[string]interface{}{"id": o.id, "role": o.role, "custody_domain": o.custody}
	}
	joins := append([]composedJoin(nil), block.joins...)
	sort.Slice(joins, func(i, k int) bool { return joinKey(joins[i]) < joinKey(joins[k]) })
	joinValues := make([]interface{}, len(joins))
	for i, j := range joins {
		value := map[string]interface{}{
			"members": []interface{}{j.members[0], j.members[1]}, "basis": j.basis, "state": j.state,
		}
		if j.pointer != nil {
			value["pointer"] = *j.pointer
		}
		if j.identifier != nil {
			value["identifier_digest"] = *j.identifier
		}
		if j.compareCarried {
			compare := make([]interface{}, len(j.compare))
			for c, pointer := range j.compare {
				compare[c] = pointer
			}
			value["compare"] = compare
		}
		joinValues[i] = value
	}
	notRequested := append([]string(nil), block.notRequested...)
	sort.Strings(notRequested)
	notRequestedValues := make([]interface{}, len(notRequested))
	for i, id := range notRequested {
		notRequestedValues[i] = id
	}
	return canonical.JCS(map[string]interface{}{
		"kind":          ComposedKind,
		"members":       memberValues,
		"observers":     observerValues,
		"joins":         joinValues,
		"not_requested": notRequestedValues,
	})
}

// joinKey orders joins by members[0], members[1], basis, then pointer (the
// empty string when absent). label-id and basis tokens exclude NUL, so a NUL
// separator keeps the tuple order.
func joinKey(j composedJoin) string {
	pointer := ""
	if j.pointer != nil {
		pointer = *j.pointer
	}
	return j.members[0] + "\x00" + j.members[1] + "\x00" + j.basis + "\x00" + pointer
}

type malformedError struct{ reason string }

func (e *malformedError) Error() string { return "composed/v1 block malformed: " + e.reason }

func parseComposed(raw interface{}) (composedBlock, string) {
	var block composedBlock
	value, ok := raw.(map[string]interface{})
	if !ok {
		return block, "not_an_object"
	}
	digest, ok := value["composed_digest"].(string)
	if !ok || !hex64RE.MatchString(digest) {
		return block, "composed_digest"
	}
	block.digest = digest

	observerList, ok := value["observers"].([]interface{})
	if !ok || len(observerList) == 0 {
		return block, "observers"
	}
	observerIDs := map[string]bool{}
	for i, rawObserver := range observerList {
		o, ok := rawObserver.(map[string]interface{})
		id, idOK := o["id"].(string)
		role, roleOK := o["role"].(string)
		custody, custodyOK := o["custody_domain"].(string)
		if !ok || !idOK || !labelRE.MatchString(id) || !roleOK || !custodyOK {
			return block, "observer:" + strconv.Itoa(i)
		}
		if observerIDs[id] {
			return block, "observer_id_duplicate:" + id
		}
		observerIDs[id] = true
		block.observers = append(block.observers, composedObserver{id, role, custody})
	}

	memberList, ok := value["members"].([]interface{})
	if !ok || len(memberList) == 0 {
		return block, "members"
	}
	memberIDs := map[string]bool{}
	for i, rawMember := range memberList {
		m, reason := parseMember(rawMember, observerIDs)
		if reason != "" {
			return block, "member:" + strconv.Itoa(i) + ":" + reason
		}
		if memberIDs[m.id] {
			return block, "member_id_duplicate:" + m.id
		}
		memberIDs[m.id] = true
		block.members = append(block.members, m)
	}

	joinList, ok := optionalArray(value, "joins")
	if !ok {
		return block, "joins"
	}
	seen := map[string]bool{}
	for i, rawJoin := range joinList {
		j, reason := parseJoin(rawJoin, memberIDs)
		if reason != "" {
			return block, "join:" + strconv.Itoa(i) + ":" + reason
		}
		key := joinKey(j)
		if j.pointer == nil {
			key += "\x00absent"
		}
		if seen[key] {
			return block, "join_duplicate:" + strconv.Itoa(i)
		}
		seen[key] = true
		block.joins = append(block.joins, j)
	}

	var reason string
	if block.notRequested, reason = labelArray(value, "not_requested"); reason != "" {
		return block, reason
	}
	for _, id := range block.notRequested {
		if memberIDs[id] {
			return block, "not_requested_is_member:" + id
		}
	}
	if block.missing, reason = labelArray(value, "missing"); reason != "" {
		return block, reason
	}
	return block, ""
}

func parseMember(raw interface{}, observers map[string]bool) (composedMember, string) {
	var m composedMember
	value, ok := raw.(map[string]interface{})
	if !ok {
		return m, "not_an_object"
	}
	var idOK, observerOK, requestOK, outcomeOK, digestOK bool
	m.id, idOK = value["id"].(string)
	m.observer, observerOK = value["observer"].(string)
	m.requestDigest, requestOK = value["request_digest"].(string)
	m.outcome, outcomeOK = value["outcome"].(string)
	m.digest, digestOK = value["digest"].(string)
	switch {
	case !idOK || !labelRE.MatchString(m.id):
		return m, "id"
	case !observerOK || !labelRE.MatchString(m.observer):
		return m, "observer"
	case !observers[m.observer]:
		return m, "observer_undeclared"
	case !requestOK || !hex64RE.MatchString(m.requestDigest):
		return m, "request_digest"
	case !digestOK || !hex64RE.MatchString(m.digest):
		return m, "digest"
	}
	bodyKey, known := composedOutcomes[m.outcome]
	if !outcomeOK || !known {
		return m, "outcome"
	}
	// A body under another outcome's member name would convert one outcome
	// into another; the outcomes are never converted.
	for _, other := range composedOutcomes {
		if _, present := value[other]; present && other != bodyKey {
			return m, "body_outcome_conflict"
		}
	}
	rawBody, present := value[bodyKey]
	if !present {
		return m, ""
	}
	body, ok := rawBody.(map[string]interface{})
	if !ok {
		return m, "body"
	}
	switch m.outcome {
	case "refusal":
		if !isDigest(body["request_digest"]) || !isString(body["reason"]) || !isString(body["issued_at"]) {
			return m, "refusal_body"
		}
	case "absence":
		window, windowOK := body["window"].(map[string]interface{})
		if !isDigest(body["request_digest"]) || !windowOK || !isString(window["from"]) || !isString(window["to"]) {
			return m, "absence_body"
		}
		if route, present := body["route"]; present && !isString(route) {
			return m, "absence_body"
		}
		if commitment, present := body["commitment"]; present && !isDigest(commitment) {
			return m, "absence_body"
		}
	}
	m.body = body
	return m, ""
}

func parseJoin(raw interface{}, members map[string]bool) (composedJoin, string) {
	var j composedJoin
	value, ok := raw.(map[string]interface{})
	if !ok {
		return j, "not_an_object"
	}
	pair, ok := value["members"].([]interface{})
	if !ok || len(pair) != 2 {
		return j, "members"
	}
	for i := range pair {
		id, ok := pair[i].(string)
		if !ok || !labelRE.MatchString(id) || !members[id] {
			return j, "members"
		}
		j.members[i] = id
	}
	if j.members[0] >= j.members[1] {
		return j, "members_order"
	}
	var basisOK, stateOK bool
	j.basis, basisOK = value["basis"].(string)
	j.state, stateOK = value["state"].(string)
	if !basisOK || !joinBases[j.basis] {
		return j, "basis"
	}
	if !stateOK || !joinStates[j.state] {
		return j, "state"
	}
	if rawPointer, present := value["pointer"]; present {
		pointer, ok := rawPointer.(string)
		if !ok || !validPointer(pointer) {
			return j, "pointer"
		}
		j.pointer = &pointer
	}
	if rawDigest, present := value["identifier_digest"]; present {
		digest, ok := rawDigest.(string)
		if !ok || !hex64RE.MatchString(digest) {
			return j, "identifier_digest"
		}
		j.identifier = &digest
	}
	if rawCompare, present := value["compare"]; present {
		list, ok := rawCompare.([]interface{})
		if !ok || len(list) == 0 {
			return j, "compare"
		}
		for _, rawPointer := range list {
			pointer, ok := rawPointer.(string)
			if !ok || !validPointer(pointer) {
				return j, "compare"
			}
			j.compare = append(j.compare, pointer)
		}
		j.compareCarried = true
	}
	return j, ""
}

// optionalArray returns an optional array member; ok is false when the member
// is present but not an array.
func optionalArray(value map[string]interface{}, key string) ([]interface{}, bool) {
	raw, present := value[key]
	if !present {
		return nil, true
	}
	list, ok := raw.([]interface{})
	return list, ok
}

func labelArray(value map[string]interface{}, key string) ([]string, string) {
	list, ok := optionalArray(value, key)
	if !ok {
		return nil, key
	}
	labels := make([]string, 0, len(list))
	for _, raw := range list {
		label, ok := raw.(string)
		if !ok || !labelRE.MatchString(label) {
			return nil, key
		}
		labels = append(labels, label)
	}
	return labels, ""
}

func isString(value interface{}) bool {
	_, ok := value.(string)
	return ok
}

func isDigest(value interface{}) bool {
	digest, ok := value.(string)
	return ok && hex64RE.MatchString(digest)
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

// validPointer reports whether pointer is an RFC 6901 JSON Pointer: empty, or
// "/"-prefixed reference tokens in which "~" appears only as "~0" or "~1".
func validPointer(pointer string) bool {
	if pointer == "" {
		return true
	}
	if pointer[0] != '/' {
		return false
	}
	for i := 0; i < len(pointer); i++ {
		if pointer[i] == '~' && (i+1 >= len(pointer) || (pointer[i+1] != '0' && pointer[i+1] != '1')) {
			return false
		}
	}
	return true
}

// resolvePointer evaluates an RFC 6901 JSON Pointer against a decoded JSON
// value. It reports false when any reference token does not resolve.
func resolvePointer(document interface{}, pointer string) (interface{}, bool) {
	if !validPointer(pointer) {
		return nil, false
	}
	if pointer == "" {
		return document, true
	}
	current := document
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch node := current.(type) {
		case map[string]interface{}:
			next, ok := node[token]
			if !ok {
				return nil, false
			}
			current = next
		case []interface{}:
			if token == "" || (len(token) > 1 && token[0] == '0') {
				return nil, false
			}
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) || strconv.Itoa(index) != token {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	return current, true
}
