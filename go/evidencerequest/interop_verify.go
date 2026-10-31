// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The envelope properties of profile §7.2, in the order a report lists
// them.
var EnvelopeProperties = []string{
	"profile_version", "envelope_signature", "responder_trust", "responder_key_current", "issued_at_form",
	"request_binding", "subject_binding", "artifact_digest", "verification_binding", "anchor_match",
	"anchor_inclusion",
}

// The refusal properties of profile §7.2, in the order a report lists them.
var RefusalProperties = []string{
	"refusal_signature", "responder_trust", "responder_key_current", "request_binding", "reason_registered",
	"issued_at_form",
}

// The members the envelope signature covers, when present (§6.2).
var envelopeSigned = []string{"profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest",
	"verification", "responder", "issued_at"}

var absenceMembers = []string{"outcome", "request_digest", "route", "window", "recorded_at", "retention", "key_id", "sig"}

// The Evidence Contract projection of a status (§8).
var statusProjection = map[string]string{
	"SATISFIED": "SATISFIED", "NOT_FOUND": "GAP", "NOT_COMMITTED": "GAP", "WITHHELD": "GAP",
	"CONTRADICTED": "GAP", "INSUFFICIENT": "INSUFFICIENT", "UNKNOWN": "UNKNOWN",
}

// profileRefusalReasons are the eight tokens §9.1 lists: the -00 and -01
// registry. The profile pins ER -01, so the two -02 additions
// (capacity_exceeded, request_unauthenticated) are not registered under it
// and no §8.1 row maps them, until it re-pins to -02 (AAC#479). Conforming
// and the Verifier's reason_registered read it.
var profileRefusalReasons = []string{
	ReasonNotAuthorized, ReasonNoSuchSubject, ReasonCoverageUnsatisfiable, ReasonDerivationUnsupported,
	ReasonPolicyDeclined, ReasonDeadlineUnmet, ReasonRequestMalformed, ReasonRetentionExpired,
}

// The §8.1 rows, by the label the conformance vectors give them, and the
// status each contributes.
var rowStatus = map[string]string{
	"envelope-1": "CONTRADICTED", "envelope-2": "INSUFFICIENT", "envelope-3": "INSUFFICIENT",
	"envelope-4": "UNKNOWN", "envelope-5": "SATISFIED", "envelope-6": "INSUFFICIENT",
	"refusal-no_such_subject": "NOT_FOUND", "refusal-retention_expired": "UNKNOWN",
	"refusal-coverage_unsatisfiable": "UNKNOWN", "refusal-withheld": "WITHHELD",
	"refusal-deadline_or_malformed": "UNKNOWN", "refusal-failed": "UNKNOWN", "received-and-failed": "UNKNOWN",
	"absence": "UNKNOWN",
}

// The rows a contract's uncertainty.on_missing applies to (§8).
var missingRows = []string{"envelope-3", "envelope-4", "refusal-no_such_subject", "refusal-retention_expired",
	"refusal-coverage_unsatisfiable", "refusal-deadline_or_malformed", "absence"}

const row7Note = "§8.1 row 7: the contract evaluates the Artifact's content; SATISFIED gives met, not_met or, " +
	"where the requirement allows it, out_of_scope, and any other sufficiency gives not_evaluable [RES §1]. " +
	"This profile fixes no content rule, so with no content evaluator the requirement is UNKNOWN (§11.3.7)."

// Exchange is one request the requester transmitted, every reply it
// received for it, and the absence record it wrote if its window closed
// with no reply.
type Exchange struct {
	Request Message
	Replies []Message
	Absence *Message
}

// ForeignObject says where a foreign signed object sits in a JSON Artifact
// (a dotted member path) and the media type that selects its native check
// (§5.1, §7.2 native_check).
type ForeignObject struct {
	Path      string
	MediaType string
}

// NativeChecker runs the native check of a foreign object as carried.
type NativeChecker func(object any, trust TrustPolicy, evaluationTime string) PropertyReport

// ContentEvaluator is §8.1 row 7: from a requirement, the Artifact octets
// and the native check (or nil), the requirement's status and verdict, or
// ok false to leave it unevaluated. The status is an Evidence Contract
// value.
type ContentEvaluator func(requirement map[string]any, artifact []byte, native *PropertyReport) (status, verdict string, ok bool)

// Claim is one evidence or proof entry of a claim (§8.3).
type Claim map[string]string

// RequirementResult is one requirement's §8 result: the row, status,
// sufficiency and verdict, and the claim's evidence and proofs. An empty
// status, sufficiency or verdict is the null the vectors write.
// AppliesFrom and OutOfScopeAllowed are the facts §8.3 copies from the
// requirement; "" and false are the absent member.
type RequirementResult struct {
	RequirementRef    string
	ContractRef       string
	Row               string
	Status            string
	Sufficiency       string
	Verdict           string
	Evidence          []Claim
	Proofs            []Claim
	Note              string
	AppliesFrom       string
	OutOfScopeAllowed bool
}

// PresentationKindsAllowed is §8.2 invariant 4: WITHHELD and NOT_COMMITTED
// never use the disclosure carrier. Nil when any kind is allowed.
func (r RequirementResult) PresentationKindsAllowed() []string {
	if r.Status == "WITHHELD" || r.Status == "NOT_COMMITTED" {
		return []string{"analysis", "story"}
	}
	return nil
}

// ReplyResult is one reply: its message type (envelope, refusal,
// received_and_failed or not_a_response, §1), its property reports (§7)
// and its §8 results by requirement.
type ReplyResult struct {
	MessageType  string
	Properties   []PropertyReport
	NativeCheck  *PropertyReport
	Requirements map[string]RequirementResult
	// RequirementOrder lists Requirements' keys in evaluation order.
	RequirementOrder []string
	Evidence         []Claim
	Proofs           []Claim
	Detail           string
	// Envelope is the decoded envelope map (with its artifact decoded to
	// bytes when it is opaque bytes), for an envelope; nil otherwise.
	Envelope map[string]any
	// Artifact is the envelope's artifact octets as carried, decoded from
	// their encoding; nil when absent or not opaque bytes.
	Artifact []byte
	// Reason is a refusal's reason as carried; nil otherwise.
	Reason any

	props map[string]PropertyReport
	row   string
}

// Status is the status reported for property, or "" when it is not
// reported.
func (r ReplyResult) Status(property string) string {
	for _, p := range r.Properties {
		if p.Property == property {
			return p.Status
		}
	}
	return ""
}

// AbsenceResult is an absence record: its form (conforming or
// not_conforming, §6.4, §7.3) and its §8 result.
type AbsenceResult struct {
	Form             string
	Detail           string
	Requirements     map[string]RequirementResult
	RequirementOrder []string
	Evidence         []Claim
}

// ExchangeResult is one exchange: its request digest, its replies and its
// absence record.
type ExchangeResult struct {
	RequestDigest string
	Replies       []*ReplyResult
	Absence       *AbsenceResult
}

// Pending is true when no reply and no conforming absence was held: the
// request is pending, and no claim is emitted (§8.1).
func (e ExchangeResult) Pending() bool {
	for _, r := range e.Replies {
		if r.MessageType != "not_a_response" {
			return false
		}
	}
	return e.Absence == nil || e.Absence.Form != "conforming"
}

// VerificationResult is every exchange verified, and caller_invariance
// across every envelope held.
type VerificationResult struct {
	Exchanges        []ExchangeResult
	CallerInvariance PropertyReport
}

// VerifyOptions narrows what Verify evaluates.
type VerifyOptions struct {
	// Requirements lists the requirement ids evaluated; nil is every
	// requirement of the contract, in its order.
	Requirements []string
	// Relations says, per requirement, whether it is the foreign object's
	// native check (is_check) or one the check only supports (supports)
	// (§8.1 rows 5 and 6). The contract has no member for it.
	Relations map[string]string
	// Foreign, when set, names the foreign object the Artifact carries.
	Foreign *ForeignObject
	// Content evaluates row 7, when set.
	Content ContentEvaluator
}

// Verifier checks evidence-interop/0 exchanges (profile §7.3) and maps them
// to Evidence Result claims (§8). It mirrors the profile's Python reference
// verifier (agent_action_capsule.interop_profile.InteropVerifier), and the
// vectors of vectors/interop-profile-v0 and
// vectors/personal-history-basic-v0 are its tests.
//
// It is offline by construction: it reads no clock and opens no
// connection. Trust in a responder's key is checked as of the message's own
// issued_at, a log key as of the checkpoint's issued_at, and anything "now"
// as of EvaluationTime, through the policy's resolver when it is online.
type Verifier struct {
	Trust          TrustPolicy
	Policy         VerificationPolicy
	EvaluationTime string
	// NativeCheckers by media type; nil is the built-in set
	// (DefaultNativeCheckers).
	NativeCheckers map[string]NativeChecker

	contractRef  string
	contract     bool
	requirements map[string]map[string]any
	order        []string
}

// NewVerifier makes a verifier. evaluationTime is required and is the only
// "now" it knows. contract, when not nil, is the contract version document
// evaluated; the claims carry its contract_ref. A contract with two
// requirements of one id, or a requirement whose clause.effective_from is
// not a calendar date, is not evaluated (§11.3.7).
func NewVerifier(trust TrustPolicy, policy VerificationPolicy, evaluationTime string, contract map[string]any) (*Verifier, error) {
	if _, ok := parseInstant(evaluationTime); !ok {
		return nil, fmt.Errorf("%w: evaluation time must be an RFC 3339 time; the verifier never reads the clock", ErrInvalid)
	}
	v := &Verifier{Trust: trust, Policy: policy, EvaluationTime: evaluationTime, requirements: map[string]map[string]any{}}
	if contract == nil {
		return v, nil
	}
	contract, _ = profileNumbers(contract).(map[string]any)
	reqs, _ := contract["requirements"].([]any)
	for _, raw := range reqs {
		req, _ := raw.(map[string]any)
		id, _ := req["id"].(string)
		if _, dup := v.requirements[id]; dup {
			return nil, fmt.Errorf("%w: two requirements share one id; the contract version is not evaluated (§11.3.7)", ErrInvalid)
		}
		if _, dated := effectiveFrom(req); dated && !isCalendarDate(appliesFrom(req)) {
			return nil, fmt.Errorf("%w: %s: clause.effective_from is not a calendar date; the contract version is not evaluated (§11.3.7)", ErrInvalid, id)
		}
		v.requirements[id] = req
		v.order = append(v.order, id)
	}
	if jcsOrNil(contract) == nil {
		return nil, fmt.Errorf("%w: the contract carries a value JCS cannot represent; no contract_digest (§11.3.7)", ErrInvalid)
	}
	v.contract = true
	v.contractRef = fmt.Sprintf("%v@%v", contract["id"], contract["version"])
	return v, nil
}

// ContractRef is id@version of the contract held, or "" with none.
func (v *Verifier) ContractRef() string { return v.contractRef }

func report(property, status, method, detail string) PropertyReport {
	return PropertyReport{Property: property, Status: status, Method: method, Detail: detail}
}

func (v *Verifier) responderKeyCurrent(key any) PropertyReport {
	const name, method = "responder_key_current", "online key-status check (§7.2)"
	if !v.Policy.Online {
		return report(name, StatusNotChecked, method, "the verifier is offline; an online check is not made (NFR-7)")
	}
	k, ok := key.(string)
	if v.Policy.KeyStatus == nil || !ok || !IsDigest(k) {
		return report(name, StatusNotChecked, method, "no key-status resolver was supplied")
	}
	status, m := v.Policy.KeyStatus(k, v.EvaluationTime)
	return report(name, status, m, "as of the evaluation time "+v.EvaluationTime)
}

func present(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

func (v *Verifier) envelopeProperties(env map[string]any, received receivedValue, mediaType string, requestOctets []byte, request map[string]any) (map[string]PropertyReport, [][]byte) {
	props := map[string]PropertyReport{}
	asked := any(ProfileID)
	if present(request, "profile") {
		asked = request["profile"]
	}
	method := "§3.3 step 5: the envelope's profile against the identifier requested"
	implemented := slices.Contains(v.Policy.ProfilesImplemented, ProfileID)
	var pv PropertyReport
	switch {
	case !present(env, "profile"):
		pv = report("profile_version", StatusNotPresent, method, "no profile member: ER alone (§3.3)")
	case !strictEqual(env["profile"], asked):
		pv = report("profile_version", StatusFail, method, fmt.Sprintf("requested %v, got %v", asked, env["profile"]))
	case !implemented || env["profile"] != ProfileID:
		pv = report("profile_version", StatusNotChecked, method, fmt.Sprintf("%v is not implemented; not checked under any other version", env["profile"]))
	default:
		pv = report("profile_version", StatusPass, method, "")
	}
	props["profile_version"] = pv
	if pv.Status != StatusPass {
		for _, name := range EnvelopeProperties[1:] {
			props[name] = report(name, StatusNotChecked, "not run (§3.3 step 5, §7.2)", "profile_version is not PASS")
		}
		return props, nil
	}

	responder, issuedAt := env["responder"], env["issued_at"]
	method = "Ed25519 over the JCS signing input (§6.2)"
	switch {
	case !present(env, "sig") || !present(env, "responder"):
		props["envelope_signature"] = report("envelope_signature", StatusNotPresent, method, "sig or responder is absent")
	case !received.wellFormed:
		props["envelope_signature"] = report("envelope_signature", StatusFail, method, "not well-formed (§5.2): "+received.why)
	default:
		signed := map[string]any{}
		for _, k := range envelopeSigned {
			if present(env, k) {
				signed[k] = env[k]
			}
		}
		body := jcsOrNil(signed)
		props["envelope_signature"] = report("envelope_signature", passIf(body != nil && verifyHexSignature(responder, env["sig"], body)), method, "")
	}
	method = "trust policy: responder keys, as of the envelope's issued_at"
	if !present(env, "responder") {
		props["responder_trust"] = report("responder_trust", StatusNotPresent, method, "")
	} else {
		props["responder_trust"] = report("responder_trust", v.Trust.AcceptsResponder(responder, issuedAt), method, "")
	}
	props["responder_key_current"] = v.responderKeyCurrent(responder)
	method = "§5.2 time form"
	if !present(env, "issued_at") {
		props["issued_at_form"] = report("issued_at_form", StatusNotPresent, method, "")
	} else {
		props["issued_at_form"] = report("issued_at_form", passIf(isProfileTime(issuedAt)), method, "")
	}
	method = "SHA-256 over the retained request octets (§5.1)"
	if !present(env, "request_digest") {
		props["request_binding"] = report("request_binding", StatusNotPresent, method, "")
	} else {
		props["request_binding"] = report("request_binding", passIf(env["request_digest"] == Digest(requestOctets)), method, "")
	}
	method = "subject and derivation equal the request's, by value (§7.2)"
	if !present(env, "subject") {
		props["subject_binding"] = report("subject_binding", StatusNotPresent, method, "")
	} else {
		ok := strictEqual(env["subject"], request["subject"]) && present(env, "derivation") == present(request, "derivation") &&
			strictEqual(env["derivation"], request["derivation"])
		props["subject_binding"] = report("subject_binding", passIf(ok), method, "")
	}
	method = "SHA-256 over the artifact octets (§6.2)"
	artifact, opaque := []byte(nil), false
	if present(env, "artifact") {
		artifact, opaque = opaqueReceived(env["artifact"], mediaType)
	}
	switch {
	case !present(env, "artifact") || !present(env, "artifact_digest"):
		props["artifact_digest"] = report("artifact_digest", StatusNotPresent, method, "")
	case !opaque:
		props["artifact_digest"] = report("artifact_digest", StatusFail, method, "artifact is not opaque bytes in this encoding (§4)")
	default:
		props["artifact_digest"] = report("artifact_digest", passIf(env["artifact_digest"] == Digest(artifact)), method, "")
	}
	method = "SHA-256 of each verification_content item against verification, in order (§6.2)"
	var material [][]byte
	ver, content := env["verification"], env["verification_content"]
	if ver == nil && content == nil {
		props["verification_binding"] = report("verification_binding", StatusNotPresent, method, "no verification material; not required")
	} else {
		entries, entriesOK := ver.([]any)
		for _, e := range entries {
			m, ok := e.(map[string]any)
			entriesOK = entriesOK && ok && isText(m["kind"]) && isDigestValue(m["digest"])
		}
		rawItems, itemsOK := content.([]any)
		items := make([][]byte, 0, len(rawItems))
		for _, x := range rawItems {
			b, ok := opaqueReceived(x, mediaType)
			itemsOK = itemsOK && ok
			items = append(items, b)
		}
		ok := entriesOK && itemsOK && len(items) == len(entries)
		for i := 0; ok && i < len(items); i++ {
			ok = Digest(items[i]) == entries[i].(map[string]any)["digest"]
		}
		if ok {
			material = items
		}
		props["verification_binding"] = report("verification_binding", passIf(ok), method, "")
	}
	props["anchor_match"] = anchorMatch(env, request)
	props["anchor_inclusion"] = checkAnchorInclusion(env, material, map[string]string{
		"envelope_signature":   props["envelope_signature"].Status,
		"artifact_digest":      props["artifact_digest"].Status,
		"verification_binding": props["verification_binding"].Status,
	}, v.Trust, v.Policy.KindsImplemented)
	return props, material
}

func passIf(ok bool) string {
	if ok {
		return StatusPass
	}
	return StatusFail
}

// strictEqual is equality by value with no bool/int conflation, as the
// reference's _strict_equal: the same type at every level, the same
// members, the same items in order. Integers outside the data model and
// floats compare by value (floats numerically: NaN equals nothing); any
// other value outside the model equals nothing.
func strictEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool, string, uint64, cborNegative, cborBigUint, cborFloat:
		return a == b
	case []byte:
		y, ok := b.([]byte)
		return ok && string(x) == string(y)
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !strictEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, present := y[k]
			if !present || !strictEqual(v, w) {
				return false
			}
		}
		return true
	case cborTag:
		y, ok := b.(cborTag)
		return ok && x.Number == y.Number && strictEqual(x.Value, y.Value)
	}
	return false
}

func anchorMatch(env, request map[string]any) PropertyReport {
	const name = "anchor_match"
	coverage, okCoverage := request["coverage"].(map[string]any)
	if !okCoverage || len(coverage) != 1 {
		return report(name, StatusNotChecked, "§7.2 anchor_match", "the retained request carries no single coverage member")
	}
	anchor, okAnchor := env["anchor"].(map[string]any)
	if !okAnchor {
		return report(name, StatusNotPresent, "§7.2 anchor_match", "no anchor")
	}
	if pin, ok := coverage["expected_pin"]; ok {
		method := "anchor.digest equals the expected_pin (ER §3.2)"
		if !present(anchor, "digest") {
			return report(name, StatusNotPresent, method, "")
		}
		return report(name, passIf(strictEqual(anchor["digest"], pin)), method, "")
	}
	floor := coverage["min_freshness"]
	method := "anchor.freshness meets the min_freshness floor (ER §3.2, §4.1 item 2)"
	got, ok := anchor["freshness"]
	if !ok {
		return report(name, StatusNotPresent, method, "anchor.freshness is absent")
	}
	var pass bool
	if f, isUint := uintMember(floor); isUint {
		g, gUint := uintMember(got)
		pass = gUint && g >= f
	} else if isProfileTime(floor) {
		ft, _ := parseInstant(floor)
		gt, gOK := parseInstant(got)
		pass = isProfileTime(got) && gOK && !gt.Before(ft)
	} else {
		return report(name, StatusNotChecked, method, "the retained request's floor is malformed")
	}
	detail := ""
	if !pass {
		detail = "in the type the request used"
	}
	return report(name, passIf(pass), method, detail)
}

// required is the required envelope properties (§7.2): all but
// responder_key_current, and verification_binding only when verification
// is present.
func required(env map[string]any, props map[string]PropertyReport) map[string]string {
	out := map[string]string{}
	for k, p := range props {
		if k != "responder_key_current" {
			out[k] = p.Status
		}
	}
	if !present(env, "verification") {
		delete(out, "verification_binding")
	}
	return out
}

func (v *Verifier) refusalProperties(ref map[string]any, received receivedValue, requestOctets []byte) map[string]PropertyReport {
	props := map[string]PropertyReport{}
	keyID, issuedAt := ref["key_id"], ref["issued_at"]
	method := "Ed25519 over JCS of {issued_at, reason, request_digest} (§6.3, ERV A7)"
	switch {
	case !present(ref, "sig") || !present(ref, "key_id"):
		props["refusal_signature"] = report("refusal_signature", StatusNotPresent, method, "sig or key_id is absent")
	case !received.wellFormed:
		props["refusal_signature"] = report("refusal_signature", StatusFail, method, "not well-formed (§5.2): "+received.why)
	case !present(ref, "issued_at") || !present(ref, "reason") || !present(ref, "request_digest"):
		props["refusal_signature"] = report("refusal_signature", StatusFail, method, "a signed member is absent")
	default:
		body := jcsOrNil(map[string]any{"issued_at": ref["issued_at"], "reason": ref["reason"], "request_digest": ref["request_digest"]})
		props["refusal_signature"] = report("refusal_signature", passIf(body != nil && verifyHexSignature(keyID, ref["sig"], body)), method, "")
	}
	method = "trust policy: responder keys, as of the refusal's issued_at"
	if !present(ref, "key_id") {
		props["responder_trust"] = report("responder_trust", StatusNotPresent, method, "")
	} else {
		props["responder_trust"] = report("responder_trust", v.Trust.AcceptsResponder(keyID, issuedAt), method, "")
	}
	props["responder_key_current"] = v.responderKeyCurrent(keyID)
	method = "SHA-256 over the retained request octets (§5.1)"
	if !present(ref, "request_digest") {
		props["request_binding"] = report("request_binding", StatusNotPresent, method, "")
	} else {
		props["request_binding"] = report("request_binding", passIf(ref["request_digest"] == Digest(requestOctets)), method, "")
	}
	reason, _ := ref["reason"].(string)
	props["reason_registered"] = report("reason_registered", passIf(isText(ref["reason"]) && slices.Contains(profileRefusalReasons, reason)),
		"exactly one token of the ER §13 registry, exact case (§9.1, ERV A13)", "")
	method = "§5.2 time form"
	if !present(ref, "issued_at") {
		props["issued_at_form"] = report("issued_at_form", StatusNotPresent, method, "")
	} else {
		props["issued_at_form"] = report("issued_at_form", passIf(isProfileTime(issuedAt)), method, "")
	}
	return props
}

func refusalRow(props map[string]PropertyReport, reason any) string {
	for k, p := range props {
		if k != "responder_key_current" && p.Status != StatusPass {
			return "refusal-failed"
		}
	}
	switch reason {
	case "not_authorized", "policy_declined", "derivation_unsupported":
		return "refusal-withheld"
	case "deadline_unmet", "request_malformed":
		return "refusal-deadline_or_malformed"
	}
	return fmt.Sprintf("refusal-%v", reason)
}

func ordered(props map[string]PropertyReport, names []string) []PropertyReport {
	out := make([]PropertyReport, len(names))
	for i, n := range names {
		out[i] = props[n]
	}
	return out
}

func digestClaim(digest string) []Claim {
	return []Claim{{"digest_alg": "SHA-256", "digest": digest}}
}

func (v *Verifier) reply(m Message, requestOctets []byte, request map[string]any) *ReplyResult {
	received, ok, why := decodeReceived(m)
	obj, isMap := received.value.(map[string]any)
	if !ok || !isMap {
		if why == "" {
			why = "not a map"
		}
		return &ReplyResult{MessageType: "not_a_response", Detail: why + ": a transport condition (§9.2)"}
	}
	hasEnv, hasRef := present(obj, "artifact_digest"), present(obj, "reason")
	switch {
	case hasEnv && hasRef:
		return &ReplyResult{MessageType: "received_and_failed", Detail: "carries both artifact_digest and reason (§1, P-21)",
			Evidence: digestClaim(Digest(m.Octets))}
	case hasEnv:
		props, _ := v.envelopeProperties(obj, received, m.MediaType, requestOctets, request)
		named := isDigestValue(obj["artifact_digest"])
		digest := Digest(m.Octets)
		detail := "artifact_digest is not a digest; evidence[] cites the reply octets"
		if named {
			digest, detail = obj["artifact_digest"].(string), ""
		}
		var proofs []Claim
		if props["anchor_inclusion"].Status == StatusPass {
			for _, e := range obj["verification"].([]any) {
				entry := e.(map[string]any)
				if entry["kind"] == KindCLLInclusionProof {
					proofs = []Claim{{"kind": "inclusion_proof", "digest_alg": "SHA-256", "digest": entry["digest"].(string)}}
					break
				}
			}
		}
		env := make(map[string]any, len(obj))
		for k, x := range obj {
			env[k] = x
		}
		artifact, opaque := opaqueReceived(obj["artifact"], m.MediaType)
		if !opaque {
			artifact = nil
		}
		env["artifact"] = artifact
		return &ReplyResult{MessageType: "envelope", Properties: ordered(props, EnvelopeProperties), Evidence: digestClaim(digest),
			Proofs: proofs, Detail: detail, Envelope: env, Artifact: artifact, props: props}
	case hasRef:
		props := v.refusalProperties(obj, received, requestOctets)
		return &ReplyResult{MessageType: "refusal", Properties: ordered(props, RefusalProperties), Evidence: digestClaim(Digest(m.Octets)),
			Reason: obj["reason"], props: props, row: refusalRow(props, obj["reason"])}
	}
	return &ReplyResult{MessageType: "not_a_response", Detail: "neither artifact_digest nor reason: a transport condition (§1, §9.2)"}
}

func (v *Verifier) absence(record Message, requestOctets []byte) *AbsenceResult {
	var problems []string
	var value map[string]any
	if received, ok, _ := decodeReceived(record); ok && received.wellFormed {
		value, _ = received.value.(map[string]any)
	}
	digest := ""
	if value != nil {
		if body := jcsOrNil(value); body != nil {
			digest = Digest(body)
		}
	} else {
		problems = append(problems, "not a well-formed map")
		value = map[string]any{}
	}
	if value["outcome"] != "recorded_absence" {
		problems = append(problems, "outcome is not recorded_absence")
	}
	if value["request_digest"] != Digest(requestOctets) {
		problems = append(problems, "request_digest is not the digest of the retained request")
	}
	window, _ := value["window"].(map[string]any)
	opened, closed := window["opened"], window["closed"]
	windowOK := window != nil && len(window) == 2 && present(window, "opened") && present(window, "closed") &&
		isProfileTime(opened) && isProfileTime(closed) && opened.(string) <= closed.(string)
	if !windowOK {
		problems = append(problems, "window is not {opened, closed} in the §5.2 form")
	}
	recorded := value["recorded_at"]
	if !isProfileTime(recorded) {
		problems = append(problems, "recorded_at is not in the §5.2 form")
	} else if windowOK && recorded.(string) < closed.(string) {
		problems = append(problems, "recorded_at is earlier than window.closed (§6.4)")
	}
	var extra []string
	for k := range value {
		if !slices.Contains(absenceMembers, k) {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		slices.Sort(extra)
		problems = append(problems, fmt.Sprintf("members outside §6.4, which may read as the responder's act: %s", pyList(extra)))
	}
	if present(value, "route") && !isText(value["route"]) {
		problems = append(problems, "route is not a text string")
	}
	if present(value, "retention") && !isDigestValue(value["retention"]) {
		problems = append(problems, "retention is not a digest")
	}
	if present(value, "key_id") != present(value, "sig") {
		problems = append(problems, "key_id and sig are not both present")
	} else if present(value, "sig") {
		unsigned := map[string]any{}
		for k, x := range value {
			if k != "sig" {
				unsigned[k] = x
			}
		}
		body := jcsOrNil(unsigned)
		if body == nil || !verifyHexSignature(value["key_id"], value["sig"], body) {
			problems = append(problems, "the requester's sig does not verify")
		}
	}
	if digest == "" {
		digest = Digest(record.Octets)
	}
	form := "conforming"
	if len(problems) > 0 {
		form = "not_conforming"
	}
	return &AbsenceResult{Form: form, Detail: strings.Join(problems, "; "), Evidence: digestClaim(digest)}
}

func pyList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = "'" + s + "'"
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func requirementShape(req map[string]any) string {
	profile, hasProfile := req["profile"]
	if !hasProfile {
		profile = "outcome"
	}
	if profile == "outcome" || profile == "obligation" {
		native := present(req, "evidence_rule") || !hasProfile
		kind := "abstract"
		if native {
			kind = "native"
		}
		return fmt.Sprintf("%s-%v", kind, profile)
	}
	s, _ := profile.(string)
	return s
}

func applyUncertainty(req map[string]any, row, status string) string {
	if req == nil {
		return status
	}
	if shape := requirementShape(req); shape != "abstract-outcome" && shape != "quality" {
		return status
	}
	u, ok := req["uncertainty"].(map[string]any)
	if !ok {
		return status
	}
	if slices.Contains(missingRows, row) {
		switch u["on_missing"] {
		case "insufficient":
			return "INSUFFICIENT"
		case "unknown":
			return "UNKNOWN"
		}
		return status
	}
	if row == "envelope-1" && u["on_conflict"] == "contradicted" {
		return "CONTRADICTED"
	}
	return status
}

// effectiveFrom is the requirement's clause.effective_from as carried, and
// whether it is present. Any shape may carry it (§11.3.4).
func effectiveFrom(req map[string]any) (any, bool) {
	clause, _ := req["clause"].(map[string]any)
	value, ok := clause["effective_from"]
	return value, ok
}

// appliesFrom is the date §8.3 copies into the claim, or "" when the
// requirement states none.
func appliesFrom(req map[string]any) string {
	value, _ := effectiveFrom(req)
	s, _ := value.(string)
	return s
}

// outOfScopeAllowed is the requirement's switch: only a native shape carries
// it, so the same member on an open stub or an abstract shape grants nothing.
func outOfScopeAllowed(req map[string]any) bool {
	if req == nil {
		return false
	}
	if shape := requirementShape(req); shape != "native-outcome" && shape != "native-obligation" {
		return false
	}
	allowed, _ := req["out_of_scope_allowed"].(bool)
	return allowed
}

// isCalendarDate reports whether s is YYYY-MM-DD naming a real date. The
// Evidence Contract schema checks only the pattern, so 2027-02-30 passes it.
func isCalendarDate(s string) bool {
	if !calendarDateText.MatchString(s) {
		return false
	}
	d, err := time.Parse(time.DateOnly, s)
	return err == nil && d.Year() >= 1
}

var calendarDateText = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// pairs is §8.2 invariant 1, the verdict relation of [RES §1]: SATISFIED
// pairs with met, not_met or, where the requirement allows it, out_of_scope;
// every other sufficiency pairs with not_evaluable only.
func pairs(sufficiency, verdict string, allowed bool) bool {
	if sufficiency != "SATISFIED" {
		return verdict == "not_evaluable"
	}
	return verdict == "met" || verdict == "not_met" || (verdict == "out_of_scope" && allowed)
}

var evidenceStatuses = []string{"SATISFIED", "NOT_FOUND", "NOT_COMMITTED", "WITHHELD", "CONTRADICTED", "INSUFFICIENT", "UNKNOWN", "NOT_APPLICABLE"}

// errInvariant reports a content evaluator that broke §8.2 invariant 1 or
// returned a status that is not an Evidence Contract value.
var errInvariant = errors.New("evidencerequest: §8 mapping")

func (v *Verifier) requirement(id, row string, evidence, proofs []Claim, status, verdict, note string) (*RequirementResult, error) {
	req := v.requirements[id]
	if row != "envelope-7" {
		status = applyUncertainty(req, row, rowStatus[row])
		verdict = "not_evaluable"
		if row == "envelope-5" {
			verdict = "not_met"
		}
	}
	if status == "NOT_APPLICABLE" {
		return nil, nil
	}
	sufficiency := statusProjection[status]
	allowed := outOfScopeAllowed(req)
	if !pairs(sufficiency, verdict, allowed) {
		return nil, fmt.Errorf("%w: %s: %q with sufficiency %s breaks §8.2 invariant 1", errInvariant, id, verdict, sufficiency)
	}
	return &RequirementResult{RequirementRef: id, ContractRef: v.contractRef, Row: row, Status: status, Sufficiency: sufficiency,
		Verdict: verdict, Evidence: slices.Clone(evidence), Proofs: slices.Clone(proofs), Note: note,
		AppliesFrom: appliesFrom(req), OutOfScopeAllowed: allowed}, nil
}

func envelopeRow(req map[string]string, contradicted bool, native, relation string) string {
	has := func(s string) bool {
		for _, x := range req {
			if x == s {
				return true
			}
		}
		return false
	}
	switch {
	case contradicted:
		return "envelope-1"
	case has(StatusFail):
		return "envelope-2"
	case has(StatusNotPresent):
		return "envelope-3"
	case has(StatusNotChecked) || has(StatusInconclusive):
		return "envelope-4"
	case native == StatusFail && relation == "is_check":
		return "envelope-5"
	case native == StatusFail && relation == "supports":
		return "envelope-6"
	}
	return "envelope-7"
}

// callerInvariance is §7.2's caller_invariance: among verified envelopes
// for one (responder, subject, derivation, anchor), identical artifact
// digests. It returns the report and the envelopes in a conflict.
func callerInvariance(results []*ReplyResult) (PropertyReport, map[*ReplyResult]bool) {
	const method = "identical artifact_digest across verified envelopes for one question (§7.2, ER §5)"
	type group struct{ members []*ReplyResult }
	groups := map[string]*group{}
	var keys []string
	for _, r := range results {
		if r.MessageType != "envelope" {
			continue
		}
		if r.props["envelope_signature"].Status != StatusPass || r.props["responder_trust"].Status != StatusPass ||
			r.props["artifact_digest"].Status != StatusPass {
			continue
		}
		env := r.Envelope
		var anchorDigest []byte
		if a, ok := env["anchor"].(map[string]any); ok {
			anchorDigest = jcsOrNil(a["digest"])
		}
		var derivation []byte
		if present(env, "derivation") {
			derivation = jcsOrNil(env["derivation"])
		}
		key := fmt.Sprintf("%q|%q|%q|%q", jcsOrNil(env["responder"]), jcsOrNil(env["subject"]), derivation, anchorDigest)
		if groups[key] == nil {
			groups[key] = &group{}
			keys = append(keys, key)
		}
		groups[key].members = append(groups[key].members, r)
	}
	conflicted := map[*ReplyResult]bool{}
	compared, n := 0, 0
	for _, k := range keys {
		g := groups[k]
		if len(g.members) < 2 {
			continue
		}
		compared++
		digests := map[string]bool{}
		for _, r := range g.members {
			digests[string(jcsOrNil(r.Envelope["artifact_digest"]))] = true
		}
		if len(digests) > 1 {
			for _, r := range g.members {
				conflicted[r] = true
			}
			n += len(g.members)
		}
	}
	if len(conflicted) > 0 {
		return report("caller_invariance", StatusFail, method, fmt.Sprintf("%d verified envelopes for one question name different artifacts", n)), conflicted
	}
	if compared > 0 {
		return report("caller_invariance", StatusPass, method, ""), conflicted
	}
	return report("caller_invariance", StatusNotChecked, method, "fewer than two verified envelopes for one question are held (P-17)"), conflicted
}

func (v *Verifier) nativeCheck(artifact []byte, spec ForeignObject) PropertyReport {
	checkers := v.NativeCheckers
	if checkers == nil {
		checkers = DefaultNativeCheckers()
	}
	checker := checkers[spec.MediaType]
	method := "native check for " + spec.MediaType
	var value any
	if artifact != nil {
		// The Artifact's own format governs it, not §5.2: a float elsewhere
		// in it does not hide the foreign object.
		value = decodeArtifactJSON(artifact)
	}
	for _, part := range strings.Split(spec.Path, ".") {
		m, ok := value.(map[string]any)
		if !ok {
			value = nil
			break
		}
		value = m[part]
	}
	if value == nil {
		return report("native_check", StatusNotPresent, method, fmt.Sprintf("no object at '%s' in the Artifact", spec.Path))
	}
	if checker == nil {
		return report("native_check", StatusNotChecked, method, "no native check is implemented for this media type")
	}
	return checker(value, v.Trust, v.EvaluationTime)
}

// Verify verifies every exchange held, compares their envelopes
// (caller_invariance) and maps each reply and absence to a result per
// requirement.
func (v *Verifier) Verify(exchanges []Exchange, opts VerifyOptions) (VerificationResult, error) {
	ids := opts.Requirements
	if ids == nil {
		ids = slices.Clone(v.order)
	}
	if v.contract {
		for _, id := range ids {
			if _, ok := v.requirements[id]; !ok {
				return VerificationResult{}, fmt.Errorf("%w: requirement %q is not in the contract", ErrInvalid, id)
			}
		}
	}
	out := make([]ExchangeResult, 0, len(exchanges))
	var all []*ReplyResult
	for _, ex := range exchanges {
		request, err := requestMap(ex.Request)
		if err != nil {
			return VerificationResult{}, err
		}
		result := ExchangeResult{RequestDigest: Digest(ex.Request.Octets)}
		for _, m := range ex.Replies {
			r := v.reply(m, ex.Request.Octets, request)
			result.Replies = append(result.Replies, r)
			all = append(all, r)
		}
		if ex.Absence != nil {
			result.Absence = v.absence(*ex.Absence, ex.Request.Octets)
		}
		out = append(out, result)
	}
	for _, r := range all {
		for _, p := range r.Properties {
			if !validStatus(p.Status) {
				return VerificationResult{}, fmt.Errorf("%w: %s reported %q, not a §7.1 status", errInvariant, p.Property, p.Status)
			}
		}
	}
	invariance, conflicted := callerInvariance(all)
	for _, result := range out {
		for _, r := range result.Replies {
			if err := v.mapReply(r, ids, opts, conflicted[r]); err != nil {
				return VerificationResult{}, err
			}
		}
		if a := result.Absence; a != nil && a.Form == "conforming" {
			// A record that is not a conforming absence for this request is
			// no absence: the request is still pending, and a pending
			// request yields no claim (§6.4, §8.2 invariant 3).
			a.Requirements = map[string]RequirementResult{}
			for _, q := range ids {
				res, err := v.requirement(q, "absence", a.Evidence, nil, "", "", "")
				if err != nil {
					return VerificationResult{}, err
				}
				if res != nil {
					a.Requirements[q] = *res
					a.RequirementOrder = append(a.RequirementOrder, q)
				}
			}
		}
	}
	return VerificationResult{Exchanges: out, CallerInvariance: invariance}, nil
}

// requestMap reads the retained request octets as a request map.
func requestMap(request Message) (map[string]any, error) {
	received, ok, _ := decodeReceived(request)
	value, isMap := received.value.(map[string]any)
	// The requester's own octets: a duplicate member or an out-of-range
	// number makes them no request map, as the reference reads them.
	if !ok || !isMap || (request.MediaType == MediaTypeJSON && !received.wellFormed) {
		return nil, fmt.Errorf("%w: the retained request octets are not a request map", ErrInvalid)
	}
	return value, nil
}

func (v *Verifier) mapReply(r *ReplyResult, ids []string, opts VerifyOptions, contradicted bool) error {
	add := func(q string, res *RequirementResult, err error) error {
		if err != nil {
			return err
		}
		if res != nil {
			r.Requirements[q] = *res
			r.RequirementOrder = append(r.RequirementOrder, q)
		}
		return nil
	}
	switch r.MessageType {
	case "not_a_response":
		return nil
	case "received_and_failed", "refusal":
		row := r.row
		if r.MessageType == "received_and_failed" {
			row = "received-and-failed"
		}
		r.Requirements = map[string]RequirementResult{}
		for _, q := range ids {
			res, err := v.requirement(q, row, r.Evidence, nil, "", "", "")
			if err := add(q, res, err); err != nil {
				return err
			}
		}
		return nil
	}
	req := required(r.Envelope, r.props)
	allPass := true
	for _, s := range req {
		allPass = allPass && s == StatusPass
	}
	if opts.Foreign != nil && allPass && !contradicted {
		nc := v.nativeCheck(r.Artifact, *opts.Foreign)
		if !validStatus(nc.Status) {
			return fmt.Errorf("%w: native_check reported %q, not a §7.1 status", errInvariant, nc.Status)
		}
		r.NativeCheck = &nc
	}
	native := ""
	if r.NativeCheck != nil {
		native = r.NativeCheck.Status
	}
	r.Requirements = map[string]RequirementResult{}
	for _, q := range ids {
		relation := opts.Relations[q]
		row := envelopeRow(req, contradicted, native, relation)
		var res *RequirementResult
		var err error
		switch {
		case row != "envelope-7":
			res, err = v.requirement(q, row, r.Evidence, r.Proofs, "", "", "")
		case relation == "is_check" && native != StatusPass:
			shown := native
			if shown == "" {
				shown = "not run"
			}
			res, err = v.requirement(q, row, r.Evidence, r.Proofs, "UNKNOWN", "not_evaluable",
				"the native check is "+shown+", so the requirement that is that check is UNKNOWN (§5.1, §11.3.7)")
		default:
			status, verdict, ok := "", "", false
			if opts.Content != nil {
				if reqDoc, held := v.requirements[q]; held {
					artifact := r.Artifact
					if artifact == nil {
						artifact = []byte{}
					}
					status, verdict, ok = opts.Content(reqDoc, artifact, r.NativeCheck)
				}
			}
			if !ok {
				res, err = v.requirement(q, row, r.Evidence, r.Proofs, "UNKNOWN", "not_evaluable", row7Note)
			} else if !slices.Contains(evidenceStatuses, status) {
				err = fmt.Errorf("%w: %s: %q is not an Evidence Contract status", errInvariant, q, status)
			} else {
				res, err = v.requirement(q, row, r.Evidence, r.Proofs, status, verdict, "")
			}
		}
		if err := add(q, res, err); err != nil {
			return err
		}
	}
	return nil
}

func validStatus(s string) bool {
	switch s {
	case StatusPass, StatusFail, StatusNotPresent, StatusNotChecked, StatusInconclusive:
		return true
	}
	return false
}

// profileNumbers converts the numbers of a value decoded by encoding/json
// (json.Number, or a float64 without UseNumber) to the profile's types, so
// a contract read that way has a JCS form and a contract_digest.
func profileNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		return JSONNumber(x)
	case float64:
		if x >= 0 && x <= MaxSafeInteger && x == float64(uint64(x)) {
			return uint64(x)
		}
		return OutsideModel{}
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = profileNumbers(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[k] = profileNumbers(item)
		}
		return out
	}
	return v
}
