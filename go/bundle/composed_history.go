// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/action-state-group/agent-action-capsule/go/witness"
)

// FormHistory is the one member form bundle -03 defines: a History answer
// ("History Members"), an artifact member whose body is the responder's
// signed response as received.
const FormHistory = "history"

// HistorySignatureVerifier checks a History answer's signature under the
// deployment's signature profile and returns one of the refusal signature
// states. Without one, a History is signature-unverified and a same_key join
// on it is not derivable. EvidenceInteropSignature is the evidence-interop
// one.
type HistorySignatureVerifier func(answer map[string]interface{}) string

// evidenceInteropSigned are the members an evidence-interop envelope signs,
// when present (spec/interop-profile-v0.md §6.2; unchanged in /1 and /2).
var evidenceInteropSigned = []string{"profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest",
	"verification", "responder", "issued_at"}

var evidenceInteropProfiles = map[string]bool{"evidence-interop/0": true, "evidence-interop/1": true, "evidence-interop/2": true}

var sigHexRE = regexp.MustCompile(`^[0-9a-f]{128}$`)

// EvidenceInteropSignature is a HistorySignatureVerifier for the
// evidence-interop profiles: Ed25519 by responder over the JCS of the signed
// members present. Another profile is signature-unverified.
func EvidenceInteropSignature(answer map[string]interface{}) string {
	if profile, _ := answer["profile"].(string); !evidenceInteropProfiles[profile] {
		return RefusalSignatureUnverified
	}
	signed := map[string]interface{}{}
	for _, name := range evidenceInteropSigned {
		if value, present := answer[name]; present {
			signed[name] = value
		}
	}
	body, err := canonical.JCS(signed)
	sig, sigOK := answer["sig"].(string)
	responder, _ := answer["responder"].(string)
	key, keyErr := hex.DecodeString(responder)
	if err != nil || !sigOK || !sigHexRE.MatchString(sig) || keyErr != nil || len(key) != ed25519.PublicKeySize {
		return RefusalSignatureInvalid
	}
	raw, _ := hex.DecodeString(sig)
	if ed25519.Verify(ed25519.PublicKey(key), body, raw) {
		return RefusalSignatureVerified
	}
	return RefusalSignatureInvalid
}

// historyState is what a History member's verification leaves for its
// same_key joins: the signature state and the anchor time.
type historyState struct {
	signature string
	anchorAt  time.Time
	okAnchor  bool
}

// verifyHistory checks a carried History answer (-03 "History Members"): its
// request binding, its signature under the deployment's profile and its
// anchor checkpoint, whose signed timestamp is the anchor time. It returns
// the recomputed digest. The History's own properties are its profile's.
func verifyHistory(m composedMember, out *ComposedMemberResult, failed, withheld *[]string, opts Options) (string, historyState, error) {
	var state historyState
	computed, err := canonical.JSONDigest(m.body)
	if m.body["request_digest"] != m.requestDigest {
		out.Findings = append(out.Findings, "request_digest_mismatch")
		*failed = append(*failed, "member_request_digest_mismatch:"+m.id)
	}
	out.HistorySignature = RefusalSignatureUnverified
	if opts.HistorySignature != nil {
		switch s := opts.HistorySignature(m.body); s {
		case RefusalSignatureVerified, RefusalSignatureInvalid:
			out.HistorySignature = s
		}
	}
	state.signature = out.HistorySignature
	switch out.HistorySignature {
	case RefusalSignatureInvalid:
		out.Findings = append(out.Findings, "history_signature_invalid")
		*failed = append(*failed, "history_signature_invalid:"+m.id)
	case RefusalSignatureUnverified:
		*withheld = append(*withheld, "history_signature_unverified:"+m.id)
	}
	anchor, _ := m.body["anchor"].(map[string]interface{})
	anchorDigest, _ := anchor["digest"].(string)
	var timestamp string
	out.AnchorCheckpoint, timestamp = anchorCheckpoint(m.anchorCheckpoint, anchorDigest)
	switch out.AnchorCheckpoint {
	case "mismatch", "invalid":
		out.Findings = append(out.Findings, "history_anchor_checkpoint_"+out.AnchorCheckpoint)
		*failed = append(*failed, "history_anchor_checkpoint_"+out.AnchorCheckpoint+":"+m.id)
	case "verified":
		state.anchorAt, state.okAnchor = recordTime(timestamp)
		out.AnchorTime = timestamp
	}
	return computed, state, err
}

// anchorCheckpoint returns a History's anchor_checkpoint state and, when it
// verified, its signed timestamp: its SHA-256 must be the signed anchor digest
// and it must verify under its own key.
func anchorCheckpoint(encoded *string, anchorDigest string) (string, string) {
	if encoded == nil {
		return "absent", ""
	}
	cose, err := strictB64URL.DecodeString(*encoded)
	if err != nil {
		return "invalid", ""
	}
	sum := sha256.Sum256(cose)
	if hex.EncodeToString(sum[:]) != anchorDigest {
		return "mismatch", ""
	}
	signed, err := witness.ParseSignedCheckpoint(cose)
	if err != nil {
		return "invalid", ""
	}
	// A signed time that is not an RFC 3339 UTC instant is not a checkpoint
	// the draft reads.
	if _, ok := recordTime(signed.Timestamp); !ok {
		return "invalid", ""
	}
	return "verified", signed.Timestamp
}

// RelatedHistories is one pair of History members that derived joins relate
// (bundle -03, "History Members"): each agrees with its party's half on
// same_key, and the halves agree on pre_agreed_identifier at Pointer. The
// relation is only as strong as the identifier Pointer selects.
type RelatedHistories struct {
	Histories [2]string
	Halves    [2]string
	Pointer   string
}

// sameKeyState derives a same_key join (-03 "History Members"), in the order
// the text states its steps: the first that applies decides. An empty state is
// not derivable. sound holds the members whose carried body reproduced its
// digest and, for a History, names the member's request.
func sameKeyState(j composedJoin, byID map[string]composedMember, missing, sound map[string]bool, histories map[string]historyState) (string, string) {
	history, other := byID[j.members[0]], byID[j.members[1]]
	if other.form == FormHistory {
		history, other = other, history
	}
	// 1. A member listed in missing.
	if missing[history.id] || missing[other.id] {
		return "", ""
	}
	// 2. The other member is not an artifact with records.
	if other.outcome != "artifact" || (other.body != nil && EmptyHistory(other.body)) {
		return "unjoined", ""
	}
	// 3. A body that did not verify as carried, or a History answer whose
	//    signature is not verified.
	state := histories[history.id]
	if !sound[history.id] || !sound[other.id] || state.signature != RefusalSignatureVerified {
		return "", ""
	}
	// 4. The half's root record is not signed: its producer signature must
	//    verify, under its key_id, over its recomputed Capsule ID.
	record := rootRecord(other)
	if record == nil {
		return "", "half_signature_unverified"
	}
	if verdict, _ := envelope.VerifyRecordSignature(record); verdict != envelope.Authored {
		return "", "half_signature_unverified"
	}
	// The signed record is the one the Bundle names: its recomputed Capsule
	// ID is the capsule_id it carries.
	if id, err := canonical.ComputeCapsuleID(record); err != nil || id != record["capsule_id"] {
		return "", "half_signature_unverified"
	}
	// 5. The key that signed the half is not the History's responder.
	if record["key_id"] != history.body["responder"] {
		return "unjoined", "history_key_differs"
	}
	// 6. No anchor time, or no time on the half.
	at, okAt := recordTime(record["timestamp"])
	if !state.okAnchor || !okAt {
		return "", "history_anchor_time_unknown"
	}
	// 7. A History as of an anchor before the deal is not about the deal.
	if state.anchorAt.Before(at) {
		return "unjoined", "history_anchor_predates_deal"
	}
	return "agree", ""
}

// relatedHistories lists the History pairs, ascending, that derived joins
// relate: each History agrees with its party's half on same_key and the two
// halves agree on pre_agreed_identifier, with that join's pointer. Being
// carried in one block relates nothing.
func relatedHistories(joins []ComposedJoinResult, declared []composedJoin, byID map[string]composedMember) []RelatedHistories {
	halves := map[string][]string{}
	links := map[[2]string][]string{}
	for i, j := range joins {
		if j.Derived != "agree" {
			continue
		}
		switch j.Basis {
		case "same_key":
			history, half := j.Members[0], j.Members[1]
			if byID[half].form == FormHistory {
				history, half = half, history
			}
			halves[history] = append(halves[history], half)
		case "pre_agreed_identifier":
			links[j.Members] = append(links[j.Members], *declared[i].pointer)
		}
	}
	ids := make([]string, 0, len(halves))
	for id := range halves {
		ids = append(ids, id)
		sort.Strings(halves[id])
	}
	sort.Strings(ids)
	related := []RelatedHistories{}
	for i, first := range ids {
		for _, second := range ids[i+1:] {
			for _, x := range halves[first] {
				for _, y := range halves[second] {
					pair := [2]string{x, y}
					if y < x {
						pair = [2]string{y, x}
					}
					pointers := append([]string(nil), links[pair]...)
					sort.Strings(pointers)
					for _, pointer := range pointers {
						related = append(related, RelatedHistories{Histories: [2]string{first, second}, Halves: pair, Pointer: pointer})
					}
				}
			}
		}
	}
	return related
}

// parseHistoryMember reads a History member: form history under the artifact
// outcome, its body history, no bundle or response, and anchor_checkpoint
// only here.
func parseHistoryMember(m composedMember, value map[string]interface{}) (composedMember, string) {
	if form, _ := value["form"].(string); form != FormHistory || m.outcome != "artifact" {
		return m, "form"
	}
	m.form = FormHistory
	for _, key := range []string{"bundle", "response", "refusal", "absence"} {
		if _, present := value[key]; present {
			return m, "body_outcome_conflict"
		}
	}
	if raw, present := value["anchor_checkpoint"]; present {
		encoded, ok := raw.(string)
		if !ok || !b64url.MatchString(encoded) {
			return m, "anchor_checkpoint"
		}
		m.anchorCheckpoint = &encoded
	}
	raw, present := value["history"]
	if !present {
		return m, ""
	}
	body, ok := raw.(map[string]interface{})
	anchor, anchorOK := body["anchor"].(map[string]interface{})
	if !ok || !isDigest(body["request_digest"]) || !isDigest(body["artifact_digest"]) || !anchorOK ||
		!isDigest(anchor["digest"]) || !isDigest(body["responder"]) || !isString(body["derivation"]) ||
		!isString(body["issued_at"]) || !isString(body["sig"]) {
		return m, "history_body"
	}
	m.body = body
	return m, ""
}

// joinNamesHistory applies -03 "Block": a join naming a History member is
// same_key, and a same_key join names exactly one and carries none of
// pointer, identifier_digest and compare.
func joinNamesHistory(j composedJoin, forms map[string]string) string {
	histories := 0
	for _, id := range j.members {
		if forms[id] == FormHistory {
			histories++
		}
	}
	switch {
	case j.basis != "same_key" && histories != 0:
		return "join_names_history_member"
	case j.basis != "same_key":
		return ""
	case histories != 1:
		return "same_key_members"
	case j.pointer != nil || j.identifier != nil || j.compareCarried:
		return "same_key_shape"
	}
	return ""
}
