// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/action-state-group/agent-action-capsule/go/witness"
)

// History members and the same_key join basis
// (draft-mih-zhang-agent-disclosure-bundle-03, "History Members" and "Joins").
// A History member is an artifact member whose body is a History answer: its
// artifact response envelope and the anchor checkpoint the envelope names. It
// has no root record; a History member that passes its five checks has a join
// view, its responder key and its anchor checkpoint's time.

// History check states reported on a History member.
const (
	HistoryVerified = "verified"
	HistoryInvalid  = "invalid"
	HistoryMatches  = "matches"
	HistoryMismatch = "mismatch"
)

// historyProfiles are the envelope profiles whose member names and signature
// -03 reads.
var historyProfiles = map[string]bool{"evidence-interop/0": true, "evidence-interop/1": true, "evidence-interop/2": true}

// historyBases are the join bases -03 defines a derivation for with a History
// member; any other is not derivable with one.
var historyBases = map[string]bool{"controller_binding": true, "same_key": true}

// HistoryMemberResult reports a carried History member's checks: the
// envelope signature (verified, invalid or signature_unverified), the
// artifact, request and artifact-anchor digests (matches or mismatch), and the
// anchor checkpoint (verified, mismatch when its digest is not anchor.digest,
// or invalid). Key and Time are its join view, set only when every check
// passed.
type HistoryMemberResult struct {
	Derivation        interface{}
	EnvelopeSignature string
	ArtifactDigest    string
	RequestDigest     string
	ArtifactAnchor    string
	AnchorCheckpoint  string
	Key               string
	Time              string
}

// HistoryTimes reports a History's time against a root record's, as facts:
// Relation is "before", "equal" or "after", the History's time relative to
// the record's, compared as instants.
type HistoryTimes struct {
	History     string
	HistoryTime string
	Record      string
	RecordTime  string
	Relation    string
}

// JoinKey is one member's key on a same_key join that derives unjoined.
type JoinKey struct {
	Member string
	Key    string
}

// historyView is a History member's join view.
type historyView struct {
	key  string
	at   time.Time
	time string
}

// historyShape is the history body's form; a body outside it makes the block
// malformed.
func historyShape(body map[string]interface{}) bool {
	env, ok := body["envelope"].(map[string]interface{})
	if !ok {
		return false
	}
	subject, ok := env["subject"].(map[string]interface{})
	if !ok || len(subject) != 1 {
		return false
	}
	if value, present := subject["full_history"]; !present || value != nil {
		return false
	}
	_, derivation := env["derivation"]
	anchor, anchorOK := env["anchor"].(map[string]interface{})
	_, artifactOK := decodeUnpaddedB64URL(env["artifact"])
	_, checkpointOK := decodeUnpaddedB64URL(body["anchor_checkpoint"])
	return derivation && isDigest(env["responder"]) && isString(env["sig"]) && artifactOK &&
		isDigest(env["artifact_digest"]) && isDigest(env["request_digest"]) &&
		anchorOK && isDigest(anchor["digest"]) && checkpointOK
}

// decodeUnpaddedB64URL decodes unpadded base64url.
func decodeUnpaddedB64URL(value interface{}) ([]byte, bool) {
	text, ok := value.(string)
	if !ok || !b64url.MatchString(text) {
		return nil, false
	}
	decoded, err := strictB64URL.DecodeString(text)
	return decoded, err == nil
}

// verifyHistory checks a carried History member (checks 1 to 5) and fills
// out.History. It returns the recomputed member digest (the envelope's) and
// the failed and withheld findings.
func verifyHistory(m composedMember, out *ComposedMemberResult) (string, []string, []string) {
	env := m.body["envelope"].(map[string]interface{})
	h := &HistoryMemberResult{Derivation: env["derivation"]}
	out.History = h
	var failed, withheld []string
	computed, err := canonical.JSONDigest(env)
	if err != nil {
		computed = ""
	}

	h.EnvelopeSignature = RefusalSignatureUnverified
	if profile, _ := env["profile"].(string); historyProfiles[profile] {
		h.EnvelopeSignature = HistoryInvalid
		if evidencerequest.EnvelopeSignatureHolds(env) {
			h.EnvelopeSignature = HistoryVerified
		}
	}
	artifact, _ := decodeUnpaddedB64URL(env["artifact"])
	matches := func(ok bool) string {
		if ok {
			return HistoryMatches
		}
		return HistoryMismatch
	}
	anchorDigest := env["anchor"].(map[string]interface{})["digest"].(string)
	h.ArtifactDigest = matches(sha256Hex(artifact) == env["artifact_digest"])
	h.RequestDigest = matches(env["request_digest"] == m.requestDigest)
	stated, anchorOK := artifactAnchor(artifact)
	h.ArtifactAnchor = matches(anchorOK && stated == anchorDigest)
	checkpoint, _ := decodeUnpaddedB64URL(m.body["anchor_checkpoint"])
	var timestamp string
	var timestampOK bool
	if sha256Hex(checkpoint) != anchorDigest {
		h.AnchorCheckpoint = HistoryMismatch
	} else if timestamp, timestampOK = checkpointTime(checkpoint); timestampOK {
		h.AnchorCheckpoint = HistoryVerified
	} else {
		h.AnchorCheckpoint = HistoryInvalid
	}

	for _, check := range []struct{ state, finding string }{
		{h.EnvelopeSignature, "history_envelope_signature_invalid"},
		{h.ArtifactDigest, "history_artifact_digest_mismatch"},
		{h.RequestDigest, "history_request_digest_mismatch"},
		{h.ArtifactAnchor, "history_artifact_anchor_mismatch"},
		{h.AnchorCheckpoint, "history_anchor_checkpoint_" + h.AnchorCheckpoint},
	} {
		if check.state == HistoryInvalid || check.state == HistoryMismatch {
			out.Findings = append(out.Findings, check.finding)
			failed = append(failed, check.finding+":"+m.id)
		}
	}
	if h.EnvelopeSignature == RefusalSignatureUnverified {
		withheld = append(withheld, "history_signature_unverified:"+m.id)
	}
	if len(failed) == 0 && len(withheld) == 0 && timestampOK {
		h.Key, h.Time = env["responder"].(string), timestamp
	}
	return computed, failed, withheld
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// artifactAnchor returns the anchor member of an artifact that is the UTF-8
// JCS of a JSON object; ok is false when it is not one (duplicate members, a
// value JCS cannot write, or octets that are not exactly that serialization).
func artifactAnchor(artifact []byte) (string, bool) {
	if duplicateMembers(artifact) {
		return "", false
	}
	decoder := json.NewDecoder(bytes.NewReader(artifact))
	decoder.UseNumber()
	var value map[string]interface{}
	if err := decoder.Decode(&value); err != nil || value == nil {
		return "", false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return "", false
	}
	serialized, err := canonical.JCS(value)
	if err != nil || !bytes.Equal(serialized, artifact) {
		return "", false
	}
	anchor, ok := value["anchor"].(string)
	return anchor, ok
}

// duplicateMembers reports whether any JSON object in data repeats a member
// name (or data is not JSON).
func duplicateMembers(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func() bool
	walk = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return true
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return false
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return true
				}
				seen[name] = true
				if walk() {
					return true
				}
			}
		case '[':
			for decoder.More() {
				if walk() {
					return true
				}
			}
		}
		_, err = decoder.Token()
		return err != nil
	}
	return walk()
}

// checkpointTime returns the timestamp of a CLL COSE checkpoint that verifies
// under its own key.
func checkpointTime(cose []byte) (string, bool) {
	signed, err := witness.ParseSignedCheckpoint(cose)
	if err != nil {
		return "", false
	}
	if _, ok := recordTime(signed.Timestamp); !ok {
		return "", false
	}
	return signed.Timestamp, true
}

// Key sources reported on every controller_binding and same_key join
// (bundle -03 "Joins", Member keys).
const (
	KeySourceRecordSignature = "record_signature"
	KeySourceLogCheckpoint   = "log_checkpoint"
	KeySourceHistory         = "history"
	KeySourceNone            = "none"
)

// KeySource is where one member's key came from on a controller_binding or
// same_key join.
type KeySource struct {
	Member string
	Source string
}

// keySides returns each member's side of a controller_binding or same_key
// join, or false when one has none: not derivable. Under controller_binding
// a pointer, when present, must select that same key in a root record.
func keySides(j composedJoin, members []composedMember, views map[string]historyView) ([]bindingSide, bool) {
	sides := make([]bindingSide, 0, len(members))
	for _, m := range members {
		side, _, ok := memberKey(m, views)
		if !ok {
			return nil, false
		}
		if j.basis == "controller_binding" && j.pointer != nil && !m.history {
			if record := rootRecord(m); record != nil {
				value, resolved := resolvePointer(record, *j.pointer)
				if key, isString := value.(string); !resolved || !isString || key != side.key {
					return nil, false
				}
			}
		}
		sides = append(sides, side)
	}
	return sides, true
}

// memberKey returns a member's key, its time and where the key came from: a
// History member's join view; an empty-history Bundle's checkpoint signer at
// that checkpoint's time; for a member Bundle with records, the key its root
// record's producer signature verifies under at the record's time or, for a
// root record that carries neither signature nor key_id, the key that signed
// the Bundle's checkpoint at that checkpoint's time, when the record's
// identity and its own membership under that checkpoint hold. A present
// signature that fails never falls back to the checkpoint key.
func memberKey(m composedMember, views map[string]historyView) (bindingSide, string, bool) {
	switch {
	case m.body == nil:
		return bindingSide{}, KeySourceNone, false
	case m.history:
		view, ok := views[m.id]
		if !ok {
			return bindingSide{}, KeySourceNone, false
		}
		return bindingSide{key: view.key, okKey: true, at: view.at, okAt: true}, KeySourceHistory, true
	case EmptyHistory(m.body):
		side, keyed := checkpointSide(m.body)
		if !keyed {
			return bindingSide{}, KeySourceNone, false
		}
		return side, KeySourceLogCheckpoint, true
	}
	record := rootRecord(m)
	if record == nil {
		return bindingSide{}, KeySourceNone, false
	}
	_, hasSignature := record["signature"]
	_, hasKeyID := record["key_id"]
	if hasSignature || hasKeyID {
		side, ok := signerSide(record)
		if !ok {
			return bindingSide{}, KeySourceNone, false
		}
		return side, KeySourceRecordSignature, true
	}
	id, _ := record["capsule_id"].(string)
	signed := RecordLoggedUnderCheckpoint(m.body, id)
	if signed == nil {
		return bindingSide{}, KeySourceNone, false
	}
	at, okAt := recordTime(signed.Timestamp)
	return bindingSide{key: signed.KeyID, okKey: true, at: at, okAt: okAt}, KeySourceLogCheckpoint, true
}

// keySources reports where each member's key came from, in the join's member
// order, on every controller_binding and same_key join, whatever it derived.
func keySources(j composedJoin, byID map[string]composedMember, views map[string]historyView) []KeySource {
	if !historyBases[j.basis] {
		return nil
	}
	out := make([]KeySource, 0, 2)
	for _, id := range j.members {
		m := byID[id]
		source := KeySourceNone
		if m.outcome == "artifact" {
			if _, found, ok := memberKey(m, views); ok {
				source = found
			}
		}
		out = append(out, KeySource{Member: id, Source: source})
	}
	return out
}

// joinKeys returns each member's key, in the join's member order, for a
// same_key join that derives unjoined.
func joinKeys(j composedJoin, members []composedMember, sides []bindingSide) []JoinKey {
	if j.basis != "same_key" {
		return nil
	}
	byID := map[string]string{}
	for i, m := range members {
		byID[m.id] = sides[i].key
	}
	return []JoinKey{{Member: j.members[0], Key: byID[j.members[0]]}, {Member: j.members[1], Key: byID[j.members[1]]}}
}

// keyedLink is the linkage of a controller_binding or same_key join.
func keyedLink(j composedJoin, a, b bindingSide, opts Options) (linked, derivable bool) {
	if j.basis == "same_key" {
		return a.okKey && b.okKey && a.key == b.key, true
	}
	return controllerBindingLink(j, a, b, opts)
}

// signerSide is a root record's same_key side: its key_id when its producer
// signature verifies under that key, never a key it merely names.
func signerSide(record map[string]interface{}) (bindingSide, bool) {
	verdict, _ := envelope.VerifyRecordSignature(record)
	key, ok := record["key_id"].(string)
	if verdict != envelope.Authored || !ok {
		return bindingSide{}, false
	}
	at, okAt := recordTime(record["timestamp"])
	return bindingSide{key: key, okKey: true, at: at, okAt: okAt}, true
}

// historyTimes reports, for a join between a History member with a join view
// and a member with a root record, both times and how they compare.
func historyTimes(j composedJoin, byID map[string]composedMember, views map[string]historyView) *HistoryTimes {
	a, b := byID[j.members[0]], byID[j.members[1]]
	for _, pair := range [][2]composedMember{{a, b}, {b, a}} {
		view, ok := views[pair[0].id]
		if !ok {
			continue
		}
		record := rootRecord(pair[1])
		if record == nil {
			return nil
		}
		stated, _ := record["timestamp"].(string)
		at, ok := recordTime(record["timestamp"])
		if !ok {
			return nil
		}
		relation := "equal"
		switch {
		case view.at.Before(at):
			relation = "before"
		case view.at.After(at):
			relation = "after"
		}
		return &HistoryTimes{History: pair[0].id, HistoryTime: view.time, Record: pair[1].id, RecordTime: stated, Relation: relation}
	}
	return nil
}
