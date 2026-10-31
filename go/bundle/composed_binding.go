// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

// The controller_binding join basis (draft-mih-zhang-agent-disclosure-bundle-02,
// "Controller Binding Records" and "Joins"). Binding records and revocation
// statements are delivered beside the containing Bundle (Options); the block
// binds a record only through a join's identifier_digest. This file derives
// the join's linkage and nothing else: it reports no binding property.

const (
	bindingVersion    = "controller-binding/0"
	revocationVersion = "controller-binding-revocation/0"
	revocationMethod  = "revocation_statement/0"
	methodDual        = "dual_signature/0"
	methodCredential  = "dual_signature_credential/0"
)

// bindingClaims maps each claim type to the method the draft defines for it
// and the members it adds.
var bindingClaims = map[string]struct {
	method string
	added  []string
}{
	"same_controller_asserted":       {methodDual, nil},
	"delegated_by":                   {methodDual, []string{"delegator"}},
	"same_organization_credentialed": {methodCredential, []string{"credential"}},
}

var (
	bindingMembers  = []string{"binding_version", "claim", "method", "keys", "issued_at", "not_before", "not_after", "revocation", "nonce", "sigs"}
	signatureHexRE  = regexp.MustCompile(`^[0-9a-f]{128}$`)
	bindingTimeRE   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	recordTimeRE    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$`)
	revocationShape = []string{"revocation_version", "binding", "key_id", "revoked_at", "sig"}
)

// bindingTime reads a binding or revocation time: RFC 3339, UTC, "Z",
// seconds precision.
func bindingTime(value interface{}) (time.Time, bool) {
	return utcTime(value, bindingTimeRE)
}

// recordTime reads a root record's timestamp, which may carry fractional
// seconds. Times compare as instants.
func recordTime(value interface{}) (time.Time, bool) {
	return utcTime(value, recordTimeRE)
}

func utcTime(value interface{}, form *regexp.Regexp) (time.Time, bool) {
	text, ok := value.(string)
	if !ok || !form.MatchString(text) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	return parsed, err == nil
}

// signingInput is the UTF-8 JCS of value without the member named omit.
func signingInput(value map[string]interface{}, omit string) ([]byte, bool) {
	rest := make(map[string]interface{}, len(value))
	for k, v := range value {
		if k != omit {
			rest[k] = v
		}
	}
	data, err := canonical.JCS(rest)
	return data, err == nil
}

func exactMembers(value map[string]interface{}, names []string) bool {
	if len(value) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := value[name]; !ok {
			return false
		}
	}
	return true
}

// bindingForm checks a binding record's form ("Controller Binding Records").
// A method token the draft does not define is well formed; one defined for
// another claim type is not.
func bindingForm(record map[string]interface{}) bool {
	claim, _ := record["claim"].(string)
	spec, known := bindingClaims[claim]
	members := append(append([]string(nil), bindingMembers...), spec.added...)
	if _, typed := record["key_types"]; typed {
		members = append(members, "key_types")
		types, ok := record["key_types"].([]interface{})
		if !ok || len(types) != 2 || !isString(types[0]) || !isString(types[1]) {
			return false
		}
	}
	if !known || !exactMembers(record, members) {
		return false
	}
	method, ok := record["method"].(string)
	if !ok {
		return false
	}
	for _, other := range bindingClaims {
		if method == other.method && method != spec.method {
			return false
		}
	}
	keys, ok := record["keys"].([]interface{})
	if !ok || len(keys) != 2 || !isDigest(keys[0]) || !isDigest(keys[1]) || keys[0].(string) >= keys[1].(string) {
		return false
	}
	issued, okIssued := bindingTime(record["issued_at"])
	notBefore, okBefore := bindingTime(record["not_before"])
	notAfter, okAfter := bindingTime(record["not_after"])
	if !okIssued || !okBefore || !okAfter || notBefore.After(issued) || !notAfter.After(issued) {
		return false
	}
	if record["binding_version"] != bindingVersion || record["revocation"] != revocationMethod {
		return false
	}
	if nonce, ok := record["nonce"].(string); !ok || nonce == "" {
		return false
	}
	sigs, ok := record["sigs"].([]interface{})
	if !ok {
		return false
	}
	for _, raw := range sigs {
		entry, ok := raw.(map[string]interface{})
		sig, _ := entry["sig"].(string)
		if !ok || !exactMembers(entry, []string{"key_id", "sig"}) || !isDigest(entry["key_id"]) {
			return false
		}
		// A key type other than ed25519 signs in its own form (draft -02
		// leaves it to the document defining that type).
		if ed25519Keys(record) && !signatureHexRE.MatchString(sig) {
			return false
		}
	}
	switch claim {
	case "delegated_by":
		return record["delegator"] == keys[0] || record["delegator"] == keys[1]
	case "same_organization_credentialed":
		credential, ok := record["credential"].(map[string]interface{})
		return ok && exactMembers(credential, []string{"issuer", "method", "digest"}) &&
			isDigest(credential["issuer"]) && isString(credential["method"]) && isDigest(credential["digest"])
	}
	return true
}

// ed25519Keys reports whether both bound keys are Ed25519 keys: key_types
// is absent, or names ed25519 twice. The draft defines no other key type, so
// a record under one is skipped like a record under an unimplemented method.
func ed25519Keys(record map[string]interface{}) bool {
	raw, typed := record["key_types"]
	if !typed {
		return true
	}
	types, ok := raw.([]interface{})
	return ok && len(types) == 2 && types[0] == "ed25519" && types[1] == "ed25519"
}

// bindingSignatures checks that sigs carries exactly one signature by each
// bound key, in the order of keys, over the signing input.
func bindingSignatures(record map[string]interface{}, input []byte) bool {
	keys := record["keys"].([]interface{})
	sigs := record["sigs"].([]interface{})
	if len(sigs) != 2 {
		return false
	}
	for i, raw := range sigs {
		entry := raw.(map[string]interface{})
		if entry["key_id"] != keys[i] {
			return false
		}
		public, errKey := hex.DecodeString(keys[i].(string))
		signature, errSig := hex.DecodeString(entry["sig"].(string))
		if errKey != nil || errSig != nil ||
			!ed25519strict.Verify(ed25519.PublicKey(public), input, signature) {
			return false
		}
	}
	return true
}

// revocationRevokes reports whether a delivered revocation statement applies
// to the binding with this digest and keys and takes effect at or before
// either time.
func revocationRevokes(statement map[string]interface{}, digest string, keys []interface{}, times [2]time.Time) bool {
	if !exactMembers(statement, revocationShape) || statement["revocation_version"] != revocationVersion ||
		statement["binding"] != digest || (statement["key_id"] != keys[0] && statement["key_id"] != keys[1]) {
		return false
	}
	revokedAt, ok := bindingTime(statement["revoked_at"])
	sig, _ := statement["sig"].(string)
	if !ok || !signatureHexRE.MatchString(sig) {
		return false
	}
	input, ok := signingInput(statement, "sig")
	public, _ := hex.DecodeString(statement["key_id"].(string))
	signature, _ := hex.DecodeString(sig)
	if !ok || !ed25519strict.Verify(ed25519.PublicKey(public), input, signature) {
		return false
	}
	return !revokedAt.After(times[0]) || !revokedAt.After(times[1])
}

// controllerBindingLink derives the linkage of a controller_binding join
// between two root records. derivable is false when no delivered binding
// record has the join's identifier_digest, or when every one that does names
// a method this verifier does not implement. Otherwise linked is true when
// one such record applies: well formed, signed by both bound keys, its keys
// exactly the two values pointer selects, in effect at both root records'
// timestamps, and revoked by no delivered statement at or before either. A
// join without pointer or identifier_digest names no record: not derivable.
func controllerBindingLink(j composedJoin, a, b bindingSide, opts Options) (linked, derivable bool) {
	if j.identifier == nil {
		return false, false
	}
	va, okA, ta, okTA := a.key, a.okKey, a.at, a.okAt
	vb, okB, tb, okTB := b.key, b.okKey, b.at, b.okAt
	for _, record := range opts.ControllerBindings {
		input, ok := signingInput(record, "sigs")
		if !ok {
			continue
		}
		sum := sha256.Sum256(input)
		if hex.EncodeToString(sum[:]) != *j.identifier {
			continue
		}
		if !bindingForm(record) {
			// A malformed record does not apply: the join derives, unjoined.
			derivable = true
			continue
		}
		if method := record["method"].(string); method != methodDual && method != methodCredential || !ed25519Keys(record) {
			continue
		}
		derivable = true
		keys := record["keys"].([]interface{})
		pair := okA && okB && va != vb && (va == keys[0] || va == keys[1]) && (vb == keys[0] || vb == keys[1])
		notBefore, _ := bindingTime(record["not_before"])
		notAfter, _ := bindingTime(record["not_after"])
		inEffect := okTA && okTB && !ta.Before(notBefore) && !tb.Before(notBefore) &&
			ta.Before(notAfter) && tb.Before(notAfter)
		if !pair || !inEffect || !bindingSignatures(record, input) {
			continue
		}
		revoked := false
		for _, statement := range opts.BindingRevocations {
			if revocationRevokes(statement, *j.identifier, keys, [2]time.Time{ta, tb}) {
				revoked = true
				break
			}
		}
		if !revoked {
			return true, true
		}
	}
	return false, derivable
}

// bindingSide is one member's side of a controller_binding join: the key
// identifier the binding must name and the time T it must cover.
type bindingSide struct {
	key   string
	okKey bool
	at    time.Time
	okAt  bool
}

// recordSide reads a side from a root record: the key identifier pointer
// selects, and the record's timestamp. Asserted as a string: two resolved
// objects would not compare.
func recordSide(record map[string]interface{}, pointer string) bindingSide {
	raw, _ := resolvePointer(record, pointer)
	key, okKey := raw.(string)
	at, okAt := recordTime(record["timestamp"])
	return bindingSide{key: key, okKey: okKey, at: at, okAt: okAt}
}

// checkpointSide reads an empty-history member's side from its signed
// checkpoint: the key that signed checkpoint.cose and its timestamp. A
// member without a checkpoint that verifies has no key, so the join is not
// derivable.
func checkpointSide(body map[string]interface{}) (bindingSide, bool) {
	claim, signed, _ := VerifyCheckpoint(body)
	if claim.Status != "pass" || signed == nil {
		return bindingSide{}, false
	}
	at, okAt := recordTime(signed.Timestamp)
	return bindingSide{key: signed.KeyID, okKey: true, at: at, okAt: okAt}, true
}
