// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/witness"
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
	methodTokenRE   = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
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
	if !known || !exactMembers(record, append(append([]string(nil), bindingMembers...), spec.added...)) {
		return false
	}
	method, ok := record["method"].(string)
	if !ok || !methodTokenRE.MatchString(method) {
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
		if !ok || !exactMembers(entry, []string{"key_id", "sig"}) || !isDigest(entry["key_id"]) || !isString(entry["sig"]) {
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
		sig, _ := entry["sig"].(string)
		signature, errSig := hex.DecodeString(sig)
		if errKey != nil || errSig != nil || !signatureHexRE.MatchString(sig) ||
			!witness.VerifyEd25519Strict(ed25519.PublicKey(public), input, signature) {
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
	if !ok || !witness.VerifyEd25519Strict(ed25519.PublicKey(public), input, signature) {
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
// timestamps, and revoked by no delivered statement at or before either.
func controllerBindingLink(j composedJoin, ra, rb map[string]interface{}, opts Options) (linked, derivable bool) {
	if j.pointer == nil || j.identifier == nil {
		return false, true
	}
	// Asserted as strings: two resolved objects would not compare.
	rawA, _ := resolvePointer(ra, *j.pointer)
	rawB, _ := resolvePointer(rb, *j.pointer)
	va, okA := rawA.(string)
	vb, okB := rawB.(string)
	ta, okTA := recordTime(ra["timestamp"])
	tb, okTB := recordTime(rb["timestamp"])
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
		if method := record["method"].(string); method != methodDual && method != methodCredential {
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
