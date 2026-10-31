// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/controllerbinding"
	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
)

// The controller_binding join basis (draft-mih-zhang-agent-disclosure-bundle-02,
// "Controller Binding Records" and "Joins"). Binding records and revocation
// statements are delivered beside the containing Bundle (Options); the block
// binds a record only through a join's identifier_digest. This file derives
// the join's linkage and nothing else: it reports no binding property.

// bindingTimeRE is a binding or revocation time as -02 states it: RFC 3339,
// UTC, "Z", seconds precision. A root record's timestamp may carry fractional
// seconds (recordTimeRE); times compare as instants.
var (
	signatureHexRE = regexp.MustCompile(`^[0-9a-f]{128}$`)
	recordTimeRE   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$`)
)

// recordTime reads a root record's timestamp.
func recordTime(value interface{}) (time.Time, bool) {
	text, ok := value.(string)
	if !ok || !recordTimeRE.MatchString(text) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	return parsed, err == nil
}

// ed25519Keys reports whether both bound keys are Ed25519 keys: key_types
// is absent, or names ed25519 twice. -02 defines no other key type, so a
// record under one is skipped like a record under an unimplemented method.
func ed25519Keys(record map[string]interface{}) bool {
	raw, typed := record["key_types"]
	if !typed {
		return true
	}
	types, ok := raw.([]interface{})
	return ok && len(types) == 2 && types[0] == "ed25519" && types[1] == "ed25519"
}

// bindingReport verifies one delivered record through the one binding
// verifier, go/controllerbinding, at the given times. It returns the
// verifier's report and whether the record is well formed as -02 states it.
//
// -02 differs from Controller Binding v0 in two places, both applied here
// and nowhere else: an empty nonce is malformed, and a key type other than
// ed25519 is well formed without CB v0's rule for it (the 32-character
// bip340 nonce), because -02 does not define that type.
func bindingReport(record map[string]interface{}, times []time.Time, statements [][]byte) (report controllerbinding.Report, wellFormed bool) {
	subject := record
	if !ed25519Keys(record) {
		subject = make(map[string]interface{}, len(record))
		for k, v := range record {
			if k != "key_types" {
				subject[k] = v
			}
		}
	}
	octets, err := canonical.JCS(record)
	if err != nil {
		return controllerbinding.Report{}, false
	}
	report = controllerbinding.Verify(octets, times, controllerbinding.Options{Revocations: statements})
	if types, typed := record["key_types"]; typed {
		list, ok := types.([]interface{})
		if !ok || len(list) != 2 || !isString(list[0]) || !isString(list[1]) {
			return report, false
		}
	}
	if nonce, _ := record["nonce"].(string); nonce == "" {
		return report, false
	}
	// Under ed25519 keys a sig is a sig-hex; -02 makes a record that fails
	// this malformed, where CB v0 reads it as a signature that does not verify.
	if sigs, ok := record["sigs"].([]interface{}); ok && ed25519Keys(record) {
		for _, raw := range sigs {
			entry, _ := raw.(map[string]interface{})
			if sig, ok := entry["sig"].(string); !ok || !signatureHexRE.MatchString(sig) {
				return report, false
			}
		}
	}
	formReport := report
	if len(subject) != len(record) {
		if formOctets, err := canonical.JCS(subject); err == nil {
			formReport = controllerbinding.Verify(formOctets, nil, controllerbinding.Options{})
		}
	}
	return report, formReport.Properties[controllerbinding.PropertyForm] == evidencerequest.StatusPass
}

// bindingDigest is -02's binding digest: the SHA-256 of the JCS of the record
// without sigs. A join names its record by it, so a record with another
// digest is skipped before any signature is checked.
func bindingDigest(record map[string]interface{}) (string, bool) {
	rest := make(map[string]interface{}, len(record))
	for k, v := range record {
		if k != "sigs" {
			rest[k] = v
		}
	}
	octets, err := canonical.JCS(rest)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(octets)
	return hex.EncodeToString(sum[:]), true
}

// controllerBindingLink derives the linkage of a controller_binding join
// between two root records. derivable is false when no delivered binding
// record has the join's identifier_digest, or when every one that does names
// a method or key type this verifier does not implement. Otherwise linked is
// true when one such record applies: well formed, signed by both bound keys,
// its keys exactly the two values pointer selects, in effect at both root
// records' timestamps, and revoked by no delivered statement at or before
// either. A join without pointer or identifier_digest names no record: not
// derivable. The record checks are go/controllerbinding's; only the join's
// reading of its report is here.
func controllerBindingLink(j composedJoin, a, b bindingSide, opts Options) (linked, derivable bool) {
	if j.identifier == nil {
		return false, false
	}
	var times []time.Time
	if a.okAt && b.okAt {
		times = []time.Time{a.at, b.at}
	}
	var statements [][]byte
	for _, statement := range opts.BindingRevocations {
		if octets, err := canonical.JCS(statement); err == nil {
			statements = append(statements, octets)
		}
	}
	for _, record := range opts.ControllerBindings {
		if digest, ok := bindingDigest(record); !ok || digest != *j.identifier {
			continue
		}
		report, wellFormed := bindingReport(record, times, statements)
		if !wellFormed {
			// A malformed record does not apply: the join derives, unjoined.
			derivable = true
			continue
		}
		if !implemented(record) {
			continue
		}
		derivable = true
		if a.okKey && b.okKey && report.AppliesTo(a.key, b.key) {
			return true, true
		}
	}
	return false, derivable
}

// implemented reports whether this verifier implements the record's method
// and key types: a method -02 defines for the record's claim, and ed25519
// keys.
func implemented(record map[string]interface{}) bool {
	method, _ := record["method"].(string)
	claim, _ := record["claim"].(string)
	want := "dual_signature/0"
	if claim == "same_organization_credentialed" {
		want = "dual_signature_credential/0"
	}
	return method == want && ed25519Keys(record)
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
