// SPDX-License-Identifier: BSD-3-Clause

// Package controllerbinding verifies a Controller Binding v0 binding record
// (spec/controller-binding-v0.md, cited as CB): its form (§3), both
// signatures over the one signing input (§4), its window, the revocation
// statements the caller received (§5), and, for same_organization_credentialed,
// a credential through a verifier the caller passes. It reports the binding
// properties of §6.1 in the profile's §7.1 vocabulary, what the binding proves
// (§7 item 2), whether it applies to a pair of keys (§6.2) and the
// issuer_independence that gives (§7 item 4).
//
// A binding shows only that whoever held each private key signed the record.
// Nothing here establishes who controls a key. The package ships no trust
// anchors, accepted credential issuers or credential verifier: no credential
// format is registered (CB-3), and accepting an issuer is the caller's trust
// policy.
//
// The conformance vectors in vectors/controller-binding-v0 are the package's
// tests.
package controllerbinding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
)

// Version is the binding_version of a binding record (CB §3.1), and
// RevocationVersion the revocation_version of a revocation statement (§5).
const (
	Version           = "controller-binding/0"
	RevocationVersion = "controller-binding-revocation/0"
	RevocationMethod  = "revocation_statement/0"
)

// The claim types of CB §3.2 and the verification methods this package
// implements.
const (
	ClaimSameController       = "same_controller_asserted"
	ClaimDelegatedBy          = "delegated_by"
	ClaimSameOrganization     = "same_organization_credentialed"
	MethodDualSignature       = "dual_signature/0"
	MethodDualSignatureCredit = "dual_signature_credential/0"
)

// The binding properties of CB §6.1.
const (
	PropertyForm       = "controller_binding_form"
	PropertySignatures = "controller_binding_signatures"
	PropertyWindow     = "controller_binding_window"
	PropertyRevocation = "controller_binding_revocation"
	PropertyCredential = "controller_binding_credential"
)

// What a binding proves (CB §7 item 2), in the vectors' words.
const (
	provesControl      = "control of both keys at the ceremony"
	provesCredentialed = "a trusted issuer key states that both keys are held within one organization"
)

// claims maps each claim type to its method and the member it adds (CB §3.2).
var claims = map[string]struct {
	method string
	added  string
	states string
}{
	ClaimSameController: {MethodDualSignature, "", "both key holders state that one controller holds both keys"},
	ClaimDelegatedBy: {MethodDualSignature, "delegator",
		"both key holders state that the delegator delegated to the other key"},
	ClaimSameOrganization: {MethodDualSignatureCredit, "credential",
		"both key holders state that both keys are held within one organization"},
}

var common = []string{"binding_version", "claim", "method", "keys", "issued_at", "not_before", "not_after",
	"revocation", "nonce", "sigs"}

var hex128 = regexp.MustCompile(`^[0-9a-f]{128}$`)

// Credential is the credential member of a same_organization_credentialed
// record (CB §3.2).
type Credential struct {
	Issuer string `json:"issuer"`
	Method string `json:"method"`
	Digest string `json:"digest"`
}

// CredentialVerifier checks a delivered credential, given as the octets
// transmitted, against the record's credential member and its two bound keys.
// It owns the credential's native method and the caller's trust policy, and
// returns a §7.1 status: PASS only when the credential verifies under
// credential.Issuer, the trust policy accepts that issuer and the credential
// names both keys; FAIL when any of these fails; INCONCLUSIVE when the trust
// policy cannot decide. The package has already checked the digest.
type CredentialVerifier func(octets []byte, credential Credential, keys [2]string) string

// Options are what the caller received beside the binding record, and how it
// checks a credential.
type Options struct {
	// Revocations are revocation statements as received (CB §5). One that
	// does not apply to this binding is ignored.
	Revocations [][]byte
	// Credential is the credential as transmitted, or nil when none was
	// delivered.
	Credential []byte
	// CredentialVerifiers checks a credential by its credential.method. A
	// method with no entry is not implemented: NOT_CHECKED.
	CredentialVerifiers map[string]CredentialVerifier
}

// Report is what a verifier reports for one binding record (CB §7).
type Report struct {
	Claim         string            `json:"claim,omitempty"`
	Keys          []string          `json:"keys,omitempty"`
	Delegator     string            `json:"delegator,omitempty"`
	NotBefore     string            `json:"not_before,omitempty"`
	NotAfter      string            `json:"not_after,omitempty"`
	BindingDigest string            `json:"binding_digest,omitempty"`
	Properties    map[string]string `json:"properties"`
	Proves        []string          `json:"proves"`
}

// Verify checks one binding record, given as the octets received, at the
// times ts: for a pair under IP §6.7.4, each member's issued_at. With no
// time the window is NOT_CHECKED, so the binding does not apply.
func Verify(record []byte, ts []time.Time, opts Options) Report {
	report := Report{Properties: map[string]string{}, Proves: []string{}}
	value, err := evidencerequest.DecodeJSON(record)
	r, ok := value.(map[string]any)
	if err != nil || !ok {
		report.Properties[PropertyForm] = evidencerequest.StatusFail
		return report
	}
	if signingInput, err := evidencerequest.EncodeJCS(without(r, "sigs")); err == nil {
		report.BindingDigest = evidencerequest.Digest(signingInput)
	}
	if c, ok := r["claim"].(string); ok {
		report.Claim = c
	}
	// The keys a record names are reported even when it is malformed, so a
	// pair can be told it is named by a binding that does not apply (§6.2).
	if named, ok := r["keys"].([]any); ok && len(named) == 2 {
		first, ok1 := named[0].(string)
		second, ok2 := named[1].(string)
		if ok1 && ok2 {
			report.Keys = []string{first, second}
		}
	}
	if !wellFormed(r) {
		report.Properties[PropertyForm] = evidencerequest.StatusFail
		return report
	}
	report.Properties[PropertyForm] = evidencerequest.StatusPass
	keys := [2]string{report.Keys[0], report.Keys[1]}
	report.Delegator, _ = r["delegator"].(string)
	report.NotBefore, report.NotAfter = r["not_before"].(string), r["not_after"].(string)

	report.Properties[PropertySignatures] = signatures(r, keys)
	report.Properties[PropertyWindow] = evidencerequest.StatusPass
	if len(ts) == 0 {
		report.Properties[PropertyWindow] = evidencerequest.StatusNotChecked
	}
	notBefore, _ := instant(report.NotBefore)
	notAfter, _ := instant(report.NotAfter)
	for _, t := range ts {
		if t.Before(notBefore) || !t.Before(notAfter) {
			report.Properties[PropertyWindow] = evidencerequest.StatusFail
		}
	}
	report.Properties[PropertyRevocation] = revocation(report.BindingDigest, keys, ts, opts.Revocations)
	if report.Claim == ClaimSameOrganization {
		report.Properties[PropertyCredential] = credential(credentialOf(r), keys, opts)
	}
	if report.Properties[PropertySignatures] == evidencerequest.StatusPass {
		report.Proves = append(report.Proves, provesControl, claims[report.Claim].states)
		if report.Properties[PropertyCredential] == evidencerequest.StatusPass {
			report.Proves = append(report.Proves, provesCredentialed)
		}
	}
	return report
}

// Applies reports whether the binding applies to the pair of its own two
// keys (CB §6.2): form, signatures and window PASS, and revocation not FAIL.
// The credential never decides it. AppliesTo asks about a given pair.
func (r Report) Applies() bool {
	p := r.Properties
	return p[PropertyForm] == evidencerequest.StatusPass && p[PropertySignatures] == evidencerequest.StatusPass &&
		p[PropertyWindow] == evidencerequest.StatusPass && p[PropertyRevocation] != evidencerequest.StatusFail
}

// Binds reports whether key is one of the two keys the record names.
func (r Report) Binds(key string) bool { return slices.Contains(r.Keys, key) }

// BindsPair reports whether the record's two keys are exactly a and b, in
// either order (CB §6.2).
func (r Report) BindsPair(a, b string) bool {
	return len(r.Keys) == 2 && ((r.Keys[0] == a && r.Keys[1] == b) || (r.Keys[0] == b && r.Keys[1] == a))
}

// AppliesTo reports whether the binding applies to the pair of keys a and b
// (CB §6.2). The Report must have been made at the pair's times.
func (r Report) AppliesTo(a, b string) bool { return r.BindsPair(a, b) && r.Applies() }

// IssuerIndependence is the issuer_independence a pair gets (CB §7 item 4).
type IssuerIndependence struct {
	Status  string  `json:"status"`
	ShownAs string  `json:"shown_as"`
	Reason  *string `json:"reason"`
}

// PairIndependence is the issuer_independence of a pair signed under keys a
// and b, given every binding report the verifier received for it (CB §9.1).
// A binding never gives PASS (§6.2).
func PairIndependence(a, b string, reports ...Report) IssuerIndependence {
	if a == b {
		reason := "same key"
		return IssuerIndependence{evidencerequest.StatusFail, "redundant, not corroborating", &reason}
	}
	for _, r := range reports {
		if r.AppliesTo(a, b) {
			reason := "controller binding " + r.Claim + " " + r.BindingDigest
			return IssuerIndependence{evidencerequest.StatusFail, "redundant, not corroborating", &reason}
		}
	}
	return IssuerIndependence{evidencerequest.StatusNotChecked, "not corroborating", nil}
}

func without(m map[string]any, name string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != name {
			out[k] = v
		}
	}
	return out
}

func hasMembers(m map[string]any, names []string) bool {
	if len(m) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}
	return true
}

// instant reads a §5.2 time naming a real calendar instant. ok is false when
// it is not one; the zero time is a valid instant, not a sentinel.
func instant(v any) (time.Time, bool) {
	s, _ := v.(string)
	return evidencerequest.ParseProfileTime(s)
}

func isKey(v any) bool {
	s, ok := v.(string)
	return ok && evidencerequest.IsDigest(s)
}

// wellFormed is controller_binding_form (CB §3.1, §3.2).
func wellFormed(r map[string]any) bool {
	claim, ok := r["claim"].(string)
	spec, known := claims[claim]
	if !ok || !known {
		return false
	}
	names := common
	if spec.added != "" {
		names = append(slices.Clone(common), spec.added)
	}
	if !hasMembers(r, names) || r["binding_version"] != Version {
		return false
	}
	// A method that §3.2 defines for another claim type is malformed; one it
	// does not define at all is well formed and NOT_CHECKED.
	method, ok := r["method"].(string)
	if !ok {
		return false
	}
	for _, other := range claims {
		if other.method == method && method != spec.method {
			return false
		}
	}
	keys, ok := r["keys"].([]any)
	if !ok || len(keys) != 2 || !isKey(keys[0]) || !isKey(keys[1]) || keys[0].(string) >= keys[1].(string) {
		return false // ascending, so also distinct: a key bound to itself states nothing
	}
	issued, ok1 := instant(r["issued_at"])
	notBefore, ok2 := instant(r["not_before"])
	notAfter, ok3 := instant(r["not_after"])
	if !ok1 || !ok2 || !ok3 || notBefore.After(issued) || !issued.Before(notAfter) {
		return false
	}
	if r["revocation"] != RevocationMethod {
		return false
	}
	if _, ok := r["nonce"].(string); !ok {
		return false
	}
	sigs, ok := r["sigs"].([]any)
	if !ok {
		return false
	}
	for _, s := range sigs {
		entry, ok := s.(map[string]any)
		if !ok || !hasMembers(entry, []string{"key_id", "sig"}) {
			return false
		}
	}
	switch spec.added {
	case "delegator":
		return r["delegator"] == keys[0] || r["delegator"] == keys[1]
	case "credential":
		c, ok := r["credential"].(map[string]any)
		if !ok || !hasMembers(c, []string{"issuer", "method", "digest"}) {
			return false
		}
		_, textMethod := c["method"].(string)
		return isKey(c["issuer"]) && textMethod && isKey(c["digest"])
	}
	return true
}

// signatures is controller_binding_signatures (CB §4): exactly two entries,
// naming keys in order, each verifying over the one signing input.
func signatures(r map[string]any, keys [2]string) string {
	if method := r["method"].(string); method != claims[r["claim"].(string)].method {
		return evidencerequest.StatusNotChecked // a method this revision does not define
	}
	signingInput, err := evidencerequest.EncodeJCS(without(r, "sigs"))
	sigs := r["sigs"].([]any)
	if err != nil || len(sigs) != 2 {
		return evidencerequest.StatusFail
	}
	for i, s := range sigs {
		entry := s.(map[string]any)
		if entry["key_id"] != keys[i] || !verifyHex(keys[i], entry["sig"], signingInput) {
			return evidencerequest.StatusFail
		}
	}
	return evidencerequest.StatusPass
}

func verifyHex(key string, sig any, message []byte) bool {
	text, ok := sig.(string)
	if !ok || !hex128.MatchString(text) {
		return false
	}
	raw, _ := hex.DecodeString(text)
	return evidencerequest.VerifySignature(key, message, raw) == nil
}

// revocation is controller_binding_revocation (CB §5, §6.1): FAIL when a
// received statement applies with revoked_at at or before some T, otherwise
// NOT_CHECKED, since a statement not received cannot be excluded (CB-1).
func revocation(digest string, keys [2]string, ts []time.Time, statements [][]byte) string {
	for _, octets := range statements {
		value, err := evidencerequest.DecodeJSON(octets)
		s, ok := value.(map[string]any)
		if err != nil || !ok || !hasMembers(s, []string{"revocation_version", "binding", "key_id", "revoked_at", "sig"}) ||
			s["revocation_version"] != RevocationVersion || s["binding"] != digest ||
			(s["key_id"] != keys[0] && s["key_id"] != keys[1]) {
			continue
		}
		signed, err := evidencerequest.EncodeJCS(without(s, "sig"))
		if err != nil || !verifyHex(s["key_id"].(string), s["sig"], signed) {
			continue
		}
		revokedAt, ok := instant(s["revoked_at"])
		if !ok {
			continue
		}
		for _, t := range ts {
			if !revokedAt.After(t) {
				return evidencerequest.StatusFail
			}
		}
	}
	return evidencerequest.StatusNotChecked
}

func credentialOf(r map[string]any) Credential {
	c := r["credential"].(map[string]any)
	return Credential{Issuer: c["issuer"].(string), Method: c["method"].(string), Digest: c["digest"].(string)}
}

// credential is controller_binding_credential (CB §6.1).
func credential(c Credential, keys [2]string, opts Options) string {
	if opts.Credential == nil {
		return evidencerequest.StatusNotPresent
	}
	verify, ok := opts.CredentialVerifiers[c.Method]
	if !ok || verify == nil {
		return evidencerequest.StatusNotChecked
	}
	sum := sha256.Sum256(opts.Credential)
	if hex.EncodeToString(sum[:]) != c.Digest {
		return evidencerequest.StatusFail
	}
	switch status := verify(opts.Credential, c, keys); status {
	case evidencerequest.StatusPass, evidencerequest.StatusFail, evidencerequest.StatusInconclusive:
		return status
	default:
		return evidencerequest.StatusFail // a verifier that returns no status vouches for nothing
	}
}
