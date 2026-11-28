// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"encoding/hex"
	"regexp"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

// The carried signature profiles of composed/v1
// (draft-mih-zhang-agent-disclosure-bundle-03, "Carried Signature
// Profiles"): three opt-in profiles in which a verifier checks the signature
// of a refusal or an artifact response a member carries. Pass
// VerifyCarriedRefusal and VerifyCarriedResponse as Options.RefusalSignature
// and Options.ResponseSignature; without them every carried signature stays
// signature-unverified.
//
// Each check returns RefusalSignatureVerified, RefusalSignatureInvalid or
// RefusalSignatureUnverified. The state covers the signature alone: no check
// of a signed value (a timestamp's format, a digest's form, a registered
// reason) enters it, and it does not compare the key with the member's
// responder. Ed25519 is strict: a small-order key or R never verifies.
const (
	// ThreeMemberRefusalProfile signs the refusal's issued_at, reason and
	// request_digest with sig under key_id.
	ThreeMemberRefusalProfile = "three-member-refusal/v1"
	// WholeRefusalProfile signs the whole refusal without signature with
	// signature under key_id.
	WholeRefusalProfile = "whole-refusal/v1"
	// DigestBoundArtifactResponseProfile signs an artifact response's
	// request_digest, anchor, artifact_kind, artifact_digest and issued_at,
	// with the type ArtifactResponseType, with sig under key_id.
	DigestBoundArtifactResponseProfile = "digest-bound-artifact-response/v1"
)

// ArtifactResponseType is the type the verifier supplies to a digest-bound
// artifact response's signing input; it is never read from the carried
// object.
const ArtifactResponseType = "evidence-artifact-response/v1"

var (
	carriedKeyRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	carriedSigRE = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// CarriedRefusalProfile is the profile a carried refusal is read in: one
// that carries sig and no signature is in ThreeMemberRefusalProfile, unless
// it also carries policy_digest (an evidence-interop/2 refusal may sign it),
// in which case it is in none of these profiles (""); every other refusal is
// in WholeRefusalProfile. Presence decides; a null member is present.
func CarriedRefusalProfile(refusal map[string]interface{}) string {
	_, hasSig := refusal["sig"]
	_, hasSignature := refusal["signature"]
	if hasSig && !hasSignature {
		if _, hasPolicy := refusal["policy_digest"]; hasPolicy {
			return ""
		}
		return ThreeMemberRefusalProfile
	}
	return WholeRefusalProfile
}

// CarriedResponseProfile is DigestBoundArtifactResponseProfile for a
// carried response that does not carry responder, and "" for one that
// does, which is in none of these profiles.
func CarriedResponseProfile(response map[string]interface{}) string {
	if _, ok := response["responder"]; ok {
		return ""
	}
	return DigestBoundArtifactResponseProfile
}

// VerifyCarriedRefusal checks a carried refusal's signature in the profile
// CarriedRefusalProfile reads it in. It is a RefusalSignatureVerifier.
func VerifyCarriedRefusal(refusal map[string]interface{}) string {
	if CarriedRefusalProfile(refusal) == ThreeMemberRefusalProfile {
		return VerifyThreeMemberRefusal(refusal)
	}
	return VerifyWholeRefusal(refusal)
}

// VerifyCarriedResponse checks a carried response's signature. It is a
// ResponseSignatureVerifier: every response this file can check is in
// DigestBoundArtifactResponseProfile.
func VerifyCarriedResponse(response map[string]interface{}) string {
	return VerifyDigestBoundArtifactResponse(response)
}

// ThreeMemberRefusalSigningInput is the UTF-8 JCS of the refusal's
// issued_at, reason and request_digest; ok is false when one is absent or
// not a string.
func ThreeMemberRefusalSigningInput(refusal map[string]interface{}) (input []byte, ok bool) {
	signed, ok := carriedStrings(refusal, "issued_at", "reason", "request_digest")
	if !ok {
		return nil, false
	}
	input, err := canonical.JCS(signed)
	return input, err == nil
}

// VerifyThreeMemberRefusal checks the refusal's sig under its key_id in
// ThreeMemberRefusalProfile. A refusal in this profile carries sig, so it is
// never signature-unverified; one CarriedRefusalProfile reads in another
// profile, or in none, is not checked here and is signature-unverified.
func VerifyThreeMemberRefusal(refusal map[string]interface{}) string {
	if CarriedRefusalProfile(refusal) != ThreeMemberRefusalProfile {
		return RefusalSignatureUnverified
	}
	input, ok := ThreeMemberRefusalSigningInput(refusal)
	if !ok {
		return RefusalSignatureInvalid
	}
	return carriedVerifies(refusal["key_id"], refusal["sig"], input)
}

// VerifyWholeRefusal checks the refusal's signature under its key_id over
// the JCS of the refusal without signature, in WholeRefusalProfile. A
// refusal CarriedRefusalProfile reads in another profile, or in none, is not
// checked here and is signature-unverified.
func VerifyWholeRefusal(refusal map[string]interface{}) string {
	if CarriedRefusalProfile(refusal) != WholeRefusalProfile {
		return RefusalSignatureUnverified
	}
	_, hasKey := refusal["key_id"]
	_, hasSignature := refusal["signature"]
	if !hasKey && !hasSignature {
		return RefusalSignatureUnverified
	}
	unsigned := make(map[string]interface{}, len(refusal))
	for name, member := range refusal {
		if name != "signature" {
			unsigned[name] = member
		}
	}
	input, err := canonical.JCS(unsigned)
	if err != nil {
		return RefusalSignatureInvalid
	}
	return carriedVerifies(refusal["key_id"], refusal["signature"], input)
}

// ArtifactResponseSigningInput is the signing input of
// DigestBoundArtifactResponseProfile: the UTF-8 JCS of the five members and
// the type ArtifactResponseType. A producer signs these bytes.
func ArtifactResponseSigningInput(requestDigest, anchor, artifactKind, artifactDigest, issuedAt string) ([]byte, error) {
	return canonical.JCS(map[string]interface{}{
		"type": ArtifactResponseType, "request_digest": requestDigest, "anchor": anchor,
		"artifact_kind": artifactKind, "artifact_digest": artifactDigest, "issued_at": issuedAt,
	})
}

// VerifyDigestBoundArtifactResponse checks a carried response's sig under
// its key_id in DigestBoundArtifactResponseProfile. A response that carries
// responder is in none of these profiles and is signature-unverified, as is
// one that carries neither key_id nor sig.
func VerifyDigestBoundArtifactResponse(response map[string]interface{}) string {
	if CarriedResponseProfile(response) == "" {
		return RefusalSignatureUnverified
	}
	_, hasKey := response["key_id"]
	_, hasSig := response["sig"]
	if !hasKey && !hasSig {
		return RefusalSignatureUnverified
	}
	signed, ok := carriedStrings(response, "request_digest", "anchor", "artifact_kind", "artifact_digest", "issued_at")
	if !ok {
		return RefusalSignatureInvalid
	}
	input, err := ArtifactResponseSigningInput(signed["request_digest"].(string), signed["anchor"].(string),
		signed["artifact_kind"].(string), signed["artifact_digest"].(string), signed["issued_at"].(string))
	if err != nil {
		return RefusalSignatureInvalid
	}
	return carriedVerifies(response["key_id"], response["sig"], input)
}

// carriedStrings returns the named members, each present and a string.
func carriedStrings(value map[string]interface{}, names ...string) (map[string]interface{}, bool) {
	out := make(map[string]interface{}, len(names))
	for _, name := range names {
		member, ok := value[name].(string)
		if !ok {
			return nil, false
		}
		out[name] = member
	}
	return out, true
}

// carriedVerifies is the state of a signature: key and sig lowercase hex of
// a 32-byte key and a 64-byte signature, and strict Ed25519 over input.
func carriedVerifies(rawKey, rawSig interface{}, input []byte) string {
	key, keyOK := rawKey.(string)
	sig, sigOK := rawSig.(string)
	if !keyOK || !sigOK || !carriedKeyRE.MatchString(key) || !carriedSigRE.MatchString(sig) {
		return RefusalSignatureInvalid
	}
	keyBytes, _ := hex.DecodeString(key)
	sigBytes, _ := hex.DecodeString(sig)
	if !ed25519strict.Verify(keyBytes, input, sigBytes) {
		return RefusalSignatureInvalid
	}
	return RefusalSignatureVerified
}
