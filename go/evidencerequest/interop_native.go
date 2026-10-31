// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

const jwsMethod = "JWS compact serialization (RFC 7515), EdDSA (RFC 8037), under the key its kid names"

// DefaultNativeCheckers is the built-in native check set: JWS compact
// serialization with EdDSA, the form the conformance vectors carry. An
// object whose media type has no checker is reported NOT_CHECKED.
func DefaultNativeCheckers() map[string]NativeChecker {
	return map[string]NativeChecker{"application/jose": CheckJWSEdDSA}
}

// CheckJWSEdDSA verifies a JWS compact serialization signed with EdDSA over
// Ed25519 (profile §5.1, §7.2 native_check). The signing input is the
// ASCII of header.payload exactly as carried, so the payload is never
// re-encoded. kid names the raw public key in the §5.2 hex form, and the
// trust policy must accept it as a key for foreign objects at the
// evaluation time: the JWS carries no signing time.
func CheckJWSEdDSA(object any, trust TrustPolicy, evaluationTime string) PropertyReport {
	result := func(status, detail string) PropertyReport {
		return report("native_check", status, jwsMethod, detail)
	}
	text, ok := object.(string)
	if !ok || strings.Count(text, ".") != 2 {
		return result(StatusFail, "not a JWS compact serialization")
	}
	parts := strings.Split(text, ".")
	header, ok1 := opaqueReceived(parts[0], MediaTypeJSON)
	_, ok2 := opaqueReceived(parts[1], MediaTypeJSON)
	signature, ok3 := opaqueReceived(parts[2], MediaTypeJSON)
	if !ok1 || !ok2 || !ok3 {
		return result(StatusFail, "a segment is not base64url")
	}
	parsed, ok, _ := decodeReceivedJSON(header)
	h, isMap := parsed.value.(map[string]any)
	if !ok || !parsed.wellFormed || !isMap {
		return result(StatusFail, "the protected header is not a well-formed JSON object")
	}
	if h["alg"] != "EdDSA" {
		return result(StatusFail, fmt.Sprintf("alg is %s, not EdDSA", pyRepr(h["alg"])))
	}
	if present(h, "crit") {
		return result(StatusFail, "crit is present and no extension is understood (RFC 7515 §4.1.11)")
	}
	kid, isString := h["kid"].(string)
	if !isString || !IsDigest(kid) {
		return result(StatusFail, "kid is not a raw Ed25519 public key in hex (§5.2)")
	}
	switch trust.acceptsForeignKey(kid, evaluationTime) {
	case StatusFail:
		return result(StatusFail, "the trust policy does not accept the key kid names")
	case StatusInconclusive:
		return result(StatusInconclusive, "the trust policy cannot resolve the key's status")
	}
	key, _ := hex.DecodeString(kid)
	if len(signature) != ed25519.SignatureSize || !ed25519strict.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return result(StatusFail, "the signature does not verify")
	}
	return result(StatusPass, "")
}

// decodeArtifactJSON reads a JSON Artifact the way the native check reads
// it: its own format governs it, so a value outside §5.2 elsewhere in it
// does not hide the foreign object. Nil when it is not JSON.
func decodeArtifactJSON(artifact []byte) any {
	parsed, ok, _ := decodeReceivedJSON(artifact)
	if !ok {
		return nil
	}
	return parsed.value
}
