// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict/ed25519stricttest"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each test below uses the two kinds of signature ed25519.Verify accepts and
// strict Ed25519 refuses (the "small-order A" and "identity R" cases of
// cll-ed25519-vectors.json), each over the path's own message, and checks
// first that ed25519.Verify does accept it, so the path's refusal is the
// strict check's doing.

var identityKey = ed25519stricttest.IdentityKey

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func identityForgery(message []byte, t *testing.T) []byte {
	t.Helper()
	forged := ed25519stricttest.IdentityKeyForgery()
	require.True(t, ed25519.Verify(identityKey, message, forged))
	return forged
}

func identityR(key ed25519.PrivateKey, message []byte, t *testing.T) []byte {
	t.Helper()
	signature := ed25519stricttest.IdentityR(key, message)
	require.True(t, ed25519.Verify(key.Public().(ed25519.PublicKey), message, signature))
	return signature
}

// The interop envelope, refusal and acceptance signatures are checked with
// verifyHexSignature.
func TestVerifyHexSignatureIsStrict(t *testing.T) {
	message := []byte("any message")
	assert.False(t, verifyHexSignature(hex.EncodeToString(identityKey), hex.EncodeToString(identityForgery(message, t)), message))

	key := testKey(8)
	keyHex := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	assert.True(t, verifyHexSignature(keyHex, hex.EncodeToString(ed25519.Sign(key, message)), message))
	assert.False(t, verifyHexSignature(keyHex, hex.EncodeToString(identityR(key, message, t)), message))
}

func jws(kid string, sign func([]byte) []byte) string {
	b64 := base64.RawURLEncoding.EncodeToString
	signingInput := b64([]byte(`{"alg":"EdDSA","kid":"`+kid+`"}`)) + "." + b64([]byte(`{}`))
	return signingInput + "." + b64(sign([]byte(signingInput)))
}

// The native JWS check verifies under a trust-policy key: a small-order key
// or R is refused even when the policy lists the key.
func TestCheckJWSEdDSAIsStrict(t *testing.T) {
	identityHex := hex.EncodeToString(identityKey)
	forged := jws(identityHex, func(m []byte) []byte { return identityForgery(m, t) })
	report := CheckJWSEdDSA(forged, TrustPolicy{ForeignKeys: []string{identityHex}}, "2026-10-16T00:00:00Z")
	assert.Equal(t, StatusFail, report.Status)

	key := testKey(7)
	keyHex := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	trust := TrustPolicy{ForeignKeys: []string{keyHex}}
	honest := jws(keyHex, func(m []byte) []byte { return ed25519.Sign(key, m) })
	assert.Equal(t, StatusPass, CheckJWSEdDSA(honest, trust, "2026-10-16T00:00:00Z").Status)
	smallR := jws(keyHex, func(m []byte) []byte { return identityR(key, m, t) })
	assert.Equal(t, StatusFail, CheckJWSEdDSA(smallR, trust, "2026-10-16T00:00:00Z").Status)
}

// inclusionCase is a record-subject envelope carrying one CLL checkpoint,
// signed by sign under kid, and a placeholder inclusion proof.
func inclusionCase(t *testing.T, kid []byte, sign func([]byte) []byte) (map[string]any, [][]byte) {
	t.Helper()
	marshal := func(v any) []byte {
		out, err := deterministicCBOR.Marshal(v)
		require.NoError(t, err)
		return out
	}
	protected := marshal(map[any]any{1: -8, 4: kid, 15: map[any]any{1: "iss", 2: "sub"}})
	payload := marshal(map[any]any{
		"kind": "cll-checkpoint", "log_size": 1, "prev_size": 0, "prev_commitment": []byte{},
		"issued_at": "2026-10-15T00:00:00Z", "commitment": marshal([]any{bytes.Repeat([]byte{2}, 32)}),
	})
	checkpoint := marshal(cbor.Tag{Number: 18, Content: []any{protected, map[any]any{}, payload, sign(sigStructure(protected, payload))}})
	proof := []byte("proof")
	artifact := Digest([]byte("artifact"))
	env := map[string]any{
		"subject":         map[string]any{"record": artifact},
		"artifact_digest": artifact,
		"anchor":          map[string]any{"digest": Digest(checkpoint)},
		"verification": []any{
			map[string]any{"kind": KindCLLCheckpoint, "digest": Digest(checkpoint)},
			map[string]any{"kind": KindCLLInclusionProof, "digest": Digest(proof)},
		},
	}
	return env, [][]byte{checkpoint, proof}
}

// anchor_inclusion step 10 verifies the checkpoint under a trust-policy log
// key: a small-order key or R fails there.
func TestCheckpointSignatureIsStrict(t *testing.T) {
	passed := map[string]string{"envelope_signature": StatusPass, "artifact_digest": StatusPass, "verification_binding": StatusPass}
	run := func(kid []byte, sign func([]byte) []byte) PropertyReport {
		env, material := inclusionCase(t, kid, sign)
		trust := TrustPolicy{LogKeys: []LogKey{{Iss: "iss", Sub: "sub", Kid: hex.EncodeToString(kid)}}}
		return checkAnchorInclusion(env, material, passed, trust, CLLKinds)
	}
	forged := run(identityKey, func(m []byte) []byte { return identityForgery(m, t) })
	assert.Equal(t, StatusFail, forged.Status)
	assert.True(t, strings.HasPrefix(forged.Detail, "step 10:"), forged.Detail)

	key := testKey(9)
	public := key.Public().(ed25519.PublicKey)
	honest := run(public, func(m []byte) []byte { return ed25519.Sign(key, m) })
	assert.False(t, strings.HasPrefix(honest.Detail, "step 10:"), honest.Detail)
	smallR := run(public, func(m []byte) []byte { return identityR(key, m, t) })
	assert.Equal(t, StatusFail, smallR.Status)
	assert.True(t, strings.HasPrefix(smallR.Detail, "step 10:"), smallR.Detail)
}
