// SPDX-License-Identifier: BSD-3-Clause
package witness

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The shared strict Ed25519 cases of checkpointed-local-log
// (vectors/cross-language/cll-ed25519-vectors.json, a verbatim copy).
func TestVerifyEd25519StrictMatchesTheCLLVectors(t *testing.T) {
	data, err := os.ReadFile("../../vectors/cross-language/cll-ed25519-vectors.json")
	require.NoError(t, err)
	var vectors struct {
		Cases []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key_hex"`
			Message   string `json:"message_hex"`
			Signature string `json:"signature_hex"`
			Valid     bool   `json:"valid"`
		} `json:"ed25519_cases"`
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.Len(t, vectors.Cases, 54)
	decode := func(text string) []byte {
		raw, err := hex.DecodeString(text)
		require.NoError(t, err)
		return raw
	}
	for _, c := range vectors.Cases {
		got := verifyEd25519Strict(decode(c.PublicKey), decode(c.Message), decode(c.Signature))
		require.Equal(t, c.Valid, got, c.Name)
	}
}

// A receipt "signed" by the identity key (R the identity, S = 0) verifies
// over any root under ed25519.Verify alone; it must be refused.
func TestSmallOrderKeyReceiptIsRefused(t *testing.T) {
	identity := make([]byte, 32)
	identity[0] = 1
	forged := append(append([]byte(nil), identity...), make([]byte, 32)...)
	leaf := []byte("any leaf")
	receipt := buildReceipt(t, leaf, receiptSpec{alg: algEdDSA, vds: 1, signature: forged})
	require.True(t, ed25519.Verify(identity, []byte("any message"), forged))
	_, err := VerifyCOSEReceipt(receipt, leaf, ed25519.PublicKey(identity))
	require.Error(t, err)
}
