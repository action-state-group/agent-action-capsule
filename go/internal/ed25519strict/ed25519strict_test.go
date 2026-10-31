// SPDX-License-Identifier: BSD-3-Clause
package ed25519strict

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The shared strict Ed25519 cases of checkpointed-local-log
// (vectors/cross-language/cll-ed25519-vectors.json, a verbatim copy).
func TestVerifyMatchesTheCLLVectors(t *testing.T) {
	data, err := os.ReadFile("../../../vectors/cross-language/cll-ed25519-vectors.json")
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
		got := Verify(decode(c.PublicKey), decode(c.Message), decode(c.Signature))
		require.Equal(t, c.Valid, got, c.Name)
	}
}
