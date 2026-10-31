// SPDX-License-Identifier: BSD-3-Clause

package controllerbinding

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict/ed25519stricttest"
	"github.com/stretchr/testify/require"
)

// Binding and revocation signatures by an ed25519 key are checked with
// verifyHex, under strict Ed25519: the identity key's forgery and a
// small-order R by an honest key (the "small-order A" and "identity R" cases
// of cll-ed25519-vectors.json), which ed25519.Verify accepts, are refused.
func TestVerifyHexIsStrict(t *testing.T) {
	message := []byte("signed octets")
	identity := ed25519stricttest.IdentityKey
	forged := ed25519stricttest.IdentityKeyForgery()
	require.True(t, ed25519.Verify(identity, message, forged))
	require.False(t, verifyHex(hex.EncodeToString(identity), hex.EncodeToString(forged), message))

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	require.True(t, verifyHex(hex.EncodeToString(public), hex.EncodeToString(ed25519.Sign(key, message)), message))
	smallR := ed25519stricttest.IdentityR(key, message)
	require.True(t, ed25519.Verify(public, message, smallR))
	require.False(t, verifyHex(hex.EncodeToString(public), hex.EncodeToString(smallR), message))
	require.False(t, verifyHex("zz", hex.EncodeToString(forged), message))
}
