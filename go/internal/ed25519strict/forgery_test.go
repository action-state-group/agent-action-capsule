// SPDX-License-Identifier: BSD-3-Clause
package ed25519strict

import (
	"crypto/ed25519"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict/ed25519stricttest"
	"github.com/stretchr/testify/require"
)

// The identity key with R the identity and S = 0 verifies over any message
// under ed25519.Verify alone; Verify refuses it.
func TestVerifyRefusesTheIdentityKeyForgery(t *testing.T) {
	identity := ed25519stricttest.IdentityKey
	forged := ed25519stricttest.IdentityKeyForgery()
	require.True(t, ed25519.Verify(identity, []byte("any message"), forged))
	require.False(t, Verify(identity, []byte("any message"), forged))
}

// A key holder's signature with R the identity (the "identity R" case, over
// another message) passes ed25519.Verify; Verify refuses it.
func TestVerifyRefusesAnIdentityR(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	message := []byte("any message")
	signature := ed25519stricttest.IdentityR(key, message)
	public := key.Public().(ed25519.PublicKey)
	require.True(t, ed25519.Verify(public, message, signature))
	require.False(t, Verify(public, message, signature))
	require.True(t, Verify(public, message, ed25519.Sign(key, message)))
}

// Wrong lengths are refused, never a panic.
func TestVerifyRefusesWrongLengths(t *testing.T) {
	require.False(t, Verify(make([]byte, 31), nil, make([]byte, 64)))
	require.False(t, Verify(make([]byte, 32), nil, make([]byte, 63)))
}
