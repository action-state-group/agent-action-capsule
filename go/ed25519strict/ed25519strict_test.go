// SPDX-License-Identifier: BSD-3-Clause
package ed25519strict

import (
	"crypto/ed25519"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict/ed25519stricttest"
	"github.com/stretchr/testify/require"
)

// The public Verify applies the module's strict rule: an ordinary signature
// verifies; the small-order-key and identity-R forgeries, which
// ed25519.Verify alone accepts, do not; wrong lengths never verify.
func TestVerifyIsStrict(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	message := []byte("any message")
	require.True(t, Verify(public, message, ed25519.Sign(key, message)))

	forged := ed25519stricttest.IdentityKeyForgery()
	require.True(t, ed25519.Verify(ed25519stricttest.IdentityKey, message, forged))
	require.False(t, Verify(ed25519stricttest.IdentityKey, message, forged))

	identityR := ed25519stricttest.IdentityR(key, message)
	require.True(t, ed25519.Verify(public, message, identityR))
	require.False(t, Verify(public, message, identityR))

	require.False(t, Verify(make([]byte, 31), nil, make([]byte, 64)))
	require.False(t, Verify(make([]byte, 32), nil, make([]byte, 63)))
}
