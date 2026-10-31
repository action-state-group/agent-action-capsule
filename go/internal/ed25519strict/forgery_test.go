// SPDX-License-Identifier: BSD-3-Clause
package ed25519strict

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
)

// The identity key with R the identity and S = 0 verifies over any message
// under ed25519.Verify alone; Verify refuses it.
func TestVerifyRefusesTheIdentityKeyForgery(t *testing.T) {
	identity := make([]byte, 32)
	identity[0] = 1
	forged := append(append([]byte(nil), identity...), make([]byte, 32)...)
	require.True(t, ed25519.Verify(identity, []byte("any message"), forged))
	require.False(t, Verify(identity, []byte("any message"), forged))
}

// Wrong lengths are refused, never a panic.
func TestVerifyRefusesWrongLengths(t *testing.T) {
	require.False(t, Verify(make([]byte, 31), nil, make([]byte, 64)))
	require.False(t, Verify(make([]byte, 32), nil, make([]byte, 63)))
}
