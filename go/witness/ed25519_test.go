// SPDX-License-Identifier: BSD-3-Clause
package witness

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
)

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
