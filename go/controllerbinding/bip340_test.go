// SPDX-License-Identifier: BSD-3-Clause

package controllerbinding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The BIP-340 check against the BIP's own test vectors, the same five rows
// python/tests/test_controller_binding_v0_vectors.py checks: two valid and
// three invalid (index 5, 6 and 12 of the BIP's test-vectors.csv).
func TestBIP340AgreesWithTheBIPsVectors(t *testing.T) {
	rows := []struct {
		key, msg, sig string
		valid         bool
	}{
		{"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
			true},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
			true},
		{"EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			false},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
			false},
		{"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			"0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
			false},
	}
	for i, row := range rows {
		msg, err := hex.DecodeString(row.msg)
		require.NoError(t, err)
		got := verifyBIP340(strings.ToLower(row.key), msg, strings.ToLower(row.sig))
		assert.Equal(t, row.valid, got, "row %d", i)
	}
}

// nostrSig signs the §4.1 event with the given created_at token text, so the
// signature is valid over exactly that text.
func nostrSig(t *testing.T, createdAt string, signed []byte) (string, map[string]any) {
	t.Helper()
	secret := sha256.Sum256([]byte("bip340-test"))
	priv, _ := btcec.PrivKeyFromBytes(secret[:])
	key := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
	digest := sha256.Sum256(signed)
	event := `[0,"` + key + `",` + createdAt + `,3374,[],"` + Version + `:` + hex.EncodeToString(digest[:]) + `"]`
	id := sha256.Sum256([]byte(event))
	sig, err := schnorr.Sign(priv, id[:])
	require.NoError(t, err)
	return key, map[string]any{"created_at": evidencerequest.JSONNumber(createdAt),
		"sig": hex.EncodeToString(sig.Serialize())}
}

// created_at is an integer in 0..2^53-1 (CB §4.1), read from its token as
// the reference reads it: -0 is the integer 0; a fraction or an exponent is
// not an integer, even when the event was signed over that text.
func TestNostrCreatedAt(t *testing.T) {
	signed := []byte(`{"x":1}`)
	for _, c := range []struct {
		token string
		ok    bool
	}{
		{"0", true}, {"1700000000", true}, {"9007199254740991", true},
		{"9007199254740992", false}, {"-1", false}, {"1.0", false}, {"1e3", false},
	} {
		key, sig := nostrSig(t, c.token, signed)
		assert.Equal(t, c.ok, verifyNostr(key, sig, Version, signed), c.token)
	}
	// -0 is the integer 0, so the event is the one serialized with 0.
	key, sig := nostrSig(t, "0", signed)
	sig["created_at"] = evidencerequest.JSONNumber("-0")
	assert.True(t, verifyNostr(key, sig, Version, signed))

	key, sig = nostrSig(t, "1", signed)
	sig["created_at"] = "1"
	assert.False(t, verifyNostr(key, sig, Version, signed), "created_at as text")
	_, sig = nostrSig(t, "1", signed)
	assert.False(t, verifyNostr(key, sig, RevocationVersion, signed), "another version")
	assert.False(t, verifyNostr(key, sig, Version, []byte(`{"x":2}`)), "other octets")
	sig["sig"] = strings.ToUpper(sig["sig"].(string))
	assert.False(t, verifyNostr(key, sig, Version, signed), "uppercase sig")
}
