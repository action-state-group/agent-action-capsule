// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	require.NoError(t, err)
	return b
}

// A float map key is dropped and flagged, as the reference drops it, and a
// float value compares by value.
func TestStrictCBORDropsAFloatKey(t *testing.T) {
	// {"correlation": "d", 1.5: "x"}
	data := append([]byte{0xa2}, mustCBOR(t, "correlation")...)
	data = append(data, mustCBOR(t, "d")...)
	data = append(data, 0xf9, 0x3e, 0x00)
	data = append(data, mustCBOR(t, "x")...)
	d, err := decodeCBORItem(data)
	require.NoError(t, err)
	assert.True(t, d.irregular)
	assert.Equal(t, map[string]any{"correlation": "d"}, d.value)

	one, err := decodeCBORItem([]byte{0xf9, 0x3e, 0x00})
	require.NoError(t, err)
	two, err := decodeCBORItem([]byte{0xf9, 0x3e, 0x00})
	require.NoError(t, err)
	assert.True(t, strictEqual(one.value, two.value), "1.5 equals 1.5")
	for name, pair := range map[string]struct {
		a, b  []byte
		equal bool
	}{
		"1.5 at two widths": {[]byte{0xf9, 0x3e, 0x00}, []byte{0xfa, 0x3f, 0xc0, 0x00, 0x00}, true},
		"-0 and 0":          {[]byte{0xf9, 0x80, 0x00}, []byte{0xf9, 0x00, 0x00}, true},
		"NaN and NaN":       {[]byte{0xf9, 0x7e, 0x00}, []byte{0xf9, 0x7e, 0x00}, false},
		"1.0 and 1":         {[]byte{0xf9, 0x3c, 0x00}, []byte{0x01}, false},
	} {
		a, err := decodeCBORItem(pair.a)
		require.NoError(t, err, name)
		b, err := decodeCBORItem(pair.b)
		require.NoError(t, err, name)
		assert.Equal(t, pair.equal, strictEqual(a.value, b.value), name)
	}
	big, err := decodeCBORItem([]byte{0x1b, 0x10, 0, 0, 0, 0, 0, 0, 0})
	require.NoError(t, err)
	assert.True(t, strictEqual(big.value, cborBigUint{N: 1 << 60}), "2^60 equals 2^60")
	assert.False(t, numbersInDomain(big.value))
}

// In generic mode a byte-string key stays apart from the text key of the
// same content, so a checkpoint whose claims name "kind" only as bytes has
// no kind claim.
func TestGenericCBORKeepsByteKeysApart(t *testing.T) {
	// {"kind": 1, h'6b696e64': 2}
	data := append([]byte{0xa2}, mustCBOR(t, "kind")...)
	data = append(data, 0x01)
	data = append(data, mustCBOR(t, []byte("kind"))...)
	data = append(data, 0x02)
	d, err := decodeCBORGeneric(data)
	require.NoError(t, err)
	m := d.value.(map[any]any)
	assert.Equal(t, uint64(1), m["kind"])
	assert.Equal(t, uint64(2), m[cborBytesKey("kind")])
	assert.False(t, d.duplicateKeys)

	payload := append([]byte{0xa1}, mustCBOR(t, []byte("kind"))...)
	payload = append(payload, mustCBOR(t, "cll-checkpoint")...)
	protected := mustCBOR(t, map[int]any{1: -8, 4: make([]byte, 32), 15: map[int]any{1: "i", 2: "s"}})
	checkpoint := mustCBOR(t, cbor.Tag{Number: 18, Content: []any{protected, map[any]any{}, payload, make([]byte, 64)}})
	_, err = decodeCLLCheckpoint(checkpoint)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kind claim")

	d, err = decodeCBORGeneric([]byte{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	require.NoError(t, err, "an integer below -2^63 is still an integer")
	assert.Equal(t, cborNegative{N: 1<<64 - 1}, d.value)
}

// A proof is checked as the strict decoder reads it: a self-described CBOR
// tag around it, or around an item in it, is not the proof shape, though a
// generic decoder strips the tag.
func TestCLLProofsAreReadAsSent(t *testing.T) {
	leaf := []byte("leaf")
	peak := MMRIncludedRoot(0, CLLLeafValue(leaf), nil)
	proof, err := EncodeCLLInclusionProof(0, nil)
	require.NoError(t, err)
	require.Equal(t, "", inclusionFailure([][]byte{peak}, leaf, proof), "the proof as encoded")
	tagged := append([]byte{0xd9, 0xd9, 0xf7}, proof...)
	assert.NotEqual(t, "", inclusionFailure([][]byte{peak}, leaf, tagged))
	inner := append([]byte{0x82, 0xd9, 0xd9, 0xf7}, proof[1:]...) // the index wrapped
	assert.NotEqual(t, "", inclusionFailure([][]byte{peak}, leaf, inner))

	consistency := []byte{0x84, 0x01, 0x01, 0x81, 0x80, 0x80} // [1, 1, [[]], []]
	require.Equal(t, "", consistencyFailure([][]byte{peak}, [][]byte{peak}, consistency), "a one-node MMR extends itself")
	assert.NotEqual(t, "", consistencyFailure([][]byte{peak}, [][]byte{peak}, append([]byte{0xd9, 0xd9, 0xf7}, consistency...)))
	assert.NotEqual(t, "", consistencyFailure([][]byte{peak}, [][]byte{peak}, []byte{0x84, 0x01, 0xd9, 0xd9, 0xf7, 0x01, 0x81, 0x80, 0x80}))
}
