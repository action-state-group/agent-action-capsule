// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vectors/cbor-nesting/: every Go reader of received CBOR (the request
// reader's DecodeCBOR and the interop profile's strict decoder) reads items
// nested up to the limit the JSON readers share and refuses deeper input as
// malformed, as Python and Rust do (#504).
func TestCBORNestingVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "cbor-nesting", "cases.json"))
	require.NoError(t, err)
	var doc struct {
		MaxNestingDepth int `json:"max_nesting_depth"`
		Cases           []struct {
			ID      string `json:"id"`
			Accept  bool   `json:"accept"`
			Tag     bool   `json:"tag"`
			CBORHex string `json:"cbor_hex"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Equal(t, canonical.MaxNestingDepth, doc.MaxNestingDepth)
	require.Len(t, doc.Cases, 9)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			octets, err := hex.DecodeString(c.CBORHex)
			require.NoError(t, err)

			generic, genericErr := decodeCBORGeneric(octets)
			_, interopErr := decodeCBORItem(octets)
			if c.Accept {
				require.NoError(t, genericErr)
				require.NoError(t, interopErr)
				assert.True(t, generic.wellFormed())
			} else {
				assert.ErrorIs(t, genericErr, errCBOR)
				assert.ErrorIs(t, interopErr, errCBOR)
			}

			check := ParseRequest(Message{Octets: octets, MediaType: MediaTypeCBOR})
			if c.Tag {
				// A request holds no tag at any depth (vectors/cbor-request-model/).
				assert.Equal(t, ReasonRequestMalformed, check.Reason)
				if !c.Accept {
					_, err := DecodeCBOR(octets)
					assert.ErrorIs(t, err, errNotWellFormed)
				}
				return
			}
			if c.Accept {
				assert.Empty(t, check.Reason, check.Why)
				assert.Equal(t, "n-1", check.Request.Nonce)
			} else {
				assert.Equal(t, ReasonRequestMalformed, check.Reason)
				assert.Equal(t, "not a well-formed map", check.Why)
			}
		})
	}
}

// cborNestsTooDeep counts exactly where fxamacker's limit does not: a tag
// around a scalar or an array, a bignum tag, an indefinite-length container
// and an indefinite string.
func TestCBORNestsTooDeepCountsEveryLevel(t *testing.T) {
	repeat := func(unit []byte, n int, tail ...byte) []byte {
		var out []byte
		for i := 0; i < n; i++ {
			out = append(out, unit...)
		}
		return append(out, tail...)
	}
	limit := canonical.MaxNestingDepth
	for name, unit := range map[string][]byte{
		"tag":        {0xd9, 0x03, 0xe8},
		"array":      {0x81},
		"indefinite": {0x9f},
	} {
		inner := []byte{0xf6}
		if name == "indefinite" {
			inner = []byte{0xff}
		}
		closing := func(n int) []byte {
			if name != "indefinite" {
				return inner
			}
			out := []byte{}
			for i := 0; i < n; i++ {
				out = append(out, 0xff)
			}
			return out
		}
		assert.False(t, cborNestsTooDeep(repeat(unit, limit, closing(limit)...)), name)
		assert.True(t, cborNestsTooDeep(repeat(unit, limit+1, closing(limit+1)...)), name)
	}
	// Bignum tags around a byte string: 128 levels read, 129 refused.
	bignum := []byte{0xc2}
	assert.False(t, cborNestsTooDeep(repeat(bignum, limit, 0x41, 0x01)))
	assert.True(t, cborNestsTooDeep(repeat(bignum, limit+1, 0x41, 0x01)))
	// An indefinite string is not a level; a malformed head is left to the decoder.
	assert.False(t, cborNestsTooDeep([]byte{0x7f, 0x61, 0x61, 0xff}))
	assert.False(t, cborNestsTooDeep([]byte{0x81}))
	assert.False(t, cborNestsTooDeep(nil))
}
