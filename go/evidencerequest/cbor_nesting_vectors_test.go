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

			if c.Tag {
				// Readers of a request differ on a tag in a member they ignore;
				// the generic decoders above count tag levels.
				return
			}
			check := ParseRequest(Message{Octets: octets, MediaType: MediaTypeCBOR})
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
