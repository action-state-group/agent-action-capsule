// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vectors/cbor-request-model/ (#529): a CBOR request is read only in core
// deterministic encoding with every item, inside ignored members too, in the
// request data model, as Python and Rust read it.
func TestCBORRequestModelVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "cbor-request-model", "cases.json"))
	require.NoError(t, err)
	var doc struct {
		Cases []struct {
			ID      string `json:"id"`
			Accept  bool   `json:"accept"`
			CBORHex string `json:"cbor_hex"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Len(t, doc.Cases, 18)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			octets, err := hex.DecodeString(c.CBORHex)
			require.NoError(t, err)
			check := ParseRequest(Message{Octets: octets, MediaType: MediaTypeCBOR})
			if c.Accept {
				assert.Empty(t, check.Reason, check.Why)
				assert.Equal(t, "n-1", check.Request.Nonce)
			} else {
				assert.Equal(t, ReasonRequestMalformed, check.Reason)
			}
		})
	}
}
