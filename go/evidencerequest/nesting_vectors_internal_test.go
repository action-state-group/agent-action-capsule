// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vectors/json-nesting/: both JSON readers (DecodeJSON, which Controller
// Binding, the history profiles and the request reader use, and the interop
// profile's received-value reader) read objects and arrays nested up to the
// limit Python, TypeScript and Rust share and refuse deeper text as they
// refuse other malformed input.
func TestJSONNestingVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "json-nesting", "cases.json"))
	require.NoError(t, err)
	var doc struct {
		MaxNestingDepth int `json:"max_nesting_depth"`
		Cases           []struct {
			ID        string `json:"id"`
			Accept    bool   `json:"accept"`
			JSON      string `json:"json"`
			JCSSHA256 string `json:"jcs_sha256"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Equal(t, canonical.MaxNestingDepth, doc.MaxNestingDepth)
	require.Len(t, doc.Cases, 9)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			value, err := DecodeJSON([]byte(c.JSON))
			received, duplicates, badNumber, receivedErr := parseReceivedJSON([]byte(c.JSON))
			if !c.Accept {
				assert.ErrorIs(t, err, errNotWellFormed)
				assert.ErrorIs(t, receivedErr, errJSON)
				return
			}
			require.NoError(t, err)
			require.NoError(t, receivedErr)
			assert.False(t, duplicates || badNumber)
			assert.Equal(t, value, received)
			out, err := EncodeJCS(value)
			require.NoError(t, err)
			sum := sha256.Sum256(out)
			assert.Equal(t, c.JCSSHA256, hex.EncodeToString(sum[:]))
		})
	}
}
