// SPDX-License-Identifier: BSD-3-Clause
package canonical_test

import (
	"bytes"
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

// NestingCase is one case of vectors/json-nesting/cases.json.
type nestingCase struct {
	ID        string `json:"id"`
	Depth     int    `json:"depth"`
	Accept    bool   `json:"accept"`
	JSON      string `json:"json"`
	JCSSHA256 string `json:"jcs_sha256"`
}

func nestingCases(t *testing.T) []nestingCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "json-nesting", "cases.json"))
	require.NoError(t, err)
	var doc struct {
		MaxNestingDepth int           `json:"max_nesting_depth"`
		Cases           []nestingCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Equal(t, canonical.MaxNestingDepth, doc.MaxNestingDepth)
	require.Len(t, doc.Cases, 9)
	return doc.Cases
}

// vectors/json-nesting/: JCS renders a value nested up to the limit and
// refuses a deeper one, so a digest is defined for exactly the values Python,
// TypeScript and Rust give one.
func TestJSONNestingVectorsJCS(t *testing.T) {
	for _, c := range nestingCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader([]byte(c.JSON)))
			decoder.UseNumber()
			var value interface{}
			require.NoError(t, decoder.Decode(&value), "encoding/json reads to 10000 levels")
			assert.Equal(t, !c.Accept, canonical.TooDeep(value))
			out, err := canonical.JCS(value)
			if !c.Accept {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			sum := sha256.Sum256(out)
			assert.Equal(t, c.JCSSHA256, hex.EncodeToString(sum[:]))
		})
	}
}
