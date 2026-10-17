// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fragment codec against capsule-viewer's fragment.py, over the vectors
// the TypeScript codec test reads too: an ASCII payload encodes to the same
// token, and every token decodes to its payload.
func TestFragmentCodecMatchesFragmentPyVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "ts", "test", "testdata", "presentation-fragment-vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var doc struct {
		Cases []struct {
			Name       string      `json:"name"`
			ASCIIJSON  bool        `json:"ascii_json"`
			FragmentPy string      `json:"fragment_py"`
			Payload    interface{} `json:"payload"`
		} `json:"cases"`
	}
	require.NoError(t, decoder.Decode(&doc))
	require.NotEmpty(t, doc.Cases)
	for _, c := range doc.Cases {
		token, err := EncodeFragment(c.Payload)
		require.NoError(t, err, c.Name)
		if c.ASCIIJSON {
			require.Equal(t, c.FragmentPy, token, c.Name)
		}
		decoded, err := DecodeFragment(c.FragmentPy)
		require.NoError(t, err, c.Name)
		require.Equal(t, c.Payload, decoded, c.Name)
	}
}
