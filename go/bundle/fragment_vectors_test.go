// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fragment codec over vectors/bundle/fragment/, which the TypeScript
// codec test reads too: an ASCII payload encodes to the recorded token, and
// every recorded token decodes to its payload.
func TestFragmentCodecMatchesFragmentPyVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "vectors", "bundle", "fragment", "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(raw))
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
