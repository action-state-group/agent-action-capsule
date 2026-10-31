// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"bytes"
	"encoding/base64"
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

// vectors/json-nesting/: a fragment or Bundle text nested 128 levels deep is
// decoded and one nested 129 levels is refused, as in Python, TypeScript and
// Rust.
func TestFragmentAndDecodeShareTheNestingLimit(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "json-nesting", "cases.json"))
	require.NoError(t, err)
	var doc struct {
		Cases []struct {
			ID     string `json:"id"`
			Accept bool   `json:"accept"`
			JSON   string `json:"json"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Len(t, doc.Cases, 9)
	for _, c := range doc.Cases {
		_, err := DecodeFragment(base64.RawURLEncoding.EncodeToString([]byte(c.JSON)))
		require.Equal(t, c.Accept, err == nil, "fragment %s: %v", c.ID, err)
		if c.JSON[0] == '{' {
			_, err = Decode([]byte(c.JSON))
			require.Equal(t, c.Accept, err == nil, "Decode %s: %v", c.ID, err)
		}
	}
}
