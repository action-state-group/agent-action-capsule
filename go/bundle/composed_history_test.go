// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// historyCases reads vectors/bundle/composed-history/vectors.json (bundle -03
// History members and the same_key basis).
func historyCases(t *testing.T) []bindingCase {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", "composed-history", "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var file struct {
		Count json.Number   `json:"count"`
		Cases []bindingCase `json:"cases"`
	}
	require.NoError(t, decoder.Decode(&file))
	require.Equal(t, json.Number("30"), file.Count)
	require.Len(t, file.Cases, 30)
	return file.Cases
}

func TestComposedHistoryVectors(t *testing.T) {
	digests := map[string]interface{}{}
	for _, c := range historyCases(t) {
		c := c
		digests[c.ID] = c.Expect["composed_digest"]
		t.Run(c.ID, func(t *testing.T) {
			composed := verifyBlock(t, c.Container, bindingOptions(c))
			if c.Expect["malformed"] == true {
				// A malformed block reports no composition result.
				require.Equal(t, "fail", composed.Status, composed.Findings)
				require.True(t, composed.Malformed)
				require.Empty(t, composed.Joins)
				return
			}
			preimage, err := ComposedDigestPreimage(composedBlockOf(c.Container))
			require.NoError(t, err)
			require.Equal(t, c.Expect["canonical_preimage"], string(preimage))
			require.Equal(t, c.Expect["status"], composed.Status, composed.Findings)
			want := map[string]interface{}{}
			for key, value := range c.Expect {
				if key != "canonical_preimage" && key != "composed_digest_equals_case" {
					want[key] = value
				}
			}
			require.Equal(t, want, expectShape(composed))
		})
	}
	// Declaring a History missing withholds its body, not its existence.
	require.Equal(t, digests["history-two-parties"], digests["history-member-missing"])
}

// TestComposedKeySourceVectors runs vectors/bundle/composed-key-source (bundle
// -03 member keys, #663) against each case's whole expect.
func TestComposedKeySourceVectors(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", "composed-key-source", "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var file struct {
		Count json.Number   `json:"count"`
		Cases []bindingCase `json:"cases"`
	}
	require.NoError(t, decoder.Decode(&file))
	require.Equal(t, json.Number("17"), file.Count)
	require.Len(t, file.Cases, 17)
	for _, c := range file.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			preimage, err := ComposedDigestPreimage(composedBlockOf(c.Container))
			require.NoError(t, err)
			require.Equal(t, c.Expect["canonical_preimage"], string(preimage))
			composed := verifyBlock(t, c.Container, bindingOptions(c))
			require.Equal(t, c.Expect["status"], composed.Status, composed.Findings)
			want := map[string]interface{}{}
			for key, value := range c.Expect {
				if key != "canonical_preimage" {
					want[key] = value
				}
			}
			require.Equal(t, want, expectShape(composed))
		})
	}
}
