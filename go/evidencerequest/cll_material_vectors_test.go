// SPDX-License-Identifier: Apache-2.0

package evidencerequest_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cllMaterialCase is one case of vectors/cll-material: an encoder's inputs
// and the octets it must produce. Python's and Rust's encoders are checked
// against the same file.
type cllMaterialCase struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Inputs struct {
		Leaf     uint64     `json:"leaf"`
		Path     []string   `json:"path"`
		OldSize  uint64     `json:"old_size"`
		NewSize  uint64     `json:"new_size"`
		OldPeaks []string   `json:"old_peaks"`
		Paths    [][]string `json:"paths"`
		NewPeaks []string   `json:"new_peaks"`
	} `json:"inputs"`
	Context struct {
		Entry string   `json:"entry"`
		Peaks []string `json:"peaks"`
	} `json:"context"`
	Expected struct {
		OctetsHex string `json:"octets_hex"`
	} `json:"expected"`
}

func hexNodes(t *testing.T, hexes []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		node, err := hex.DecodeString(h)
		require.NoError(t, err)
		out[i] = node
	}
	return out
}

func TestCLLMaterialVectors(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "cll-material", "cases.json"))
	require.NoError(t, err)
	var corpus struct {
		Count int               `json:"count"`
		Cases []cllMaterialCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &corpus))
	require.Len(t, corpus.Cases, 184)
	require.Equal(t, corpus.Count, len(corpus.Cases))

	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			switch c.Kind {
			case er.KindCLLInclusionProof:
				octets, err := er.EncodeCLLInclusionProof(c.Inputs.Leaf, hexNodes(t, c.Inputs.Path))
				require.NoError(t, err)
				assert.Equal(t, c.Expected.OctetsHex, hex.EncodeToString(octets))
				entry, err := hex.DecodeString(c.Context.Entry)
				require.NoError(t, err)
				assert.NoError(t, er.VerifyCLLInclusion(hexNodes(t, c.Context.Peaks), entry, octets))
			case er.KindCLLConsistencyProof:
				oldPeaks, newPeaks := hexNodes(t, c.Inputs.OldPeaks), hexNodes(t, c.Inputs.NewPeaks)
				paths := make([][][]byte, len(c.Inputs.Paths))
				for i, p := range c.Inputs.Paths {
					paths[i] = hexNodes(t, p)
				}
				// Go's encoder takes the right peaks: the new peaks after
				// the roots the old peaks' paths reach.
				roots := er.MMRConsistentRoots(c.Inputs.OldSize-1, oldPeaks, paths)
				require.LessOrEqual(t, len(roots), len(newPeaks))
				octets, err := er.EncodeCLLConsistencyProof(c.Inputs.OldSize, c.Inputs.NewSize, paths, newPeaks[len(roots):])
				require.NoError(t, err)
				assert.Equal(t, c.Expected.OctetsHex, hex.EncodeToString(octets))
				assert.NoError(t, er.VerifyCLLConsistency(oldPeaks, newPeaks, octets))
			default:
				t.Fatalf("unknown kind %q", c.Kind)
			}
		})
	}
}
