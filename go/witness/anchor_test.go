// SPDX-License-Identifier: BSD-3-Clause

package witness

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type anchorVectors struct {
	Policies map[string]AnchorWitnessPolicy `json:"policies"`
	Cases    []struct {
		Name     string              `json:"name"`
		Anchor   string              `json:"anchor"`
		Receipts []string            `json:"receipts"`
		Policy   json.RawMessage     `json:"policy"`
		Expected AnchorWitnessReport `json:"expected"`
	} `json:"cases"`
}

func loadAnchorVectors(t *testing.T) anchorVectors {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "anchor-witness-v1", "vectors.json"))
	require.NoError(t, err)
	var corpus anchorVectors
	require.NoError(t, json.Unmarshal(data, &corpus))
	require.NotEmpty(t, corpus.Cases)
	return corpus
}

// TestAnchorWitnessVectors runs every case of vectors/anchor-witness-v1.
func TestAnchorWitnessVectors(t *testing.T) {
	corpus := loadAnchorVectors(t)
	statuses := map[string]bool{}
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var policy AnchorWitnessPolicy
			var name string
			if json.Unmarshal(c.Policy, &name) == nil {
				policy = corpus.Policies[name]
			} else {
				require.NoError(t, json.Unmarshal(c.Policy, &policy))
			}
			receipts := make([][]byte, len(c.Receipts))
			for i, text := range c.Receipts {
				var err error
				receipts[i], err = hex.DecodeString(text)
				require.NoError(t, err)
			}
			got := CheckAnchorWitnessed(c.Anchor, receipts, policy)
			want, err := json.Marshal(c.Expected)
			require.NoError(t, err)
			gotJSON, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, string(want), string(gotJSON))
			statuses[got.Status] = true
		})
	}
	assert.Equal(t, map[string]bool{AnchorPass: true, AnchorFail: true, AnchorNotChecked: true, AnchorNotPresent: true}, statuses)
}

func TestAnchorWitnessBadInputs(t *testing.T) {
	corpus := loadAnchorVectors(t)
	policy := corpus.Policies["default"]
	report := CheckAnchorWitnessed("not a digest", [][]byte{{0x01}}, policy)
	assert.Equal(t, AnchorFail, report.Status)
	report = CheckAnchorWitnessed(corpus.Cases[0].Anchor, [][]byte{nil, {}}, policy)
	assert.Equal(t, AnchorFail, report.Status)
	assert.Nil(t, report.Witness)
	// A policy entry that is not a usable key lists no key.
	bad := AnchorWitnessPolicy{Witnesses: []AnchorWitness{{Name: "w", Keys: []string{"zz", "00"}}}}
	receipt, err := hex.DecodeString(corpus.Cases[0].Receipts[0])
	require.NoError(t, err)
	assert.Equal(t, AnchorNotChecked, CheckAnchorWitnessed(corpus.Cases[0].Anchor, [][]byte{receipt}, bad).Status)
}
