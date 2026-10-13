// SPDX-License-Identifier: BSD-3-Clause
package canonical_test

// Salted JSON-DIGEST commitment vectors (vectors/salted-digest-commitment/, informative) — Go
// parity with python/tests/test_salted_digest_commitment_vectors.py. Every opening's JCS string
// and JSON-DIGEST are recomputed with this package; positives open their commitment, negatives do
// not open the commitment of the positive they name. TypeScript asserts the same file in
// ts/test/salted-digest-commitment-vectors.test.ts.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

type saltedOpening struct {
	Nonce string `json:"nonce"`
	Text  string `json:"text"`
}

type saltedCase struct {
	ID         string        `json:"id"`
	Against    string        `json:"against"`
	Opening    saltedOpening `json:"opening"`
	OpeningJCS string        `json:"opening_jcs"`
	Commitment string        `json:"commitment"`
	Recomputed string        `json:"recomputed"`
}

type saltedVectors struct {
	Positive []saltedCase `json:"positive"`
	Negative []saltedCase `json:"negative"`
	Equality struct {
		Nonce string `json:"nonce"`
		Text  string `json:"text"`
		First string `json:"first"`
	} `json:"equality"`
}

func saltedDigest(t *testing.T, nonce, text string) (string, string) {
	t.Helper()
	opening := map[string]interface{}{"nonce": nonce, "text": text}
	b, err := canonical.JCS(opening)
	require.NoError(t, err)
	d, err := canonical.JSONDigest(opening)
	require.NoError(t, err)
	return string(b), d
}

func TestSaltedDigestCommitmentVectors(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	path := filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "salted-digest-commitment", "vectors.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var v saltedVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	require.Len(t, v.Positive, 3)
	require.Len(t, v.Negative, 5)

	positive := map[string]string{}
	for _, c := range v.Positive {
		t.Run(c.ID, func(t *testing.T) {
			s, d := saltedDigest(t, c.Opening.Nonce, c.Opening.Text)
			require.Equal(t, c.OpeningJCS, s)
			require.Equal(t, c.Commitment, d)
		})
		positive[c.ID] = c.Commitment
	}
	for _, c := range v.Negative {
		t.Run(c.ID, func(t *testing.T) {
			s, d := saltedDigest(t, c.Opening.Nonce, c.Opening.Text)
			require.Equal(t, c.OpeningJCS, s)
			require.Equal(t, c.Recomputed, d)
			require.Equal(t, positive[c.Against], c.Commitment)
			require.NotEqual(t, c.Commitment, d)
		})
	}
	_, d := saltedDigest(t, v.Equality.Nonce, v.Equality.Text)
	require.Equal(t, v.Equality.First, d)
}
