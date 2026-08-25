// SPDX-License-Identifier: BSD-3-Clause
package envelope_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/stretchr/testify/require"
)

func TestProducerEnvelopeVectors(t *testing.T) {
	root := envelopeVectorRoot(t)
	manifestData, err := os.ReadFile(filepath.Join(root, "vectors.json"))
	require.NoError(t, err)
	var manifest struct {
		Count int `json:"count"`
		Cases []struct {
			Name string `json:"name"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(manifestData, &manifest))
	require.Equal(t, manifest.Count, len(manifest.Cases))

	for _, testCase := range manifest.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			directory := filepath.Join(root, testCase.Name)
			capsuleIDData, err := os.ReadFile(filepath.Join(directory, "capsule_id.txt"))
			require.NoError(t, err)
			encoded, err := os.ReadFile(filepath.Join(directory, "envelope.cose"))
			require.NoError(t, err)
			expectedData, err := os.ReadFile(filepath.Join(directory, "expected.json"))
			require.NoError(t, err)
			var expected struct {
				OK           bool     `json:"ok"`
				FindingCodes []string `json:"finding_codes"`
				PublicKeyHex *string  `json:"public_key_hex"`
			}
			require.NoError(t, json.Unmarshal(expectedData, &expected))

			result := envelope.Verify(strings.TrimSpace(string(capsuleIDData)), encoded)
			require.Equal(t, expected.OK, result.OK, result.Findings)
			codes := make([]string, 0, len(result.Findings))
			for _, finding := range result.Findings {
				codes = append(codes, finding.Code)
			}
			require.Equal(t, expected.FindingCodes, codes)
			if expected.PublicKeyHex == nil {
				require.Empty(t, result.PublicKey)
			} else {
				require.Equal(t, *expected.PublicKeyHex, hex.EncodeToString(result.PublicKey))
			}
		})
	}
}

func envelopeVectorRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(filename), "..", "..", "producer-envelope-vectors")
}
