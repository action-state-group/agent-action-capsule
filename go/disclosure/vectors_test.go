// SPDX-License-Identifier: BSD-3-Clause
package disclosure_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/disclosure"
	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/stretchr/testify/require"
)

func TestDisclosureEnvelopeVectors(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "disclosure-envelope")
	manifestData, err := os.ReadFile(filepath.Join(root, "vectors.json"))
	require.NoError(t, err)
	var manifest struct {
		Cases []struct {
			Name string `json:"name"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(manifestData, &manifest))
	registryPath := filepath.Join(filepath.Dir(filename), "..", "..", "spec", "REGISTRY.md")
	regs, err := registries.Load(registryPath)
	require.NoError(t, err)

	for _, item := range manifest.Cases {
		t.Run(item.Name, func(t *testing.T) {
			inputData, err := os.ReadFile(filepath.Join(root, item.Name, "input.json"))
			require.NoError(t, err)
			expectedData, err := os.ReadFile(filepath.Join(root, item.Name, "expected.json"))
			require.NoError(t, err)
			var input map[string]interface{}
			decoder := json.NewDecoder(strings.NewReader(string(inputData)))
			decoder.UseNumber()
			require.NoError(t, decoder.Decode(&input))
			var expected struct {
				OK      bool `json:"ok"`
				Capsule struct {
					OK                  bool              `json:"ok"`
					Derived             map[string]string `json:"derived"`
					CapsuleIDRecomputed string            `json:"capsule_id_recomputed"`
					Findings            []struct {
						Code string `json:"code"`
					} `json:"findings"`
				} `json:"capsule"`
				Checked            int                  `json:"disclosures_checked"`
				Matched            int                  `json:"disclosures_matched"`
				DisclosureFindings []disclosure.Finding `json:"disclosure_findings"`
			}
			require.NoError(t, json.Unmarshal(expectedData, &expected))
			actual := disclosure.Verify(input["envelope"], regs)
			require.Equal(t, expected.OK, actual.OK())
			require.Equal(t, expected.Capsule.OK, actual.CapsuleResult.OK)
			require.Equal(t, expected.Capsule.Derived, actual.CapsuleResult.Assurance)
			require.NotNil(t, actual.CapsuleResult.CapsuleID)
			require.Equal(t, expected.Capsule.CapsuleIDRecomputed, *actual.CapsuleResult.CapsuleID)
			actualCodes := make([]string, len(actual.CapsuleResult.Findings))
			for index, finding := range actual.CapsuleResult.Findings {
				actualCodes[index] = finding.Code
			}
			expectedCodes := make([]string, len(expected.Capsule.Findings))
			for index, finding := range expected.Capsule.Findings {
				expectedCodes[index] = finding.Code
			}
			require.Equal(t, expectedCodes, actualCodes)
			require.Equal(t, expected.Checked, actual.DisclosuresChecked())
			require.Equal(t, expected.Matched, actual.DisclosuresMatched())
			require.Equal(t, expected.DisclosureFindings, actual.DisclosureFindings)
		})
	}
}
