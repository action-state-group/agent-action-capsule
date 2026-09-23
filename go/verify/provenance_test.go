// SPDX-License-Identifier: BSD-3-Clause
package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/require"
)

// TestProvenanceModeVectors runs every frozen vector in ../../provenance-mode-vectors/
// through the Go verifier and asserts its expected.json — the SAME expected.json
// the Python suite (python/tests/test_provenance_mode_vectors.py) asserts against,
// generated from the Python reference implementation. Both languages checking the
// same recorded (check, severity, code) tuples against a single source of truth is
// this repo's established cross-language parity mechanism for the Class-1 verifier
// (see TestCapsuleVectors for checks 1-8); check 9 follows the same discipline.
func TestProvenanceModeVectors(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	vectorRoot := filepath.Join(repoRoot, "provenance-mode-vectors")

	manifestData, err := os.ReadFile(filepath.Join(vectorRoot, "vectors.json"))
	require.NoError(t, err)
	var manifest struct {
		Count int `json:"count"`
		Cases []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(manifestData, &manifest))
	require.Equal(t, manifest.Count, len(manifest.Cases))

	regs, err := registries.Load(filepath.Join(repoRoot, "spec", "REGISTRY.md"))
	require.NoError(t, err)

	for _, item := range manifest.Cases {
		item := item
		t.Run(item.Name, func(t *testing.T) {
			caseDir := filepath.Join(vectorRoot, item.Name)
			inputData, err := os.ReadFile(filepath.Join(caseDir, "input.json"))
			require.NoError(t, err)
			expectedData, err := os.ReadFile(filepath.Join(caseDir, "expected.json"))
			require.NoError(t, err)

			var expected capsuleVectorExpected
			require.NoError(t, json.Unmarshal(expectedData, &expected))
			input := decodeCapsuleVector(t, inputData)

			if inputMap, ok := input.(map[string]interface{}); ok {
				if ledger, present := inputMap["ledger"]; present {
					assertStoreCapsuleVector(t, ledger, expected, regs)
					return
				}
			}
			assertSingleCapsuleVector(t, verify.Verify(input, nil, regs), expected)
		})
	}
}
