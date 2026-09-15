// SPDX-License-Identifier: BSD-3-Clause
package verify_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/require"
)

type capsuleVectorExpectedFinding struct {
	Check    *int   `json:"check"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
}

type capsuleVectorExpected struct {
	OK                  bool                           `json:"ok"`
	Derived             map[string]string              `json:"derived"`
	CapsuleIDRecomputed *string                        `json:"capsule_id_recomputed"`
	Exception           *string                        `json:"exception"`
	Findings            []capsuleVectorExpectedFinding `json:"findings"`
	Results             []capsuleVectorExpected        `json:"results"`
}

func TestCapsuleVectors(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	vectorRoot := filepath.Join(repoRoot, "vectors", "capsule")

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

			if item.Kind == "canonical" {
				assertCanonicalCapsuleVector(t, input, expected)
				return
			}
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

func decodeCapsuleVector(t *testing.T, data []byte) interface{} {
	t.Helper()
	var value interface{}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&value))
	return value
}

func assertCanonicalCapsuleVector(t *testing.T, input interface{}, expected capsuleVectorExpected) {
	t.Helper()
	capsule, ok := input.(map[string]interface{})
	require.True(t, ok)
	actualID, err := canonical.ComputeCapsuleID(capsule)
	if expected.Exception == nil {
		require.NoError(t, err)
		require.NotNil(t, expected.CapsuleIDRecomputed)
		require.Equal(t, *expected.CapsuleIDRecomputed, actualID)
		return
	}

	require.Error(t, err)
	var actualException string
	switch err.(type) {
	case *canonical.FloatError:
		actualException = "FloatInDigestError"
	case *canonical.UnsafeIntError:
		actualException = "UnsafeIntegerError"
	default:
		actualException = fmt.Sprintf("%T", err)
	}
	require.Equal(t, *expected.Exception, actualException)
}

func assertStoreCapsuleVector(t *testing.T, ledgerRaw interface{}, expected capsuleVectorExpected, regs map[string]map[string]bool) {
	t.Helper()
	ledger, ok := ledgerRaw.([]interface{})
	require.True(t, ok)
	results := verify.VerifyStore(ledger, regs)
	require.Len(t, results, len(expected.Results))
	for i := range results {
		assertSingleCapsuleVector(t, results[i], expected.Results[i])
	}
}

func assertSingleCapsuleVector(t *testing.T, actual verify.VerificationResult, expected capsuleVectorExpected) {
	t.Helper()
	require.Equal(t, expected.OK, actual.OK)
	require.Equal(t, expected.Derived, actual.Assurance)
	require.Equal(t, expected.CapsuleIDRecomputed, actual.CapsuleID)
	require.Equal(t, expectedCapsuleVectorFindingKeys(expected.Findings), capsuleVectorFindingKeys(actual.Findings))
}

func capsuleVectorFindingKeys(findings []verify.Finding) []string {
	keys := make([]string, len(findings))
	for i, finding := range findings {
		keys[i] = capsuleVectorFindingKey(finding.Check, finding.Severity, finding.Code)
	}
	return keys
}

func expectedCapsuleVectorFindingKeys(findings []capsuleVectorExpectedFinding) []string {
	keys := make([]string, len(findings))
	for i, finding := range findings {
		keys[i] = capsuleVectorFindingKey(finding.Check, finding.Severity, finding.Code)
	}
	return keys
}

func capsuleVectorFindingKey(check *int, severity, code string) string {
	checkValue := "null"
	if check != nil {
		checkValue = fmt.Sprintf("%d", *check)
	}
	return fmt.Sprintf("(%s,%s,%s)", checkValue, severity, code)
}
