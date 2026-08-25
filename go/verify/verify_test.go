// SPDX-License-Identifier: BSD-3-Clause
package verify_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/require"
)

func loadCapsule(t *testing.T, vector string) map[string]interface{} {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	path := filepath.Join(filepath.Dir(filename), "..", "..", "test-vectors", vector, "input.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var capsule map[string]interface{}
	require.NoError(t, decoder.Decode(&capsule))
	return capsule
}

func TestVerifyDeclaredJCSCommitsChain(t *testing.T) {
	capsule := loadCapsule(t, "pos-executed-confirmed")
	capsule["spec_version"] = "draft-mih-scitt-agent-action-capsule-03"
	capsule["format_version"] = "3"
	capsule["canonicalization_id"] = canonical.CanonicalizationJCS
	chain := map[string]interface{}{
		"parent_capsule_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"relation":          "confirms",
	}
	capsule["chain"] = chain
	assurance, ok := capsule["assurance"].(map[string]interface{})
	require.True(t, ok)
	assurance["ledger_mode"] = "chained"
	capsuleID, err := canonical.ComputeCapsuleID(capsule)
	require.NoError(t, err)
	capsule["capsule_id"] = capsuleID

	result := verify.Verify(capsule, nil, nil)
	require.True(t, result.OK, result.Findings)
	require.NotNil(t, result.CapsuleID)
	require.Equal(t, capsuleID, *result.CapsuleID)

	chain["relation"] = "supersedes"
	tampered := verify.Verify(capsule, nil, nil)
	require.False(t, tampered.OK)
	require.Contains(t, findingCodes(tampered), "capsule_id_mismatch")
}

func TestVerifyRejectsUnsupportedCanonicalizationID(t *testing.T) {
	for _, algorithm := range []string{"jcs-n", "future-algorithm"} {
		t.Run(algorithm, func(t *testing.T) {
			capsule := loadCapsule(t, "pos-executed-confirmed")
			capsule["spec_version"] = "draft-mih-scitt-agent-action-capsule-03"
			capsule["format_version"] = "3"
			capsule["canonicalization_id"] = algorithm

			result := verify.Verify(capsule, nil, nil)
			require.False(t, result.OK)
			require.Contains(t, findingCodes(result), "capsule_id_uncomputable")
		})
	}
}

func TestVerifyCanonicalizationProfileMatrix(t *testing.T) {
	tests := []struct {
		name          string
		formatVersion string
		declaration   interface{}
		declared      bool
		wantCode      string
	}{
		{name: "format 3 missing", formatVersion: "3", wantCode: "canonicalization_id_missing"},
		{name: "format 3 withdrawn", formatVersion: "3", declaration: "jcs-n", declared: true, wantCode: "canonicalization_profile_mismatch"},
		{name: "format 3 unknown", formatVersion: "3", declaration: "future-algorithm", declared: true, wantCode: "canonicalization_profile_mismatch"},
		{name: "format 3 non-string", formatVersion: "3", declaration: json.Number("7"), declared: true, wantCode: "canonicalization_id_not_string"},
		{name: "format 2 declared", formatVersion: "2", declaration: "jcs", declared: true, wantCode: "canonicalization_profile_mismatch"},
		{name: "format 2 null declaration", formatVersion: "2", declaration: nil, declared: true, wantCode: "canonicalization_profile_mismatch"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capsule := loadCapsule(t, "pos-executed-confirmed")
			capsule["format_version"] = test.formatVersion
			if test.formatVersion == "3" {
				capsule["spec_version"] = "draft-mih-scitt-agent-action-capsule-03"
			}
			if test.declared {
				capsule["canonicalization_id"] = test.declaration
			} else {
				delete(capsule, "canonicalization_id")
			}

			result := verify.Verify(capsule, nil, nil)
			require.False(t, result.OK)
			require.Contains(t, findingCodes(result), test.wantCode)
		})
	}
}

func findingCodes(result verify.VerificationResult) []string {
	codes := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		codes = append(codes, finding.Code)
	}
	return codes
}
