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
	path := filepath.Join(filepath.Dir(filename), "..", "..", "vectors/capsule", vector, "input.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var capsule map[string]interface{}
	require.NoError(t, decoder.Decode(&capsule))
	return capsule
}

// TestVerifyAcceptsEveryPublishedSpecVersion pins the -05 rule: producers emit
// the newest spec_version, verifiers accept every published one. The -04 input
// is a committed vector; the -05 input is its twin differing only in
// spec_version.
func TestVerifyAcceptsEveryPublishedSpecVersion(t *testing.T) {
	require.Equal(t, "draft-mih-scitt-agent-action-capsule-05", verify.CurrentSpecVersion)
	v04 := loadCapsule(t, "pos-v4-jcs-chain-committed")
	v05 := loadCapsule(t, "pos-v05-spec-version-chain-committed")
	require.Equal(t, "draft-mih-scitt-agent-action-capsule-04", v04["spec_version"])
	require.Equal(t, verify.CurrentSpecVersion, v05["spec_version"])
	for _, capsule := range []map[string]interface{}{v04, v05} {
		require.Contains(t, verify.PublishedSpecVersions, capsule["spec_version"])
		result := verify.Verify(capsule, nil, nil)
		require.True(t, result.OK, result.Findings)
		require.NotNil(t, result.CapsuleID)
		require.Equal(t, capsule["capsule_id"], *result.CapsuleID)
	}
	require.NotEqual(t, v04["capsule_id"], v05["capsule_id"])
}

func TestVerifyDeclaredJCSCommitsChain(t *testing.T) {
	capsule := loadCapsule(t, "pos-executed-confirmed")
	capsule["spec_version"] = verify.CurrentSpecVersion
	capsule["format_version"] = "4"
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
			capsule["spec_version"] = "draft-mih-scitt-agent-action-capsule-04"
			capsule["format_version"] = "4"
			capsule["canonicalization_id"] = algorithm

			result := verify.Verify(capsule, nil, nil)
			require.False(t, result.OK)
			require.NotContains(t, findingCodes(result), "capsule_id_uncomputable")
			require.Nil(t, result.CapsuleID)
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
		{name: "format 4 missing", formatVersion: "4", wantCode: "canonicalization_id_missing"},
		{name: "format 4 withdrawn", formatVersion: "4", declaration: "jcs-n", declared: true, wantCode: "canonicalization_profile_mismatch"},
		{name: "format 4 unknown", formatVersion: "4", declaration: "future-algorithm", declared: true, wantCode: "canonicalization_profile_mismatch"},
		{name: "format 4 non-string", formatVersion: "4", declaration: json.Number("7"), declared: true, wantCode: "canonicalization_id_not_string"},
		{name: "format 3 unsupported", formatVersion: "3", declaration: "jcs", declared: true, wantCode: "unsupported_format_version"},
		{name: "format 2 declared", formatVersion: "2", declaration: "jcs", declared: true, wantCode: "unsupported_format_version"},
		{name: "format 2 null declaration", formatVersion: "2", declaration: nil, declared: true, wantCode: "unsupported_format_version"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capsule := loadCapsule(t, "pos-executed-confirmed")
			capsule["format_version"] = test.formatVersion
			if test.formatVersion == "4" {
				capsule["spec_version"] = "draft-mih-scitt-agent-action-capsule-04"
			}
			if test.declared {
				capsule["canonicalization_id"] = test.declaration
			} else {
				delete(capsule, "canonicalization_id")
			}

			result := verify.Verify(capsule, nil, nil)
			require.False(t, result.OK)
			require.Contains(t, findingCodes(result), test.wantCode)
			require.NotContains(t, findingCodes(result), "capsule_id_uncomputable")
			require.Nil(t, result.CapsuleID)
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
