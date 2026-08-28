// SPDX-License-Identifier: BSD-3-Clause
package canonical_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestComputeCapsuleIDVintageRecord(t *testing.T) {
	chain := map[string]interface{}{
		"parent_capsule_id": "parent-a",
		"relation":          "confirms",
	}
	capsule := map[string]interface{}{
		"capsule_id": "ignored",
		"chain":      chain,
		"empty":      []interface{}{},
		"kept":       "value",
		"null":       nil,
	}

	got, err := canonical.ComputeCapsuleID(capsule)
	require.NoError(t, err)
	require.Equal(t, digest(`{"kept":"value"}`), got)

	chain["parent_capsule_id"] = "parent-b"
	changed, err := canonical.ComputeCapsuleID(capsule)
	require.NoError(t, err)
	require.Equal(t, got, changed, "vintage identity excludes chain")
}

func TestJSONDigestCommitsPresentNull(t *testing.T) {
	withNull, err := canonical.JSONDigest(map[string]interface{}{"a": json.Number("1"), "b": nil})
	require.NoError(t, err)
	withoutNull, err := canonical.JSONDigest(map[string]interface{}{"a": json.Number("1")})
	require.NoError(t, err)
	require.NotEqual(t, withoutNull, withNull)
}

func TestComputeCapsuleIDDeclaredJCS(t *testing.T) {
	chain := map[string]interface{}{
		"parent_capsule_id": "parent-a",
		"relation":          "confirms",
	}
	capsule := map[string]interface{}{
		"canonicalization_id": canonical.CanonicalizationJCS,
		"capsule_id":          "ignored",
		"chain":               chain,
		"empty":               []interface{}{},
		"kept":                "value",
		"null":                nil,
	}

	got, err := canonical.ComputeCapsuleID(capsule)
	require.NoError(t, err)
	require.Equal(t, digest(`{"canonicalization_id":"jcs","chain":{"parent_capsule_id":"parent-a","relation":"confirms"},"empty":[],"kept":"value","null":null}`), got)

	chain["parent_capsule_id"] = "parent-b"
	changed, err := canonical.ComputeCapsuleID(capsule)
	require.NoError(t, err)
	require.NotEqual(t, got, changed, "declared jcs identity commits chain")
}

func TestComputeCapsuleIDRejectsInvalidDeclaration(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  string
	}{
		{name: "withdrawn jcs-n", value: "jcs-n", want: `unsupported canonicalization_id "jcs-n"`},
		{name: "unknown", value: "future-algorithm", want: `unsupported canonicalization_id "future-algorithm"`},
		{name: "empty", value: "", want: `unsupported canonicalization_id ""`},
		{name: "null", value: nil, want: "canonicalization_id must be a string"},
		{name: "number", value: 7, want: "canonicalization_id must be a string"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := canonical.ComputeCapsuleID(map[string]interface{}{
				"canonicalization_id": test.value,
			})
			require.EqualError(t, err, test.want)
		})
	}
}
