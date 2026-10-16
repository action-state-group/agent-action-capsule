// SPDX-License-Identifier: BSD-3-Clause
package envelope

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeIsBottomUp(t *testing.T) {
	value := map[string]interface{}{
		"keep":  json.Number("0"),
		"null":  nil,
		"empty": []interface{}{},
		"outer": map[string]interface{}{"inner": map[string]interface{}{"gone": nil}},
		"list":  []interface{}{nil, map[string]interface{}{"x": nil}},
		"false": false,
		"blank": "",
	}
	require.Equal(t, map[string]interface{}{
		"keep":  json.Number("0"),
		"list":  []interface{}{nil, map[string]interface{}{}},
		"false": false,
		"blank": "",
	}, normalize(value))
}

func TestVerifyRecordSignatureRefusals(t *testing.T) {
	verdict, messages := VerifyRecordSignature([]interface{}{})
	require.Equal(t, Invalid, verdict)
	require.NotEmpty(t, messages)

	verdict, messages = VerifyRecordSignature(map[string]interface{}{"capsule_id": "x"})
	require.Equal(t, Unclaimed, verdict)
	require.Empty(t, messages)

	for name, record := range map[string]map[string]interface{}{
		"signature only":            {"signature": "00"},
		"unknown canonicalization":  {"canonicalization_id": "as-transmitted", "signature": "00", "key_id": "00"},
		"non-string algorithm":      {"canonicalization_id": json.Number("4"), "signature": "00", "key_id": "00"},
		"signature not a string":    {"signature": json.Number("1"), "key_id": "00"},
		"signature not hex":         {"signature": "zz", "key_id": "00"},
		"float in the preimage":     {"x": json.Number("1.5"), "signature": "00", "key_id": "00"},
		"envelope does not decode":  {"signature": "00", "key_id": "00"},
		"jcs declared, not decoded": {"canonicalization_id": "jcs", "signature": "d2", "key_id": "00"},
	} {
		verdict, messages := VerifyRecordSignature(record)
		require.Equal(t, Invalid, verdict, name)
		require.NotEmpty(t, messages, name)
	}
}
