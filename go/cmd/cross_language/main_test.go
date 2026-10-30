// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignatureRecordSignatureVectors(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "..", "vectors", "bundle", "strict", "vectors.json"))
	require.NoError(t, err)
	var vectors struct {
		RecordSignatures []struct {
			ID     string          `json:"id"`
			Record json.RawMessage `json:"record"`
			Expect string          `json:"expect"`
		} `json:"record_signatures"`
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.NotEmpty(t, vectors.RecordSignatures)
	seen := map[string]bool{}
	for _, testCase := range vectors.RecordSignatures {
		t.Run(testCase.ID, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := signature(bytes.NewReader(testCase.Record), &out, &errOut)
			require.Equal(t, testCase.Expect+"\n", out.String())
			require.Equal(t, map[string]int{"authored": 0, "invalid": 1, "unclaimed": 3}[testCase.Expect], code)
			require.Equal(t, testCase.Expect == "invalid", errOut.Len() != 0)
		})
		seen[testCase.Expect] = true
	}
	require.Equal(t, map[string]bool{"authored": true, "invalid": true, "unclaimed": true}, seen)
}

func TestSignatureRefusesInput(t *testing.T) {
	for name, input := range map[string]string{
		"empty": "", "not JSON": "{", "bare word": "signed",
		"two records": `{"capsule_id": "a"} {"capsule_id": "b"}`, "trailing garbage": `{} x`,
		"lone surrogate": `{"capsule_id": "\ud800"}`, "invalid UTF-8": "{\"capsule_id\": \"\xff\"}",
	} {
		var out, errOut bytes.Buffer
		require.Equal(t, 2, signature(strings.NewReader(input), &out, &errOut), name)
		require.Empty(t, out.String(), name)
		require.NotEmpty(t, errOut.String(), name)
	}
}

func TestSignatureNonObjectIsInvalid(t *testing.T) {
	var out, errOut bytes.Buffer
	require.Equal(t, 1, signature(strings.NewReader(`["capsule"]`), &out, &errOut))
	require.Equal(t, "invalid\n", out.String())
}
