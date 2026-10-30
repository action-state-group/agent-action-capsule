// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

// bindingCase is a case of vectors/controller-binding-v0 as the binding mode
// reads it.
type bindingCase struct {
	ID     string `json:"id"`
	Inputs struct {
		Halves []struct {
			OctetsText string `json:"octets_text"`
		} `json:"halves"`
		Binding struct {
			OctetsText string `json:"octets_text"`
		} `json:"binding"`
		Revocations []struct {
			OctetsText string `json:"octets_text"`
		} `json:"revocations"`
		Credential *struct {
			OctetsText string `json:"octets_text"`
		} `json:"credential"`
	} `json:"inputs"`
	Expected struct {
		Binding struct {
			BindingDigest string            `json:"binding_digest"`
			Properties    map[string]string `json:"properties"`
		} `json:"binding"`
	} `json:"expected"`
}

func bindingCases(t *testing.T) []bindingCase {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "..", "vectors", "controller-binding-v0", "vectors.json"))
	require.NoError(t, err)
	var vectors struct {
		Cases []bindingCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.Len(t, vectors.Cases, 14)
	return vectors.Cases
}

func runBinding(t *testing.T, input map[string]any) (int, map[string]any, string) {
	t.Helper()
	data, err := json.Marshal(input)
	require.NoError(t, err)
	var out, errOut bytes.Buffer
	code := binding(bytes.NewReader(data), &out, &errOut)
	var report map[string]any
	if out.Len() > 0 {
		require.NoError(t, json.Unmarshal(out.Bytes(), &report))
	}
	return code, report, errOut.String()
}

// Each case is asked with the first half's key as the node's key, at both
// halves' times. Without a credential verifier, a delivered credential is
// NOT_CHECKED; every other property is the case's expected one.
func TestBindingVectors(t *testing.T) {
	seen := map[int]bool{}
	for _, c := range bindingCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			var at []any
			var key string
			for i, h := range c.Inputs.Halves {
				var half struct {
					IssuedAt string `json:"issued_at"`
					Producer string `json:"producer"`
				}
				require.NoError(t, json.Unmarshal([]byte(h.OctetsText), &half))
				at = append(at, half.IssuedAt)
				if i == 0 {
					key = half.Producer
				}
			}
			input := map[string]any{"binding": c.Inputs.Binding.OctetsText, "at": at, "key": key}
			var revocations []any
			for _, r := range c.Inputs.Revocations {
				revocations = append(revocations, r.OctetsText)
			}
			if revocations != nil {
				input["revocations"] = revocations
			}
			if c.Inputs.Credential != nil {
				input["credential"] = c.Inputs.Credential.OctetsText
			}
			code, report, _ := runBinding(t, input)

			want := map[string]any{}
			for p, s := range c.Expected.Binding.Properties {
				if p == "controller_binding_credential" {
					s = "NOT_CHECKED"
				}
				want[p] = s
			}
			require.Equal(t, want, report["properties"])
			require.Equal(t, c.Expected.Binding.BindingDigest, report["binding_digest"])

			var record struct {
				Keys []string `json:"keys"`
			}
			require.NoError(t, json.Unmarshal([]byte(c.Inputs.Binding.OctetsText), &record))
			p := c.Expected.Binding.Properties
			fail := !slices.Contains(record.Keys, key)
			for _, name := range []string{"controller_binding_form", "controller_binding_signatures",
				"controller_binding_window", "controller_binding_revocation"} {
				fail = fail || p[name] == "FAIL"
			}
			wantCode := 3
			switch {
			case fail:
				wantCode = 1
			case p["controller_binding_signatures"] == "PASS" && p["controller_binding_window"] == "PASS":
				wantCode = 0
			}
			require.Equal(t, wantCode, code)
			require.Equal(t, wantCode == 0, report["applies"])
			seen[code] = true
		})
	}
	require.Equal(t, map[int]bool{0: true, 1: true, 3: true}, seen)
}

func TestBindingKeyNotNamed(t *testing.T) {
	c := bindingCases(t)[0]
	var half struct {
		IssuedAt string `json:"issued_at"`
	}
	require.NoError(t, json.Unmarshal([]byte(c.Inputs.Halves[0].OctetsText), &half))
	input := map[string]any{"binding": c.Inputs.Binding.OctetsText, "at": []any{half.IssuedAt}}
	code, report, _ := runBinding(t, input)
	require.Equal(t, 0, code, "with no key, the record's own checks decide")
	require.Equal(t, true, report["applies"])

	input["key"] = strings.Repeat("0", 64)
	code, report, _ = runBinding(t, input)
	require.Equal(t, 1, code)
	require.Equal(t, false, report["applies"])
	require.Equal(t, strings.Repeat("0", 64), report["key"])
}

func TestBindingRefusesInput(t *testing.T) {
	record := bindingCases(t)[0].Inputs.Binding.OctetsText
	for name, input := range map[string]string{
		"empty": "", "not JSON": "{", "an array": "[]", "two objects": `{} {}`,
		"no binding":           `{"at":["2026-10-15T00:00:00Z"]}`,
		"no at":                `{"binding":"{}"}`,
		"empty at":             `{"binding":"{}","at":[]}`,
		"a fractional time":    `{"binding":"{}","at":["2026-10-15T00:00:00.5Z"]}`,
		"not a calendar date":  `{"binding":"{}","at":["2026-02-30T00:00:00Z"]}`,
		"binding as an object": `{"binding":{},"at":["2026-10-15T00:00:00Z"]}`,
		"an uppercase key":     `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"key":"` + strings.Repeat("A", 64) + `"}`,
		"an unknown member":    `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"trust":["x"]}`,
		"a duplicate member":   `{"binding":"{}","binding":"{}","at":["2026-10-15T00:00:00Z"]}`,
		"revocations as text":  `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocations":"x"}`,
		"a numeric revocation": `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocations":[1]}`,
		"credential as object": `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"credential":{}}`,
		"lone surrogate":       `{"binding":"\ud800","at":["2026-10-15T00:00:00Z"]}`,
		"record not as text":   `{"binding":` + record + `,"at":["2026-10-15T00:00:00Z"]}`,
	} {
		var out, errOut bytes.Buffer
		require.Equal(t, 2, binding(strings.NewReader(input), &out, &errOut), name)
		require.Empty(t, out.String(), name)
		require.NotEmpty(t, errOut.String(), name)
	}
}

func TestBindingMalformedRecordIsFail(t *testing.T) {
	code, report, _ := runBinding(t, map[string]any{"binding": "not json", "at": []any{"2026-10-15T00:00:00Z"}})
	require.Equal(t, 1, code)
	require.Equal(t, map[string]any{"controller_binding_form": "FAIL"}, report["properties"])
}
