// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

func TestCapsuleModesRefuseInput(t *testing.T) {
	for _, mode := range []string{"seal", "verify"} {
		for name, input := range map[string]string{
			"empty": "", "not JSON": "{", "non-object": `["capsule"]`,
			"two values": `{"capsule_id": "a"} {"capsule_id": "b"}`, "trailing garbage": `{} x`,
			"lone surrogate": `{"capsule_id": "\ud800"}`, "invalid UTF-8": "{\"capsule_id\": \"\xff\"}",
		} {
			var out, errOut bytes.Buffer
			require.Equal(t, 2, capsuleMode(mode, strings.NewReader(input), &out, &errOut), mode+": "+name)
			require.Empty(t, out.String(), mode+": "+name)
			require.NotEmpty(t, errOut.String(), mode+": "+name)
		}
	}
}

func TestCapsuleModesSealThenVerify(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	fixture, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "..", "vectors", "cross-language", "seal-input.json"))
	require.NoError(t, err)
	var sealed, errOut bytes.Buffer
	require.Equal(t, 0, capsuleMode("seal", bytes.NewReader(fixture), &sealed, &errOut), errOut.String())
	var capsule map[string]interface{}
	require.NoError(t, json.Unmarshal(sealed.Bytes(), &capsule))
	var verified bytes.Buffer
	require.Equal(t, 0, capsuleMode("verify", &sealed, &verified, &errOut), errOut.String())
	require.Equal(t, capsule["capsule_id"].(string)+"\n", verified.String())
}

func TestSignatureNonObjectIsInvalid(t *testing.T) {
	var out, errOut bytes.Buffer
	require.Equal(t, 1, signature(strings.NewReader(`["capsule"]`), &out, &errOut))
	require.Equal(t, "invalid\n", out.String())
}

// bindingCase is a case of vectors/controller-binding-v0 as the binding mode
// reads it.
type bindingCase struct {
	ID   string `json:"id"`
	Pins struct {
		EvaluationTime string `json:"evaluation_time"`
	} `json:"pins"`
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
		RevocationList *struct {
			Declaration map[string]any `json:"declaration"`
			OctetsText  string         `json:"octets_text"`
		} `json:"revocation_list"`
	} `json:"inputs"`
	Expected struct {
		Binding struct {
			BindingDigest  string            `json:"binding_digest"`
			Properties     map[string]string `json:"properties"`
			RevocationList map[string]any    `json:"revocation_list"`
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
	require.Len(t, vectors.Cases, 42)
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
			if l := c.Inputs.RevocationList; l != nil {
				input["revocation_list"] = map[string]any{"declaration": l.Declaration, "list": l.OctetsText,
					"evaluated_at": c.Pins.EvaluationTime}
			}
			code, report, _ := runBinding(t, input)
			if c.Expected.Binding.RevocationList != nil {
				got := report["revocation_list"].(map[string]any)
				_, hasReason := got["reason"]
				require.Equal(t, got["counts"] == false, hasReason, "a reason exactly when it does not count")
				delete(got, "reason") // a diagnostic, not part of the vectors
				require.Equal(t, c.Expected.Binding.RevocationList, got)
			} else {
				require.NotContains(t, report, "revocation_list")
			}

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
	digest := strings.Repeat("a", 64)
	declaration := `{"profile":"p","asserted_by":"a","binding":"` + digest + `","list_digest":"` + digest +
		`","as_of":"2026-10-15T00:00:00Z","max_age":60}`
	for name, input := range map[string]string{
		"empty": "", "not JSON": "{", "an array": "[]", "two objects": `{} {}`,
		"no binding":              `{"at":["2026-10-15T00:00:00Z"]}`,
		"no at":                   `{"binding":"{}"}`,
		"empty at":                `{"binding":"{}","at":[]}`,
		"a fractional time":       `{"binding":"{}","at":["2026-10-15T00:00:00.5Z"]}`,
		"not a calendar date":     `{"binding":"{}","at":["2026-02-30T00:00:00Z"]}`,
		"binding as an object":    `{"binding":{},"at":["2026-10-15T00:00:00Z"]}`,
		"an uppercase key":        `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"key":"` + strings.Repeat("A", 64) + `"}`,
		"an unknown member":       `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"trust":["x"]}`,
		"a duplicate member":      `{"binding":"{}","binding":"{}","at":["2026-10-15T00:00:00Z"]}`,
		"revocations as text":     `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocations":"x"}`,
		"a numeric revocation":    `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocations":[1]}`,
		"credential as object":    `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"credential":{}}`,
		"revocation_list as text": `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocation_list":"x"}`,
		"revocation_list without a list": `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocation_list":{"declaration":` +
			declaration + `}}`,
		"revocation_list with an unknown member": `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocation_list":{"declaration":` +
			declaration + `,"list":"[]","sig":"x"}}`,
		"a list given as an array": `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocation_list":{"declaration":` +
			declaration + `,"list":[]}}`,
		"a declaration as text": `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocation_list":{"declaration":"x","list":"[]"}}`,
		"a declaration with a duplicate member": `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocation_list":{"declaration":` +
			strings.Replace(declaration, `{`, `{"profile":"q",`, 1) + `,"list":"[]"}}`,
		"a fractional evaluated_at": `{"binding":"{}","at":["2026-10-15T00:00:00Z"],"revocation_list":{"declaration":` +
			declaration + `,"list":"[]","evaluated_at":"2026-10-15T00:00:00.5Z"}}`,
		"lone surrogate":     `{"binding":"\ud800","at":["2026-10-15T00:00:00Z"]}`,
		"record not as text": `{"binding":` + record + `,"at":["2026-10-15T00:00:00Z"]}`,
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

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestBindingUnwrittenReportIsNoVerdict(t *testing.T) {
	c := bindingCases(t)[0]
	var half struct {
		IssuedAt string `json:"issued_at"`
	}
	require.NoError(t, json.Unmarshal([]byte(c.Inputs.Halves[0].OctetsText), &half))
	input, err := json.Marshal(map[string]any{"binding": c.Inputs.Binding.OctetsText, "at": []any{half.IssuedAt}})
	require.NoError(t, err)
	var errOut bytes.Buffer
	require.Equal(t, 2, binding(bytes.NewReader(input), failingWriter{}, &errOut))
	require.NotEmpty(t, errOut.String())
}

// With no evaluated_at, E is the current time: a list declared complete as of
// a minute ago under a day's bound counts, and one from 2026-10-15 does not.
func TestBindingRevocationListDefaultsToNow(t *testing.T) {
	var c bindingCase
	for _, candidate := range bindingCases(t) {
		if candidate.ID == "complete-list" {
			c = candidate
		}
	}
	require.NotNil(t, c.Inputs.RevocationList)
	var at []any
	for _, h := range c.Inputs.Halves {
		var half struct {
			IssuedAt string `json:"issued_at"`
		}
		require.NoError(t, json.Unmarshal([]byte(h.OctetsText), &half))
		at = append(at, half.IssuedAt)
	}
	run := func(asOf string, maxAge int64) map[string]any {
		declaration := map[string]any{}
		for k, v := range c.Inputs.RevocationList.Declaration {
			declaration[k] = v
		}
		declaration["as_of"], declaration["max_age"] = asOf, maxAge
		code, report, errText := runBinding(t, map[string]any{"binding": c.Inputs.Binding.OctetsText, "at": at,
			"revocation_list": map[string]any{"declaration": declaration, "list": c.Inputs.RevocationList.OctetsText}})
		require.Equal(t, 0, code, errText)
		return report
	}
	recent := time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05Z")
	assert.Equal(t, "PASS", run(recent, 86400)["properties"].(map[string]any)["controller_binding_revocation"])
	assert.Equal(t, "NOT_CHECKED", run("2026-10-19T00:00:00Z", 60)["properties"].(map[string]any)["controller_binding_revocation"])
}

// A declaration that is a JSON object but not in its form does not count:
// the binding is still checked, and the report says why (CB §5.1).
func TestBindingMalformedDeclarationDoesNotCount(t *testing.T) {
	var c bindingCase
	for _, candidate := range bindingCases(t) {
		if candidate.ID == "complete-list-revoked" {
			c = candidate
		}
	}
	require.NotNil(t, c.Inputs.RevocationList)
	var at []any
	for _, h := range c.Inputs.Halves {
		var half struct {
			IssuedAt string `json:"issued_at"`
		}
		require.NoError(t, json.Unmarshal([]byte(h.OctetsText), &half))
		at = append(at, half.IssuedAt)
	}
	declaration := map[string]any{}
	for k, v := range c.Inputs.RevocationList.Declaration {
		declaration[k] = v
	}
	delete(declaration, "max_age")
	run := func(list string) (int, map[string]any) {
		code, report, errText := runBinding(t, map[string]any{"binding": c.Inputs.Binding.OctetsText, "at": at,
			"revocation_list": map[string]any{"declaration": declaration, "list": list,
				"evaluated_at": c.Pins.EvaluationTime}})
		require.NotEqual(t, 2, code, errText)
		return code, report
	}
	code, report := run("[]")
	require.Equal(t, 0, code, "the binding applies")
	require.Equal(t, "NOT_CHECKED", report["properties"].(map[string]any)["controller_binding_revocation"])
	listed := report["revocation_list"].(map[string]any)
	require.Equal(t, false, listed["counts"])
	require.NotEmpty(t, listed["reason"])

	code, report = run(c.Inputs.RevocationList.OctetsText)
	require.Equal(t, 1, code, "an entry that applies still revokes")
	require.Equal(t, "FAIL", report["properties"].(map[string]any)["controller_binding_revocation"])
}
