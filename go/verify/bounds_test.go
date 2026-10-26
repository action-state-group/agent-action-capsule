// SPDX-License-Identifier: BSD-3-Clause
package verify_test

// Verify does bounded work on hostile numbers (#383, the #381 shape). A wide
// array under a long key used to make the walk build a full path for every
// member and keep a finding per failing number: about 125 GB for a 1 MB
// record. The shared fixture pins the same findings for every implementation.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func numberFindings(res verify.VerificationResult) []verify.Finding {
	var out []verify.Finding
	for _, f := range res.Findings {
		if f.Code == "float_in_digest_field" || f.Code == "unsafe_integer_in_digest_field" {
			out = append(out, f)
		}
	}
	return out
}

// quotesPath reports whether detail quotes exactly path: the path ends the
// detail or a ';' follows it.
func quotesPath(detail, path string) bool {
	return strings.HasSuffix(detail, " at "+path) || strings.Contains(detail, " at "+path+";")
}

func TestNumberFindingsMatchTheSharedFixture(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "cross-language", "verify-number-findings.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var fixture struct {
		Record   map[string]interface{} `json:"record"`
		Expected []struct {
			Code string `json:"code"`
			Path string `json:"path"`
		} `json:"expected"`
	}
	require.NoError(t, decoder.Decode(&fixture))

	found := numberFindings(verify.Verify(fixture.Record, nil, nil))
	require.Len(t, found, len(fixture.Expected))
	for i, e := range fixture.Expected {
		assert.Equal(t, e.Code, found[i].Code, i)
		assert.True(t, quotesPath(found[i].Detail, e.Path), "%d: %q lacks %q", i, found[i].Detail, e.Path)
	}
}

// wideRecord is a well-formed record with 250,000 copies of value in one
// array under a 500 KB key: a little over 1 MB of JSON. The same shape as
// Rust's tests/verify_bounds.rs.
func wideRecord(value interface{}) map[string]interface{} {
	items := make([]interface{}, 250_000)
	for i := range items {
		items[i] = value
	}
	record := map[string]interface{}{
		"spec_version":        "draft-mih-scitt-agent-action-capsule-05",
		"format_version":      "4",
		"canonicalization_id": "jcs",
		"action_id":           "wide",
		"action_type":         "fyi",
		"operator":            "op",
		"developer":           "dev@v1",
		"timestamp":           "2026-09-29T00:00:00Z",
		"model_attestation":   map[string]interface{}{strings.Repeat("k", 500_000): items},
	}
	id, err := canonical.ComputeCapsuleID(record)
	if err != nil {
		id = ""
	}
	record["capsule_id"] = id
	return record
}

func TestWideArrayUnderALongKeyIsBounded(t *testing.T) {
	cases := map[string]interface{}{
		"zeros":   json.Number("0"),
		"objects": map[string]interface{}{},
		"floats":  json.Number("0.5"),
		"unsafe":  json.Number("9007199254740993"),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			record := wideRecord(value)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			res := verify.Verify(record, nil, nil)
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)

			assert.Less(t, elapsed, 10*time.Second)
			// Total bytes allocated, not the peak. The identity check
			// re-canonicalizes the record; before #383 the floats shape
			// needed about 125 GB.
			assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(64<<20))
			found := numberFindings(res)
			if name == "zeros" || name == "objects" {
				assert.True(t, res.OK, res.Findings)
				assert.Empty(t, found)
				return
			}
			assert.False(t, res.OK)
			require.Len(t, found, 64)
			assert.Contains(t, found[0].Detail, " at model_attestation."+strings.Repeat("k", 256-len("model_attestation."))+"...")
			for _, f := range found {
				assert.Less(t, len(f.Detail), 600)
			}
		})
	}
}

// withinSeconds runs f and fails the test if it has not returned in 10 s.
func withinSeconds[T any](t *testing.T, f func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- f() }()
	select {
	case out := <-done:
		return out
	case <-time.After(10 * time.Second):
		t.Fatal("did not return within 10 s")
		var zero T
		return zero
	}
}

// smallRecord is a well-formed record whose model_attestation holds payload.
func smallRecord(payload interface{}) map[string]interface{} {
	return map[string]interface{}{
		"spec_version":        "draft-mih-scitt-agent-action-capsule-05",
		"format_version":      "4",
		"canonicalization_id": "jcs",
		"action_id":           "cycle",
		"action_type":         "fyi",
		"operator":            "op",
		"developer":           "dev@v1",
		"timestamp":           "2026-09-29T00:00:00Z",
		"model_attestation":   map[string]interface{}{"payload": payload},
	}
}

// A value built in Go can contain itself; encoding/json never produces one
// (#388). Verify reports it as Python does, rather than walking it forever.
func TestValueThatContainsItselfIsAnInternalError(t *testing.T) {
	deep := func() interface{} {
		var value interface{} = "leaf"
		for range canonical.MaxNestingDepth + 1 {
			value = []interface{}{value}
		}
		return value
	}
	cases := map[string]func() map[string]interface{}{
		"map": func() map[string]interface{} {
			record := smallRecord(nil)
			record["self"] = record
			return record
		},
		"slice": func() map[string]interface{} {
			items := []interface{}{nil}
			items[0] = items
			return smallRecord(items)
		},
		"mutual": func() map[string]interface{} {
			a := map[string]interface{}{}
			b := map[string]interface{}{"a": a}
			a["b"] = b
			return smallRecord(a)
		},
		"too deep": func() map[string]interface{} { return smallRecord(deep()) },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			record := build()
			res := withinSeconds(t, func() verify.VerificationResult { return verify.Verify(record, nil, nil) })
			assert.False(t, res.OK)
			require.Len(t, res.Findings, 1)
			assert.Equal(t, "verifier_internal_error", res.Findings[0].Code)

			results := withinSeconds(t, func() []verify.VerificationResult {
				return verify.VerifyStore([]interface{}{record}, nil)
			})
			require.Len(t, results, 1)
			assert.Equal(t, "verifier_internal_error", results[0].Findings[0].Code)
		})
	}
}

// A sub-value reached twice without a cycle is not one and verifies as usual.
func TestSharedSubValueStillVerifies(t *testing.T) {
	shared := map[string]interface{}{"k": []interface{}{"v"}}
	record := smallRecord([]interface{}{shared, shared, map[string]interface{}{"again": shared}})
	id, err := canonical.ComputeCapsuleID(record)
	require.NoError(t, err)
	record["capsule_id"] = id
	res := withinSeconds(t, func() verify.VerificationResult { return verify.Verify(record, nil, nil) })
	assert.True(t, res.OK, res.Findings)
}
